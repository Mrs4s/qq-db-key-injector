package injector

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"strings"
	"unsafe"

	"github.com/Mrs4s/go-db-key-injector/injector/data"
	"github.com/Mrs4s/go-db-key-injector/injector/win32"
	"github.com/pkg/errors"
	peparser "github.com/saferwall/pe"
	"golang.org/x/sys/windows"
)

type baseRelocation struct {
	VirtualAddress uint32
	SizeOfBlock    uint32
}

const (
	PAGE_NOACCESS          = 1
	PAGE_READONLY          = 2
	PAGE_READWRITE         = 4
	PAGE_WRITECOPY         = 8
	PAGE_EXECUTE           = 0x10
	PAGE_EXECUTE_READ      = 0x20
	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_EXECUTE_WRITECOPY = 0x80
	PAGE_NOCACHE           = 0x200

	IMAGE_SCN_LNK_NRELOC_CVFL        = 0x01000000
	IMAGE_SCN_MEM_DISCARDABLE        = 0x02000000
	IMAGE_SCN_MEM_NOT_CACHED         = 0x04000000
	IMAGE_SCN_MEM_NOT_PAGED          = 0x08000000
	IMAGE_SCN_MEM_NOT_SHARED         = 0x10000000
	IMAGE_SCN_MEM_EXECUTE            = 0x20000000
	IMAGE_SCN_MEM_READ               = 0x40000000
	IMAGE_SCN_MEM_WRITE              = 0x80000000
	IMAGE_SCN_CNT_INITIALIZED_DATA   = 0x00000040
	IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
)

type MemoryInjector struct {
	handle  uintptr
	pe      *peparser.File
	dataPtr uintptr
}

func NewInjector(pid uint32) (*MemoryInjector, error) {
	handle, err := win32.OpenProcess(2035711, false, pid) // PROCESS_ALL_ACCESS
	if err != nil {
		return nil, errors.Wrap(err, "open process error")
	}
	return &MemoryInjector{handle: handle}, nil
}

func (injector *MemoryInjector) ManualMapInject(payload []byte) {
	peFile, err := peparser.NewBytes(payload, &peparser.Options{})
	if err != nil {
		return
	}
	if err = peFile.Parse(); err != nil {
		return
	}
	injector.pe = peFile
	injector.dataPtr = (*reflect.SliceHeader)(unsafe.Pointer(&payload)).Data
	imageSize := injector.getPEOptionalHeader().SizeOfImage
	allocatedAddr, _ := win32.VirtualAllocEx(injector.handle, 0, int(imageSize), 0x1000|0x2000, 0x40) // Commit | Reserve , ExecuteReadWrite
	if allocatedAddr == 0 {
		return
	}
	injector.fixImportTable()
	injector.fixRelocationTable(allocatedAddr)
	injector.injectSections(allocatedAddr)
	dllMain := allocatedAddr + uintptr(injector.getPEOptionalHeader().AddressOfEntryPoint)
	injector.callEntryPoint(allocatedAddr, dllMain)
}

func (injector *MemoryInjector) RemoteLoadLibraryInject(dllPath string) error {
	addr, err := win32.VirtualAllocEx(injector.handle, 0, len(dllPath), 0x1000, 0x40)
	if err != nil {
		return errors.Wrap(err, "remote alloc memory failed")
	}
	_ = win32.WriteProcessMemory(injector.handle, addr, []byte(dllPath), uint(len(dllPath)))
	loadLibraryAddr := injector.GetRemoteProcAddress("kernel32.dll", "LoadLibraryA")
	if loadLibraryAddr == 0 {
		return errors.New("remote LoadLibraryA not found")
	}
	_, _, _ = win32.CreateRemoteThread(injector.handle, nil, 0, loadLibraryAddr, addr, 0)
	return nil
}

func (injector *MemoryInjector) GetRemoteProcAddress(moduleName, procName string) uintptr {
	module := injector.FindModuleInfo(moduleName)
	if module == nil {
		return 0
	}
	dos := win32.ReadMemory[peparser.ImageDosHeader](injector.handle, module.BaseAddress)
	opt := win32.ReadMemory[peparser.ImageOptionalHeader32](injector.handle, module.BaseAddress+uintptr(dos.AddressOfNewEXEHeader)+4+unsafe.Sizeof(peparser.ImageFileHeader{}))
	export := win32.ReadMemory[peparser.ImageExportDirectory](injector.handle, module.BaseAddress+uintptr(opt.DataDirectory[0].VirtualAddress))
	for i := uint32(0); i < export.NumberOfNames; i++ {
		funcName := win32.ReadMemoryString(injector.handle, module.BaseAddress+win32.ReadMemory[uintptr](injector.handle, module.BaseAddress+uintptr(export.AddressOfNames)+uintptr(i*4)), 255)
		if funcName != procName {
			continue
		}
		funcOrdinal := win32.ReadMemory[int16](injector.handle, module.BaseAddress+uintptr(export.AddressOfNameOrdinals)+uintptr(i*2)) + int16(export.Base)
		funcRva := win32.ReadMemory[uintptr](injector.handle, module.BaseAddress+uintptr(export.AddressOfFunctions)+4*(uintptr(uint32(funcOrdinal)-export.Base)))
		return module.BaseAddress + funcRva
	}
	return 0
}

func (injector *MemoryInjector) pLdrGerRemoteProcAddress(moduleName, procName string) uintptr {
	funcAddr := injector.GetRemoteProcAddress(moduleName, procName)
	if funcAddr == 0 {
		return 0
	}
	module := injector.FindModuleInfo(moduleName)
	dos := win32.ReadMemory[peparser.ImageDosHeader](injector.handle, module.BaseAddress)
	opt := win32.ReadMemory[peparser.ImageOptionalHeader32](injector.handle, module.BaseAddress+uintptr(dos.AddressOfNewEXEHeader)+4+unsafe.Sizeof(peparser.ImageFileHeader{}))
	if funcAddr >= module.BaseAddress+uintptr(opt.DataDirectory[0].VirtualAddress) && funcAddr <= module.BaseAddress+uintptr(opt.DataDirectory[0].VirtualAddress)+uintptr(opt.DataDirectory[0].Size) {
		forwardTarget := strings.SplitN(win32.ReadMemoryString(injector.handle, funcAddr, 255), ".", 2)
		if len(forwardTarget) != 2 {
			return funcAddr
		}
		dllName := forwardTarget[0] + ".dll"
		funcName := forwardTarget[1]
		return injector.pLdrGerRemoteProcAddress(dllName, funcName)
	}
	return funcAddr
}

func (injector *MemoryInjector) FindModuleInfo(moduleName string) *win32.ModuleInfo {
	modules := make([]uintptr, 512)
	n, err := win32.EnumProcessModules(injector.handle, modules)
	if err != nil {
		return nil
	}
	if n < len(modules) {
		modules = modules[:n]
	}
	var buf = make([]uint16, 255)
	for _, module := range modules {
		n, err = win32.GetModuleBaseName(injector.handle, module, &buf[0], uint32(len(buf)))
		if err != nil {
			continue
		}
		name := windows.UTF16ToString(buf[:n])
		if strings.ToLower(name) == strings.ToLower(moduleName) {
			info := win32.GetModuleInformation(injector.handle, module)
			return &info
		}
	}
	return nil
}

func (injector *MemoryInjector) getPEOptionalHeader() peparser.ImageOptionalHeader32 {
	return injector.pe.NtHeader.OptionalHeader.(peparser.ImageOptionalHeader32)
}

// fixImportTable 修复导入表
func (injector *MemoryInjector) fixImportTable() {
	for _, imp := range injector.pe.Imports {
		importPtr := data.NewManagedPtr[uintptr](injector.rvaToVa(uintptr(imp.Descriptor.FirstThunk)))
		for _, f := range imp.Functions {
			remoteAddr := injector.pLdrGerRemoteProcAddress(imp.Name, f.Name)
			importPtr.SetValue(remoteAddr)
			importPtr.Add(1)
		}
	}
}

// fixRelocationTable 修复重定向表
func (injector *MemoryInjector) fixRelocationTable(remoteBaseAddr uintptr) {
	if injector.pe.NtHeader.FileHeader.Characteristics&0x01 > 0 {
		return
	}
	optHeader := injector.getPEOptionalHeader()
	imageBaseDelta := uint32(remoteBaseAddr) - optHeader.ImageBase
	relocationTable := optHeader.DataDirectory[5]
	relocationSize := relocationTable.Size
	if relocationSize == 0 {
		return
	}
	va := injector.rvaToVa(uintptr(relocationTable.VirtualAddress))
	relocationDirectory := data.NewManagedPtr[baseRelocation](va)
	endOfRelocation := data.NewManagedPtr[baseRelocation](va + uintptr(relocationSize))
	for relocationDirectory.Address < endOfRelocation.Address {
		base := injector.rvaToVa(uintptr(relocationDirectory.Value().VirtualAddress))
		num := (relocationDirectory.Value().SizeOfBlock - 8) >> 1
		relocationDirectory.Add(1)
		relocationData := data.NewManagedPtr[uint16](relocationDirectory.Address)
		for i := uint32(0); i < num; i++ {
			raw := base + uintptr(relocationData.Value()&0xFFF)
			switch (relocationData.Value() >> 12) & 0xF {
			case 1:
				rawData := data.NewManagedPtr[uint16](raw)
				rawData.SetValue(rawData.Value() + uint16((imageBaseDelta>>16)&0xffff))
			case 2:
				rawData := data.NewManagedPtr[uint16](raw)
				rawData.SetValue(rawData.Value() + uint16((imageBaseDelta)&0xffff))
			case 3, 10:
				rawData := data.NewManagedPtr[uint32](raw)
				rawData.SetValue(rawData.Value() + imageBaseDelta)
			}
			relocationData.Add(1)
		}
		relocationDirectory.Address = relocationData.Address
	}
}

// injectSections 写入段
func (injector *MemoryInjector) injectSections(remoteBaseAddr uintptr) {
	for _, section := range injector.pe.Sections {
		if section.Header.Characteristics&(IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE) != 0 {
			protection := getSectionProtection(section.Header.Characteristics)
			var buf []byte
			p := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
			p.Len = int(section.Header.SizeOfRawData)
			p.Cap = int(section.Header.SizeOfRawData)
			p.Data = injector.dataPtr + uintptr(section.Header.PointerToRawData)
			_ = win32.WriteProcessMemory(injector.handle, remoteBaseAddr+uintptr(section.Header.VirtualAddress), buf, uint(section.Header.SizeOfRawData))
			_ = win32.VirtualProtectEx(injector.handle, remoteBaseAddr+uintptr(section.Header.VirtualAddress), uintptr(section.Header.VirtualSize), uintptr(protection))
		}
	}
}

func (injector *MemoryInjector) rvaToVa(rva uintptr) uintptr {
	dos := data.NewManagedPtr[peparser.ImageDosHeader](injector.dataPtr)
	va, _ := win32.ImageRvaToVa(injector.dataPtr+uintptr(dos.Value().AddressOfNewEXEHeader), injector.dataPtr, rva, 0)
	return va
}

func (injector *MemoryInjector) callEntryPoint(baseAddr, entryPoint uintptr) {
	toBytes := func(v uint32) []byte {
		buff := make([]byte, 4)
		binary.LittleEndian.PutUint32(buff, v)
		return buff
	}
	buff := new(bytes.Buffer)
	_ = buff.WriteByte(0x68)
	_, _ = buff.Write(toBytes(uint32(baseAddr)))
	_ = buff.WriteByte(0x68)
	_, _ = buff.Write(toBytes(1))
	_ = buff.WriteByte(0x68)
	_, _ = buff.Write(toBytes(0))
	_ = buff.WriteByte(0xB8)
	_, _ = buff.Write(toBytes(uint32(entryPoint)))
	_, _ = buff.Write([]byte{0xFF, 0xD0, 0x33, 0xC0, 0xC2, 0x04, 0x00})
	shellCode := buff.Bytes()
	addr, err := win32.VirtualAllocEx(injector.handle, 0, len(shellCode), 0x1000|0x2000, 0x40)
	if err != nil {
		return
	}
	_ = win32.WriteProcessMemory(injector.handle, addr, shellCode, uint(len(shellCode)))
	_, _, err = win32.CreateRemoteThread(injector.handle, nil, 0, addr, 0, 0)
	if err != nil {
		return
	}
}

func getSectionProtection(sc uint32) uint32 {
	var ret uint32
	if sc&IMAGE_SCN_MEM_NOT_CACHED != 0 {
		ret |= PAGE_NOCACHE
	}
	if sc&IMAGE_SCN_MEM_EXECUTE != 0 {
		if sc&IMAGE_SCN_MEM_READ != 0 {
			if sc&IMAGE_SCN_MEM_WRITE != 0 {
				ret = ret | PAGE_EXECUTE_READWRITE
			} else {
				ret = ret | PAGE_EXECUTE_READ
			}
		} else if sc&IMAGE_SCN_MEM_WRITE != 0 {
			ret = ret | PAGE_EXECUTE_WRITECOPY
		} else {
			ret = ret | PAGE_EXECUTE
		}
	} else if sc&IMAGE_SCN_MEM_READ != 0 {
		if sc&IMAGE_SCN_MEM_WRITE != 0 {
			ret = ret | PAGE_READWRITE
		} else {
			ret = ret | PAGE_READONLY
		}
	} else if sc&IMAGE_SCN_MEM_WRITE != 0 {
		ret = ret | PAGE_WRITECOPY
	} else {
		ret = ret | PAGE_NOACCESS
	}
	return ret
}
