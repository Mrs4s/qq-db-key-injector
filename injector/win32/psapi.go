package win32

import (
	"syscall"
	"unsafe"
)

var (
	psapi                    = syscall.NewLazyDLL("Psapi.dll")
	procEnumProcessModules   = psapi.NewProc("EnumProcessModules")
	procGetModuleBaseName    = psapi.NewProc("GetModuleBaseNameW")
	procGetModuleInformation = psapi.NewProc("GetModuleInformation")
)

type ModuleInfo struct {
	BaseAddress uintptr
	SizeOfImage uint32
	EntryPoint  uintptr
}

func EnumProcessModules(process uintptr, modules []uintptr) (n int, err error) {
	var needed int32
	const handleSize = unsafe.Sizeof(modules[0])
	r1, _, e := procEnumProcessModules.Call(
		process,
		uintptr(unsafe.Pointer(&modules[0])),
		handleSize*uintptr(len(modules)),
		uintptr(unsafe.Pointer(&needed)),
	)
	if r1 == 0 {
		return 0, e
	}
	n = int(uintptr(needed) / handleSize)
	return n, nil
}

func GetModuleBaseName(process uintptr, module uintptr, outString *uint16, size uint32) (n int, err error) {
	r1, _, e1 := procGetModuleBaseName.Call(
		process,
		module,
		uintptr(unsafe.Pointer(outString)),
		uintptr(size),
	)
	if r1 == 0 {
		return 0, e1
	}
	return int(r1), nil
}

func GetModuleInformation(hProcess, moduleHandle uintptr) ModuleInfo {
	var info ModuleInfo
	_, _, _ = procGetModuleInformation.Call(hProcess, moduleHandle, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info))
	return info
}
