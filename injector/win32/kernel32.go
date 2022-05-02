package win32

import (
	"reflect"
	"syscall"
	"unsafe"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procVirtualProtectEx   = kernel32.NewProc("VirtualProtectEx")
	procCreateRemoteThread = kernel32.NewProc("CreateRemoteThread")
	procVirtualAllocEx     = kernel32.NewProc("VirtualAllocEx")
	procReadProcessMemory  = kernel32.NewProc("ReadProcessMemory")
	procWriteProcessMemory = kernel32.NewProc("WriteProcessMemory")
)

func OpenProcess(desiredAccess uint32, inheritHandle bool, processId uint32) (handle uintptr, err error) {
	h, err := syscall.OpenProcess(desiredAccess, inheritHandle, processId)
	if err != nil {
		return 0, err
	}
	return uintptr(h), nil
}

func VirtualAllocEx(hProcess uintptr, lpAddress int, dwSize int, flAllocationType int, flProtect int) (addr uintptr, err error) {
	ret, _, err := procVirtualAllocEx.Call(
		hProcess,
		uintptr(lpAddress),
		uintptr(dwSize),
		uintptr(flAllocationType),
		uintptr(flProtect),
	)
	if int(ret) == 0 {
		return ret, err
	}
	return ret, nil
}

func WriteProcessMemory(hProcess uintptr, lpBaseAddress uintptr, data []byte, size uint) (err error) {
	var numBytesRead uintptr
	_, _, err = procWriteProcessMemory.Call(
		hProcess,
		lpBaseAddress,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&numBytesRead)),
	)
	return
}

func ReadProcessMemory(hProcess uintptr, lpBaseAddress uintptr, size uintptr) []byte {
	var numBytesRead uintptr
	data := make([]byte, size)
	_, _, _ = procReadProcessMemory.Call(
		hProcess,
		lpBaseAddress,
		uintptr(unsafe.Pointer(&data[0])),
		size,
		uintptr(unsafe.Pointer(&numBytesRead)))
	return data
}

func ReadMemory[T any](hProcess uintptr, lpBaseAddress uintptr) T {
	var t T
	buff := ReadProcessMemory(hProcess, lpBaseAddress, unsafe.Sizeof(t))
	p := (*reflect.SliceHeader)(unsafe.Pointer(&buff))
	return *(*T)(unsafe.Pointer(p.Data))
}

func ReadMemoryString(hProcess uintptr, lpBaseAddress uintptr, size int) string {
	buff := ReadProcessMemory(hProcess, lpBaseAddress, uintptr(size))
	for i, b := range buff {
		if b == 0 {
			return string(buff[:i])
		}
	}
	return string(buff)
}

func VirtualProtectEx(hProcess uintptr, lpAddress uintptr, dwSize uintptr, flNewProtect uintptr) (err error) {
	var oldProtect uintptr
	_, _, err = procVirtualProtectEx.Call(
		hProcess,
		lpAddress,
		dwSize,
		flNewProtect,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	return
}

func CreateRemoteThread(hProcess uintptr, sa *syscall.SecurityAttributes, stackSize uint32, startAddress uintptr, parameter uintptr, creationFlags uint32) (uintptr, uint32, error) {
	var threadId uint32
	r1, _, err := procCreateRemoteThread.Call(
		hProcess,
		uintptr(unsafe.Pointer(sa)),
		uintptr(stackSize),
		startAddress,
		parameter,
		uintptr(creationFlags),
		uintptr(unsafe.Pointer(&threadId)))

	if int(r1) == 0 {
		return 0, 0, err
	}
	return r1, threadId, nil
}
