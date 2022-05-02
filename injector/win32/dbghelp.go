package win32

import "syscall"

var (
	dbgHelp = syscall.NewLazyDLL("Dbghelp.dll")

	procImageRvaToVa = dbgHelp.NewProc("ImageRvaToVa")
)

func ImageRvaToVa(ntHeaders, base, rva, lastRvaSection uintptr) (addr uintptr, err error) {
	ret, _, err := procImageRvaToVa.Call(ntHeaders, base, rva, lastRvaSection)
	if int(ret) == 0 {
		return ret, err
	}
	return ret, nil
}
