package data

import (
	"reflect"
	"unsafe"
)

type Pointer[T any] struct {
	Address uintptr
}

func NewManagedPtr[T any](addr uintptr) *Pointer[T] {
	return &Pointer[T]{
		Address: addr,
	}
}

func (p *Pointer[T]) Value() T {
	return *(*T)(unsafe.Pointer(p.Address))
}

func (p *Pointer[T]) SetValue(value T) {
	*(*T)(unsafe.Pointer(p.Address)) = value
}

func (p *Pointer[T]) Add(i int) {
	var t T
	p.Address += unsafe.Sizeof(t) * uintptr(i)
}

func (p *Pointer[T]) ToBytes() []byte {
	var t T
	var buff []byte
	ptr := (*reflect.SliceHeader)(unsafe.Pointer(&buff))
	ptr.Len = int(unsafe.Sizeof(t))
	ptr.Cap = int(unsafe.Sizeof(t))
	ptr.Data = p.Address
	return buff
}
