package dllinquent

import (
	"io"
	"unsafe"

	"github.com/audibleblink/memutils"
	"golang.org/x/sys/windows"
)

type LdrDataTableEntry64 struct {
	InOrderLinks               windows.LIST_ENTRY
	InMemoryOrderLinks         windows.LIST_ENTRY
	InInitializationOrderLinks windows.LIST_ENTRY
	DllBase                    uint64
	EntryPoint                 uint64
	SizeOfImage                uint64
	FullDllName                windows.NTUnicodeString
	BaseDllName                windows.NTUnicodeString
	Flags                      uint32
	LoadCount                  uint16 // named ObseleteLoadCount OS6.2+
	TlsIndex                   uint16
	HashLinks                  [16]byte // increase by PVOID+ULONG if <OS6.2
}

type Dll struct {
	DllBaseName string
	DllBaseAddr uint64
	FuncAddress uintptr

	LdrDataTableEntry LdrDataTableEntry64
}

type PebWalker struct {
	err      error
	head     LdrDataTableEntry64
	current  LdrDataTableEntry64
	fullName string
	baseAddr uint64
	handle   windows.Handle
	peb      windows.PEB
}

func NewPebWalker(pid int) (pw PebWalker, err error) {
	pw = PebWalker{}

	perms := windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_VM_READ
	pw.handle, err = memutils.HandleForPid(pid, perms)
	if err != nil {
		return
	}

	pw.peb, err = memutils.GetPEB(pw.handle)
	if err != nil {
		return
	}

	pw.head = LdrDataTableEntry64{
		InMemoryOrderLinks: pw.peb.Ldr.InMemoryOrderModuleList,
	}

	return pw, err
}

func (pw *PebWalker) next() (head LdrDataTableEntry64) {

	err := memutils.ReadMemory(
		pw.handle,
		unsafe.Pointer(pw.head.InMemoryOrderLinks.Flink),
		unsafe.Pointer(&pw.head.InMemoryOrderLinks.Flink),
		uint32(unsafe.Sizeof(pw.head)),
	)
	if err != nil {
		pw.err = err
		return
	}

	pw.current = pw.head

	if pw.head.BaseDllName.Length > 0 {
		pw.fullName, err = memutils.PopulateStrings(pw.handle, &pw.head.BaseDllName)
		if err != nil {
			pw.err = err
			return
		}
	} else {
		pw.fullName = ""
	}

	pw.baseAddr = pw.head.DllBase

	return pw.head

}

func (pw *PebWalker) Walk() bool {

	pw.current = pw.next()

	if pw.err != nil {
		return false
	}

	if pw.fullName == "" {
		pw.err = io.EOF
		return false
	}

	return true
}

func (pw PebWalker) Dll() Dll {
	return Dll{
		DllBaseName:       pw.fullName,
		DllBaseAddr:       pw.baseAddr,
		LdrDataTableEntry: pw.current,
	}
}

func (pw PebWalker) Err() error {
	return pw.err
}
