package dllinquent

import (
	"io"
	"unsafe"

	"github.com/audibleblink/memutils"
	"golang.org/x/sys/windows"
)

// LdrDataTableEntry64 is an expanded version of windows.LdrDataTableEntry (contains additional undocumented structures)
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
	LoadCount                  uint16
	TlsIndex                   uint16
	HashLinks                  [16]byte
}

// Dll serves as a representation of the currently iterated module in a PebWalker.
// It exposes the raw LdrDataTableEntry should the user wish to access additional
// information.
type Dll struct {
	DllFullName string
	DllBaseName string
	DllBaseAddr uint64
	FuncName    string
	FuncAddress uintptr
	FuncOffset  uint64

	LdrDataTableEntry LdrDataTableEntry64
}

// PebWalker create a bufio.Scanner-like interface for walking loaded modules in
// a process' PEB
type PebWalker struct {
	// PEB holds the PEB for the process provided to NewPebWalker
	PEB      windows.PEB
	handle   windows.Handle
	head     LdrDataTableEntry64
	current  LdrDataTableEntry64
	fullName string
	baseAddr uint64
	err      error
}

// NewPebWalker creates a new PebWalker from the provided PID
func NewPebWalker(pid int) (pw PebWalker, err error) {
	pw = PebWalker{}

	perms := windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_VM_READ
	pw.handle, err = memutils.HandleForPid(pid, perms)
	if err != nil {
		return
	}

	pw.PEB, err = memutils.GetPEB(pw.handle)
	if err != nil {
		return
	}

	pw.head = LdrDataTableEntry64{
		InMemoryOrderLinks: pw.PEB.Ldr.InMemoryOrderModuleList,
	}

	return pw, err
}

// Walk returns true as long as there is Flink (Forward Link) in the Linked List
// of loaded modules
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

// Dll return a repreesentation of the currently iterated module
func (pw PebWalker) Dll() Dll {
	return Dll{
		DllFullName:       pw.fullName,
		DllBaseAddr:       pw.baseAddr,
		LdrDataTableEntry: pw.current,
	}
}

// Err returns the error that broke out of the Walk loop. If the list is exhausted,
// Err returns io.EOF
func (pw PebWalker) Err() error {
	return pw.err
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

	if pw.head.BaseDllName.Length != 0 {
		pw.fullName, err = memutils.PopulateStrings(pw.handle, &pw.head.FullDllName)
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
