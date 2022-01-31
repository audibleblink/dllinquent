package dllinquent

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/audibleblink/memutils"
)

type matchFn func(windows.LDR_DATA_TABLE_ENTRY, *Result) bool

type Result struct {
	DllBase uintptr `json:"dll_base"`
	FnPtr   uintptr `json:"fn_ptr"`
	PE      string  `json:"pe"`
}

// func FindInProcesses(dllName, funcionName string) []int {
// 	processes, err := procs.Processes()
// 	if err != nil {
// 		fmt.Fprintln(os.Stderr, err)
// 		os.Exit(1)
// 	}
//
// 	for _, proc := range processes {
// 		FindInProcess(proc.Pid, dllName, funcionName)
// 	}
// 	return make([]int, 0)
// }

func FindInProcess(hProcess windows.Handle, dllName, funcionName string) []int {
	return make([]int, 0)
}

func FindInSelf(dllName, funcionName string) (Result, error) {
	peb := windows.RtlGetCurrentPeb()
	hProcess := windows.CurrentProcess()

	dllMatchFn := findDll(dllName)
	dll := Result{}
	err := walkDlls(hProcess, peb, dllMatchFn, &dll)
	if err != nil {
		return dll, err
	}

	if dll == (Result{}) {
		return dll, fmt.Errorf("not found")
	}

	dll.FnPtr, err = windows.GetProcAddress(windows.Handle(dll.DllBase), funcionName)
	return dll, err
}

func findDll(want string) matchFn {
	return func(got windows.LDR_DATA_TABLE_ENTRY, result *Result) (found bool) {
		gotName := strings.ToLower(got.FullDllName.String())
		want = strings.ToLower(want)
		if strings.HasSuffix(gotName, want) {
			result.DllBase = got.DllBase
			found = true
			return
		}
		return
	}
}

func walkDlls(hProc windows.Handle, peb *windows.PEB, matcher matchFn, result *Result) (err error) {
	head := windows.LDR_DATA_TABLE_ENTRY{
		InMemoryOrderLinks: peb.Ldr.InMemoryOrderModuleList,
	}

	isBasePE := true
	for {
		// read the current LIST_ENTRY f(orward)link into a LDR_DATA_TABLE_ENTRY
		start := unsafe.Pointer(head.InMemoryOrderLinks.Flink)
		dest := unsafe.Pointer(&head.InMemoryOrderLinks.Flink)
		size := uint32(unsafe.Sizeof(head))
		err = memutils.ReadMemory(hProc, start, dest, size)
		if err != nil {
			return
		}

		// populate the DLL Name buffer with the remote address currently
		// stored at head.FullDllName
		var name string
		name, err = memutils.PopulateStrings(hProc, &head.FullDllName)
		if err != nil {
			return
		}

		if isBasePE {
			isBasePE = false
			result.PE = name
		}

		if name == "" {
			// we've reached the end of the Dll list
			return
		}

		matcher(head, result)
	}
}
