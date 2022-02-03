// dllinquent provides the ability to search through loaded modules and functions
// withing a process' PEB
package dllinquent

import (
	"strings"

	"github.com/audibleblink/memutils"
	"golang.org/x/sys/windows"
)

// FindInProcess will walk the PEB of a given process and search for the provided dll name and function.
// Dll names must end with '.dll' and functionName is case-sensitive
func FindInProcess(pid int, dllName, functionName string) (dll Dll, err error) {

	dll = Dll{
		DllBaseName: dllName,
		FuncName:    functionName,
	}

	err = findDll(pid, &dll)
	if err != nil {
		return
	}

	return
}

// FindInProcesses will enumerate all current process, searching for provided function and returns a map of Process
// structs as keys and Dll structs as keys
func FindInProcesses(dllName, funcionName string) (funcAddrs map[memutils.WindowsProcess]Dll, err error) {
	funcAddrs = make(map[memutils.WindowsProcess]Dll)
	processes, err := memutils.Processes()
	if err != nil {
		return
	}

	for _, proc := range processes {
		dll, err := FindInProcess(proc.Pid, dllName, funcionName)
		if err != nil {
			continue
		}
		funcAddrs[proc] = dll
	}
	return
}

// FindInSelf delegates to FindInProcess, passing its own PID
func FindInSelf(dllName, functionName string) (dll Dll, err error) {
	return FindInProcess(0, dllName, functionName)
}

func findDll(pid int, dll *Dll) (err error) {

	walker, err := NewPebWalker(pid)
	if err != nil {
		return
	}

	for walker.Walk() {
		currentDllName := strings.ToLower(walker.Dll().DllFullName)
		dll.DllBaseName = strings.ToLower(dll.DllBaseName)

		if strings.HasSuffix(currentDllName, dll.DllBaseName) {
			currDll := walker.Dll()
			dll.DllFullName = currDll.DllFullName
			dll.DllBaseAddr = currDll.DllBaseAddr
			dll.FuncAddress, err = windows.GetProcAddress(windows.Handle(dll.DllBaseAddr), dll.FuncName)
			if err != nil {
				return
			}

			dll.FuncOffset = uint64(dll.FuncAddress) - dll.DllBaseAddr

			if dll.DllBaseName == "" {
				dll.DllBaseName = currDll.DllBaseName
			}
			return
		}
	}

	err = walker.Err()
	return
}
