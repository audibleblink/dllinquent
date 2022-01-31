package dllinquent

import (
	"strings"

	"github.com/audibleblink/memutils"
	"golang.org/x/sys/windows"
)

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

func FindInProcess(pid int, dllName, functionName string) (dll Dll, err error) {
	dll, err = findDll(pid, dllName)
	if err != nil {
		return
	}

	dll.FuncAddress, err = windows.GetProcAddress(windows.Handle(dll.DllBaseAddr), functionName)
	return
}

func FindInSelf(dllName, functionName string) (dll Dll, err error) {
	return FindInProcess(0, dllName, functionName)
}

func findDll(pid int, dllname string) (dll Dll, err error) {

	walker, err := NewPebWalker(pid)
	if err != nil {
		return
	}

	for walker.Walk() {
		currentDllName := strings.ToLower(walker.Dll().DllBaseName)
		dllname = strings.ToLower(dllname)

		if strings.HasSuffix(currentDllName, dllname) {
			dll = walker.Dll()
			return
		}
	}

	err = walker.Err()
	return
}
