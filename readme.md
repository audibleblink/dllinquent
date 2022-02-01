# dllinquent

- Search running process for a given dll/function. 
- Exposes a bufio.Scanner-like interface for walking a process' PEB


## Examples


### Walker
```golang
walker, _ := NewPebWalker(pid)
for walker.Walk() {
    dll := walker.Dll()

    if strings.HasSuffix(dll.DllFullName, "amsi.dll") {
        hFunc, _ = windows.GetProcAddress(
            windows.Handle(dll.DllBaseAddr), 
            "AmsiScanBuffer",
            )

        funcOffset = uint64(dll.FuncAddress) - dll.DllBaseAddr
        fmt.Printf("AmsiScanBuffer offset: %v", funcOffset)
    }
    
    if walker.Err() == io.EOF {
        fmt.Println("amsi not loaded")
    }
}

err = walker.Err()
return
```

### Finding Dlls/Functions

```go
// dllinquent.FindInSelf("amsi.dll", "AmsiScanBuffer")          (Dll, err)
// dllinquent.FindInProcess(123, "amsi.dll", "AmsiScanBuffer")  (Dll, err)
// dllinquent.FindInProcesses("amsi.dll", "AmsiScanBuffer")     (map[Process]Dll, err)

func HasAmsi() (hasAmsi bool, dll Dll, err error) {
	dll, err = dllinquent.FindInSelf("amsi.dll", "AmsiScanBuffer")
	if err != nil {
		return
	}

	if dll != (dllinquent.Dll{}) {
		hasAmsi = true
	}
	return
}
```
