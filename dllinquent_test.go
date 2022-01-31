package dllinquent

import (
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestFindInSelf(t *testing.T) {
	type args struct {
		dllName      string
		functionName string
	}
	tests := []struct {
		name    string
		args    args
		wantDll Dll
		wantErr bool
	}{
		{
			name: "does not find dbghelp",
			args: args{
				dllName:      "dbghelp.dll",
				functionName: "MiniDumpWriteDump",
			},
			wantDll: Dll{},
			wantErr: true,
		},
		{
			name: "finds amsi",
			args: args{
				dllName:      "amsi.dll",
				functionName: "AmsiScanBuffer",
			},
			wantDll: Dll{},
			wantErr: false,
		},
	}

	windows.MustLoadDLL("amsi.dll").MustFindProc("AmsiScanBuffer")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDll, err := FindInSelf(tt.args.dllName, tt.args.functionName)
			if (err != nil) != tt.wantErr {
				t.Errorf("FindInSelf() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !(gotDll.DllBaseAddr <= uint64(gotDll.FuncAddress)) {
				t.Errorf("FindInSelf() = %v, want %v", gotDll, tt.wantDll)
			}
		})
	}
}

func TestFindInProcess(t *testing.T) {
	type args struct {
		pid          int
		dllName      string
		functionName string
	}
	tests := []struct {
		name    string
		args    args
		wantDll Dll
		wantErr bool
	}{
		{
			name: "finds dll but doesn't find non-exitent proc",
			args: args{
				pid:          os.Getpid(),
				dllName:      "rpcrt4.dll",
				functionName: "foo",
			},
			wantDll: Dll{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDll, err := FindInProcess(tt.args.pid, tt.args.dllName, tt.args.functionName)
			if (err != nil) != tt.wantErr {
				t.Errorf("FindInProcess() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != windows.ERROR_PROC_NOT_FOUND {
				t.Errorf("FindInProcess() = %v, want %v", gotDll, tt.wantDll)
			}
		})
	}
}

func TestFindInProcesses(t *testing.T) {
	type args struct {
		dllName     string
		funcionName string
	}
	tests := []struct {
		name          string
		args          args
		wantFundAddrs []Dll
		wantErr       bool
	}{
		{
			name: "finds many processes with dbghelp.MiniDumpWriteDump",
			args: args{
				dllName:     "amsi.dll",
				funcionName: "AmsiScanBuffer",
			},
			wantFundAddrs: []Dll{},
			wantErr:       false,
		},
	}

	windows.MustLoadDLL("amsi.dll").MustFindProc("AmsiScanBuffer")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFundAddrs, err := FindInProcesses(tt.args.dllName, tt.args.funcionName)
			if (err != nil) != tt.wantErr {
				t.Errorf("FindInProcesses() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(gotFundAddrs) < 1 {
				t.Errorf("FindInProcesses() = %v, want %v", gotFundAddrs, tt.wantFundAddrs)
			}
		})
	}
}
