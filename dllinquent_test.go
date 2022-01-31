package dllinquent

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestFindInSelf(t *testing.T) {
	type args struct {
		dllName     string
		funcionName string
	}
	tests := []struct {
		name    string
		args    args
		want    Result
		wantErr bool
	}{
		{
			name:    "finds it",
			args:    args{dllName: "amsi.dll", funcionName: "AmsiScanBuffer"},
			want:    Result{},
			wantErr: false,
		},
	}

	windows.MustLoadDLL("amsi.dll").MustFindProc("AmsiScanBuffer")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FindInSelf(tt.args.dllName, tt.args.funcionName)
			if (err != nil) != tt.wantErr {
				t.Errorf("FindInSelf() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got.DllBase < tt.want.FnPtr {
				t.Errorf("FindInSelf() = %v, want %v", got, tt.want)
			}
		})
	}
}
