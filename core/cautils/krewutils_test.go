package cautils

import (
	"os"
	"testing"
)

func TestIsKrewPlugin(t *testing.T) {
	tests := []struct {
		name string
		arg  string
		want bool
	}{
		{
			name: "krew plugin",
			arg:  "kubectl-kubescape",
			want: true,
		},
		{
			name: "not krew plugin",
			arg:  "kubescape",
			want: false,
		},
		{
			name: "empty",
			arg:  "",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Args = []string{tt.arg}
			result := IsKrewPlugin()
			if result != tt.want {
				t.Errorf("IsKrewPlugin() = %v, want %v", result, tt.want)
			}
		})
	}
}

func TestExecName(t *testing.T) {
	tests := []struct {
		name string
		arg  string
		want string
	}{
		{
			name: "krew plugin",
			arg:  "kubectl-kubescape",
			want: "kubectl kubescape",
		},
		{
			name: "not krew plugin",
			arg:  "kubescape",
			want: "kubescape",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Args = []string{tt.arg}
			if got := ExecName(); got != tt.want {
				t.Errorf("ExecName() = %v, want %v", got, tt.want)
			}
		})
	}
}
