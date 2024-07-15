package cautils

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetKustomizeDirectoryName(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name                string
		args                args
		want                string
		createKustomization bool
	}{
		{
			name: "kustomize directory",
			args: args{
				path: os.TempDir(),
			},
			createKustomization: true,
			want:                os.TempDir(),
		},
		{
			name: "not kustomize directory",
			args: args{
				path: os.TempDir(),
			},
			createKustomization: false,
			want:                "",
		},
		{
			name: "inexistent directory",
			args: args{
				path: filepath.Join(os.TempDir(), "bla"),
			},
			createKustomization: false,
			want:                "",
		},
		{
			name: "empty",
			args: args{
				path: "",
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempFile := filepath.Join(tt.args.path, "kustomization.yaml")
			if tt.createKustomization {
				_ = os.WriteFile(tempFile, []byte(""), 0644)
			}
			if got := getKustomizeDirectoryName(tt.args.path); got != tt.want {
				t.Errorf("GetKustomizeDirectoryName() = %v, want %v", got, tt.want)
			}
			os.Remove(tempFile)
		})
	}
}
