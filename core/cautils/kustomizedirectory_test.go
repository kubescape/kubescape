package cautils

import (
	"os"
	"testing"
)

func TestGetKustomizeDirectoryName(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name                string
		args                args
		createKustomization bool // create kustomization.yml file in the path
		want                string
	}{
		{
			name: "kustomize directory without trailing slash",
			args: args{
				path: "/tmp",
			},
			createKustomization: true,
			want:                "/tmp",
		},
		{
			name: "kustomize directory with trailing slash",
			args: args{
				path: "/tmp/",
			},
			createKustomization: true,
			want:                "/tmp",
		},
		{
			name: "not kustomize directory",
			args: args{
				path: "/tmp",
			},
			createKustomization: false,
			want:                "",
		},
		{
			name: "inexistent directory",
			args: args{
				path: "/mohaidoss",
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
			if tt.createKustomization {
				_ = os.WriteFile(tt.args.path+"/kustomization.yml", []byte(""), 0644)
			}
			if got := GetKustomizeDirectoryName(tt.args.path); got != tt.want {
				t.Errorf("GetKustomizeDirectoryName() = %v, want %v", got, tt.want)
			}
			os.Remove(tt.args.path + "/kustomization.yml")
		})
	}
}

func Test_cleanPathDir(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "No trailing slash",
			args: args{
				path: "/tmp",
			},
			want: "/tmp/",
		},
		{
			name: "With trailing slash",
			args: args{
				path: "/tmp/",
			},
			want: "/tmp/",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cleanPathDir(tt.args.path); got != tt.want {
				t.Errorf("cleanPathDir() = %v, want %v", got, tt.want)
			}
		})
	}
}
