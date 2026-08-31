package cautils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestImageScanDataTarget(t *testing.T) {
	tests := []struct {
		name string
		data ImageScanData
		want string
	}{
		{
			name: "legacy scan without platform",
			data: ImageScanData{Image: "docker.io/library/nginx:latest"},
			want: "docker.io/library/nginx:latest",
		},
		{
			name: "Linux amd64 variant",
			data: ImageScanData{
				Image: "docker.io/library/nginx:latest", Platform: "linux/amd64",
			},
			want: "docker.io/library/nginx:latest [linux/amd64]",
		},
		{
			name: "Linux ARM variant",
			data: ImageScanData{
				Image: "registry.example.com/team/app:v2", Platform: "linux/arm/v7",
			},
			want: "registry.example.com/team/app:v2 [linux/arm/v7]",
		},
		{
			name: "Windows variant",
			data: ImageScanData{
				Image: "registry.example.com/windows/app:v2", Platform: "windows/amd64",
			},
			want: "registry.example.com/windows/app:v2 [windows/amd64]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.data.Target())
		})
	}
}
