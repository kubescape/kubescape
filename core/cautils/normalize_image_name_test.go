package cautils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_normalize_name(t *testing.T) {

	tests := []struct {
		name    string
		img     string
		want    string
		wantErr bool
	}{
		{
			name:    "Normalize simple image name",
			img:     "nginx",
			want:    "docker.io/library/nginx",
			wantErr: false,
		},
		{
			name:    "Normalize image with tag",
			img:     "nginx:latest",
			want:    "docker.io/library/nginx:latest",
			wantErr: false,
		},
		{
			name:    "Normalize image with custom registry",
			img:     "quay.io/coreos/etcd:v3.5",
			want:    "quay.io/coreos/etcd:v3.5",
			wantErr: false,
		},
		{
			name:    "Invalid image name",
			img:     "https://docker.io/library/nginx",
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, err := NormalizeImageName(tt.img)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, name, tt.name)
			}
		})
	}
}
