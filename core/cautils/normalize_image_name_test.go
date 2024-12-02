package cautils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_normalize_name(t *testing.T) {

	tests := []struct {
		name string
		img  string
		want string
	}{
		{
			name: "Normalize image name",
			img:  "nginx",
			want: "docker.io/library/nginx",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, _ := NormalizeImageName(tt.img)
			assert.Equal(t, tt.want, name, tt.name)
		})
	}
}
