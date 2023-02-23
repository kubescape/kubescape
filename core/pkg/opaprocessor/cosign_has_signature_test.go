package opaprocessor

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_has_signature(t *testing.T) {

	tests := []struct {
		name string
		img  string
		want bool
	}{
		{
			name: "valid signature",
			img:  "quay.io/kubescape/gateway",
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, has_signature(tt.img), tt.name)
		})
	}
}
