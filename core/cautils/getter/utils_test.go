package getter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// should return true if the string is present in the slice
func TestContains(t *testing.T) {
	tests := []struct {
		str  []string
		key  string
		want bool
	}{
		{
			str:  []string{"apple", "banana", "orange"},
			key:  "banana",
			want: true,
		},
		{
			str:  []string{"apple", "banana", "orange"},
			key:  "mango",
			want: false,
		},
		{
			str:  []string{"", "banana", "banana"},
			key:  "banana",
			want: true,
		},
		{
			str:  []string{"", "", ""},
			key:  "grape",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			assert.Equal(t, tt.want, contains(tt.str, tt.key))
		})
	}
}
