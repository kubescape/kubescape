package containerscan

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCalculateFixed_All(t *testing.T) {
	tests := []struct {
		Fixes []FixedIn
		want  int
	}{
		{
			Fixes: []FixedIn{
				{Version: "None"},
				{Version: ""},
				{Version: "1.0.0"},
			},
			want: 1,
		},
		{
			Fixes: []FixedIn{
				{Version: "None"},
				{Version: ""},
				{Version: ""},
			},
			want: 0,
		},
		{
			Fixes: []FixedIn{
				{Version: "None"},
				{Version: ""},
				{Version: "None"},
			},
			want: 0,
		},
		{
			Fixes: []FixedIn{
				{Version: "None"},
				{Version: ""},
				{Version: "1.0.0"},
				{Version: "2.0.0"},
			},
			want: 1,
		},
		{
			Fixes: []FixedIn{
				{Version: "None"},
				{Version: ""},
				{Version: "1.0.0"},
				{Version: ""},
			},
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			assert.Equal(t, tt.want, CalculateFixed(tt.Fixes))
		})
	}
}
