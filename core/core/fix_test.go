package core

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUserConfirmed(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{
			input: "yes",
			want:  true,
		},
		{
			input: "y",
			want:  true,
		},
		{
			input: "no",
			want:  false,
		},
		{
			input: "n",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(string(tt.input), func(t *testing.T) {
			r, w, _ := os.Pipe()
			os.Stdin = r
			defer func() {
				os.Stdin = os.Stdin
			}()

			go func() {
				fmt.Fprintln(w, tt.input)
			}()

			got := userConfirmed()

			assert.Equal(t, tt.want, got)
		})
	}
}
