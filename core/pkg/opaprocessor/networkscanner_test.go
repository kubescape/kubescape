package opaprocessor

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
)

func TestIsUnauthenticatedService(t *testing.T) {
	s, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if s.Set("foo", "bar") != nil {
		t.Fatal(err)
	}

	// rego input
	type args struct {
		host string
		port string
	}
	tests := []struct {
		name     string
		args     args
		want     bool
		wantBool assert.BoolAssertionFunc
	}{
		{
			"Unauthenticated service",
			args{
				host: s.Host(),
				port: s.Port(),
			},
			true,
			assert.True,
		},
		{
			"Authenticated service",
			args{
				host: s.Host(),
				port: s.Port(),
			},
			false,
			assert.False,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isUnauthenticatedService(tt.args.host, tt.args.port)
			assert.Equalf(t, tt.want, got, "isUnauthenticatedService(%v, %v)", tt.args.host, tt.args.port)
		})

		s.RequireUserAuth("user", "pass")
	}
}
