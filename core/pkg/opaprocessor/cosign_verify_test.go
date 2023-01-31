package opaprocessor

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_verify(t *testing.T) {
	type args struct {
		img string
		key string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr assert.ErrorAssertionFunc
	}{
		{
			"valid signature",
			args{
				img: "hisu/cosign-tests:signed",
				key: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGnMCUU0jGe6r4mPsPuyTXf61PE4e\nNwB/31SvUMmnoyd/1UxSqd+MRPXPU6pcub4k6E9G9SprVCuf6Sydcbyiqw==\n-----END PUBLIC KEY-----",
			},
			true,
			assert.NoError,
		},
		{
			"no signature",
			args{
				img: "hisu/cosign-tests:unsigned",
				key: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGnMCUU0jGe6r4mPsPuyTXf61PE4e\nNwB/31SvUMmnoyd/1UxSqd+MRPXPU6pcub4k6E9G9SprVCuf6Sydcbyiqw==\n-----END PUBLIC KEY-----",
			},
			false,
			assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := verify(tt.args.img, tt.args.key)
			if !tt.wantErr(t, err, fmt.Sprintf("verify(%v, %v)", tt.args.img, tt.args.key)) {
				return
			}
			assert.Equalf(t, tt.want, got, "verify(%v, %v)", tt.args.img, tt.args.key)
		})
	}
}
