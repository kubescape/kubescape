package opaprocessor

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
				img: "quay.io/kubescape/kubescape:v3.0.3",
				key: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbgIMZrMTTlEFDLEeZXz+4R/908BG\nEeO70x6oMN7E4JQgzgbCB5rinqhK5t7dB61saVKQTb4P2NGtjPjXVbSTwQ==\n-----END PUBLIC KEY-----\n",
			},
			true,
			assert.NoError,
		},
		{
			"wrong signature",
			args{
				img: "quay.io/kubescape/kubescape:v2.9.2",
				key: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbgIMZrMTTlEFDLEeZXz+4R/908BG\nEeO70x6oMN7E4JQgzgbCB5rinqhK5t7dB61saVKQTb4P2NGtjPjXVbSTwQ==\n-----END PUBLIC KEY-----\n",
			},
			false,
			assert.Error,
		},
		{
			"no matching signature",
			args{
				img: "quay.io/kubescape/kubescape:v2.0.171",
				key: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbgIMZrMTTlEFDLEeZXz+4R/908BG\nEeO70x6oMN7E4JQgzgbCB5rinqhK5t7dB61saVKQTb4P2NGtjPjXVbSTwQ==\n-----END PUBLIC KEY-----\n",
			},
			false,
			assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := verify(context.Background(), tt.args.img, tt.args.key)
			if !tt.wantErr(t, err, fmt.Sprintf("verify(%v, %v)", tt.args.img, tt.args.key)) {
				return
			}
			assert.Equalf(t, tt.want, got, "verify(%v, %v)", tt.args.img, tt.args.key)
		})
	}
}

func TestVerify_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := verify(
		ctx,
		"quay.io/kubescape/kubescape:v3.0.3",
		"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbgIMZrMTTlEFDLEeZXz+4R/908BG\nEeO70x6oMN7E4JQgzgbCB5rinqhK5t7dB61saVKQTb4P2NGtjPjXVbSTwQ==\n-----END PUBLIC KEY-----\n",
	)

	require.Error(t, err)
	require.ErrorIs(t, err, context.Canceled)
}

func TestVerify_DeadlineExceeded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()

	time.Sleep(time.Millisecond)

	_, err := verify(
		ctx,
		"quay.io/kubescape/kubescape:v3.0.3",
		"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbgIMZrMTTlEFDLEeZXz+4R/908BG\nEeO70x6oMN7E4JQgzgbCB5rinqhK5t7dB61saVKQTb4P2NGtjPjXVbSTwQ==\n-----END PUBLIC KEY-----\n",
	)

	require.Error(t, err)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}
