package getter

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseHost(t *testing.T) {
	t.Parallel()

	t.Run("should recognize http scheme", func(t *testing.T) {
		t.Parallel()

		const input = "http://localhost:7555"
		scheme, host := parseHost(input)
		require.Equal(t, "http", scheme)
		require.Equal(t, "localhost:7555", host)
	})

	t.Run("should recognize https scheme", func(t *testing.T) {
		t.Parallel()

		const input = "https://localhost:7555"
		scheme, host := parseHost(input)
		require.Equal(t, "https", scheme)
		require.Equal(t, "localhost:7555", host)
	})

	t.Run("should adopt https scheme by default", func(t *testing.T) {
		t.Parallel()

		const input = "portal-dev.armo.cloud"
		scheme, host := parseHost(input)
		require.Equal(t, "https", scheme)
		require.Equal(t, "portal-dev.armo.cloud", host)
	})
}

func TestIsNativeFramework(t *testing.T) {
	t.Parallel()

	require.Truef(t, isNativeFramework("nSa"), "expected nsa to be native (case insensitive)")
	require.Falsef(t, isNativeFramework("foo"), "expected framework to be custom")
}

func Test_readString(t *testing.T) {
	type args struct {
		rdr      io.Reader
		sizeHint int64
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "should return empty string if sizeHint is negative",
			args: args{
				rdr:      nil,
				sizeHint: -1,
			},
			want:    "",
			wantErr: false,
		},
		{
			name: "should return empty string if sizeHint is zero",
			args: args{
				rdr:      &io.LimitedReader{},
				sizeHint: 0,
			},
			want:    "",
			wantErr: false,
		},
		{
			name: "should return empty string if sizeHint is positive",
			args: args{
				rdr:      &io.LimitedReader{},
				sizeHint: 1,
			},
			want:    "",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readString(tt.args.rdr, tt.args.sizeHint)
			if (err != nil) != tt.wantErr {
				t.Errorf("readString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("readString() = %v, want %v", got, tt.want)
			}
		})
	}
}
