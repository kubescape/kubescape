package core

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetOSType(t *testing.T) {
	tests := []struct {
		name          string
		osRelease     string
		expected      string
		expectedError error
		wantError     bool
	}{
		{
			name: "alpine",
			osRelease: `NAME="Alpine Linux"
VERSION_ID=3.19.1
`,
			expected: "alpine",
		},
		{
			name: "debian",
			osRelease: `NAME="Debian GNU/Linux"
VERSION_ID="12"
`,
			expected: "debian",
		},
		{
			name: "ubuntu",
			osRelease: `NAME="Ubuntu"
VERSION_ID="22.04"
`,
			expected: "ubuntu",
		},
		{
			name: "amazon linux",
			osRelease: `NAME="Amazon Linux"
VERSION_ID="2023"
`,
			expected: "amazon",
		},
		{
			name: "centos",
			osRelease: `NAME="CentOS Linux"
VERSION_ID="7"
`,
			expected: "centos",
		},
		{
			name: "mariner",
			osRelease: `NAME="CBL-Mariner"
VERSION_ID="2.0"
`,
			expected: "cbl-mariner",
		},
		{
			name: "azure linux",
			osRelease: `NAME="Azure Linux"
VERSION_ID="3.0"
`,
			expected: "azurelinux",
		},
		{
			name: "red hat",
			osRelease: `NAME="Red Hat Enterprise Linux"
VERSION_ID="9.4"
`,
			expected: "redhat",
		},
		{
			name: "rocky",
			osRelease: `NAME="Rocky Linux"
VERSION_ID="9.4"
`,
			expected: "rocky",
		},
		{
			name: "oracle",
			osRelease: `NAME="Oracle Linux Server"
VERSION_ID="8.9"
`,
			expected: "oracle",
		},
		{
			name: "alma",
			osRelease: `NAME="AlmaLinux"
VERSION_ID="9.4"
`,
			expected: "alma",
		},
		{
			name: "unsupported distro",
			osRelease: `NAME="Wolfi"
VERSION_ID="20240513"
`,
			expectedError: errors.ErrUnsupported,
		},
		{
			name:      "malformed os release",
			osRelease: "\x00",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := getOSType(context.Background(), []byte(tt.osRelease))

			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
				assert.Empty(t, actual)
				return
			}
			if tt.wantError {
				assert.Error(t, err)
				assert.Empty(t, actual)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestGetOSVersion(t *testing.T) {
	tests := []struct {
		name      string
		osRelease string
		expected  string
	}{
		{
			name: "quoted version",
			osRelease: `NAME="Ubuntu"
VERSION_ID="22.04"
`,
			expected: "22.04",
		},
		{
			name: "unquoted version",
			osRelease: `NAME="Amazon Linux"
VERSION_ID=2023
`,
			expected: "2023",
		},
		{
			name: "missing version",
			osRelease: `NAME="Debian GNU/Linux"
`,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := getOSVersion(context.Background(), []byte(tt.osRelease))

			assert.NoError(t, err)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
