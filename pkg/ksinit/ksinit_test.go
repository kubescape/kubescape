package ksinit

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCreateKsObjectConnectionReturnsKubeconfigErrors(t *testing.T) {
	tests := []struct {
		name          string
		setupEnv      func(t *testing.T)
		wantErrSubstr string
	}{
		{
			name: "explicit kubeconfig path does not exist",
			setupEnv: func(t *testing.T) {
				t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "missing-config"))
			},
			wantErrSubstr: "no such file or directory",
		},
		{
			name: "home kubeconfig path does not exist and in cluster config is unavailable",
			setupEnv: func(t *testing.T) {
				t.Setenv("KUBECONFIG", "")
				t.Setenv("HOME", t.TempDir())
				t.Setenv("KUBERNETES_SERVICE_HOST", "")
				t.Setenv("KUBERNETES_SERVICE_PORT", "")
			},
			wantErrSubstr: "KUBERNETES_SERVICE_HOST",
		},
		{
			name: "invalid explicit kubeconfig content",
			setupEnv: func(t *testing.T) {
				configPath := filepath.Join(t.TempDir(), "config")
				require.NoError(t, os.WriteFile(configPath, []byte("bad: ["), 0600))
				t.Setenv("KUBECONFIG", configPath)
			},
			wantErrSubstr: "error loading config file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupEnv(t)

			got, err := CreateKsObjectConnection("default", time.Second)

			require.Nil(t, got)
			require.ErrorContains(t, err, tt.wantErrSubstr)
		})
	}
}
