package lsp

import (
	"errors"
	"os"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/core"
	v1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubScannerFactory struct {
	called   bool
	scanInfo *cautils.ScanInfo
	ids      []cautils.PolicyIdentifier
	err      error
}

func (s *stubScannerFactory) NewLocalScanner(base *cautils.ScanInfo, ids []cautils.PolicyIdentifier) (*core.LocalScanner, error) {
	s.called = true
	s.scanInfo = base
	s.ids = append([]cautils.PolicyIdentifier(nil), ids...)
	return nil, s.err
}

func TestClaimStdout(t *testing.T) {
	origStdout := os.Stdout
	origStderr := os.Stderr
	origProtocolOut := protocolOut
	t.Cleanup(func() {
		os.Stdout = origStdout
		os.Stderr = origStderr
		protocolOut = origProtocolOut
	})

	t.Run("nil command is a no-op", func(t *testing.T) {
		os.Stdout = origStdout
		protocolOut = origProtocolOut

		ClaimStdout(nil)

		assert.Same(t, origStdout, os.Stdout)
		assert.Same(t, origProtocolOut, protocolOut)
	})

	t.Run("command without protocol annotation is a no-op", func(t *testing.T) {
		os.Stdout = origStdout
		protocolOut = origProtocolOut

		ClaimStdout(&cobra.Command{Use: "scan"})
		assert.Same(t, origStdout, os.Stdout)
		assert.Same(t, origProtocolOut, protocolOut)

		ClaimStdout(&cobra.Command{
			Use:         "other",
			Annotations: map[string]string{stdoutAnnotation: "false"},
		})
		assert.Same(t, origStdout, os.Stdout)
		assert.Same(t, origProtocolOut, protocolOut)
	})

	t.Run("annotated LSP command redirects os.Stdout to os.Stderr and preserves protocolOut", func(t *testing.T) {
		fakeOut, err := os.CreateTemp(t.TempDir(), "stdout-*")
		require.NoError(t, err)
		t.Cleanup(func() { _ = fakeOut.Close() })

		fakeErr, err := os.CreateTemp(t.TempDir(), "stderr-*")
		require.NoError(t, err)
		t.Cleanup(func() { _ = fakeErr.Close() })

		os.Stdout = fakeOut
		os.Stderr = fakeErr
		protocolOut = nil

		ClaimStdout(GetLSPCmd(nil))

		assert.Same(t, fakeOut, protocolOut, "protocolOut should keep the original stdout handle")
		assert.Same(t, fakeErr, os.Stdout, "os.Stdout should be redirected to os.Stderr")
	})
}

func TestGetLSPCmd_MetadataAndArgs(t *testing.T) {
	factory := &stubScannerFactory{err: errors.New("should not run")}
	cmd := GetLSPCmd(factory)

	assert.Equal(t, "lsp", cmd.Use)
	assert.Equal(t, "true", cmd.Annotations[stdoutAnnotation])
	assert.True(t, cmd.SilenceUsage)
	assert.True(t, cmd.SilenceErrors)

	cmd.SetArgs([]string{"unexpected-arg"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.False(t, factory.called, "command should fail arg validation before creating a scanner")
}

func TestGetLSPCmd_UnsupportedBuild(t *testing.T) {
	tests := []struct {
		name string
		ks   any
	}{
		{name: "nil kubescape instance", ks: nil},
		{name: "non-factory value", ks: struct{}{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := GetLSPCmd(tt.ks)
			cmd.SetArgs(nil)

			err := cmd.Execute()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "language server is not supported by this build")
		})
	}
}

func TestGetLSPCmd_ScannerFactoryWiringAndErrorPropagation(t *testing.T) {
	wantErr := errors.New("scanner init failed")
	factory := &stubScannerFactory{err: wantErr}

	cmd := GetLSPCmd(factory)
	cmd.SetArgs(nil)

	err := cmd.Execute()
	require.ErrorIs(t, err, wantErr)
	require.True(t, factory.called)
	require.NotNil(t, factory.scanInfo)
	assert.Equal(t, cautils.ScanTypeRepo, factory.scanInfo.ScanType)

	expectedIDs := cautils.BuildPolicyIdentifiers([]string{"workloadscan", "allcontrols"}, v1.KindFramework)
	assert.Equal(t, expectedIDs, factory.ids)
}
