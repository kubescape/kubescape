package version

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/kubescape/kubescape/v4/core/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type errorWriter struct {
	err error
}

func (w errorWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func TestGetVersionCmd_TextOutput(t *testing.T) {
	t.Setenv("KS_SKIP_UPDATE_CHECK", "true")

	tests := []struct {
		name        string
		buildNumber string
		args        []string
		want        string
	}{
		{
			name:        "default (no flag)",
			buildNumber: "unknown",
			args:        nil,
			want:        "Your current version is: unknown\nBuild commit: \nBuild date: \n",
		},
		{
			name:        "explicit --format text",
			buildNumber: "v3.0.1",
			args:        []string{"--format", "text"},
			want:        "Your current version is: v3.0.1\nBuild commit: \nBuild date: \n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			versioncheck.BuildNumber = tt.buildNumber

			ks := core.NewKubescape(context.Background())
			cmd := GetVersionCmd(ks, tt.buildNumber, "", "")
			require.NotNil(t, cmd)

			buf := bytes.NewBufferString("")
			cmd.SetOut(buf)
			if tt.args != nil {
				cmd.SetArgs(tt.args)
			}
			require.NoError(t, cmd.Execute())

			out, err := io.ReadAll(buf)
			require.NoError(t, err)
			assert.Equal(t, tt.want, string(out))
		})
	}
}

func TestGetVersionCmd_JSONOutput(t *testing.T) {
	t.Setenv("KS_SKIP_UPDATE_CHECK", "true")

	tests := []struct {
		name    string
		version string
		commit  string
		date    string
	}{
		{
			name:    "all fields populated",
			version: "v3.0.1",
			commit:  "abc123",
			date:    "2024-01-15",
		},
		{
			name:    "empty commit and date",
			version: "v3.2.0",
			commit:  "",
			date:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			versioncheck.BuildNumber = tt.version

			ks := core.NewKubescape(context.Background())
			cmd := GetVersionCmd(ks, tt.version, tt.commit, tt.date)
			require.NotNil(t, cmd)

			buf := bytes.NewBufferString("")
			cmd.SetOut(buf)
			cmd.SetArgs([]string{"--format", "json"})
			require.NoError(t, cmd.Execute())

			out, err := io.ReadAll(buf)
			require.NoError(t, err)

			var got versionInfo
			require.NoError(t, json.Unmarshal(out, &got))
			assert.Equal(t, tt.version, got.Version)
			assert.Equal(t, tt.commit, got.Commit)
			assert.Equal(t, tt.date, got.Date)
		})
	}
}

func TestGetVersionCmd_FormatFlagRegistered(t *testing.T) {
	ks := core.NewKubescape(context.Background())
	cmd := GetVersionCmd(ks, "v3.0.0", "", "")
	require.NotNil(t, cmd)

	f := cmd.Flags().Lookup("format")
	require.NotNil(t, f, "--format flag must be registered on the version command")
	assert.Equal(t, "text", f.DefValue, "--format default must be text")
}

func TestGetVersionCmd_InvalidFormat(t *testing.T) {
	t.Setenv("KS_SKIP_UPDATE_CHECK", "true")

	ks := core.NewKubescape(context.Background())
	cmd := GetVersionCmd(ks, "v3.0.0", "", "")
	require.NotNil(t, cmd)

	cmd.SetArgs([]string{"--format", "yaml"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported format")
	assert.Contains(t, err.Error(), "yaml")
}

func TestGetVersionCmd_TextWriterError(t *testing.T) {
	t.Setenv("KS_SKIP_UPDATE_CHECK", "true")

	wantErr := errors.New("write failed")
	ks := core.NewKubescape(context.Background())
	cmd := GetVersionCmd(ks, "v3.0.0", "abc123", "2026-08-13")
	cmd.SetOut(errorWriter{err: wantErr})

	err := cmd.Execute()
	require.ErrorIs(t, err, wantErr)
}
