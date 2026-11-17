package lsp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPathFromURI(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		windows bool
		want    string
		wantErr bool
	}{
		{name: "unix", uri: "file:///home/dev/k8s/pod.yaml", want: "/home/dev/k8s/pod.yaml"},
		{name: "unix percent-encoded", uri: "file:///home/dev/my%20dir/p%C3%B6d.yaml", want: "/home/dev/my dir/pöd.yaml"},
		{name: "unix localhost", uri: "file://localhost/home/dev/pod.yaml", want: "/home/dev/pod.yaml"},
		{name: "unix remote host", uri: "file://otherhost/share/pod.yaml", wantErr: true},
		{name: "not a file", uri: "untitled:Untitled-1", wantErr: true},
		{name: "https", uri: "https://example.com/pod.yaml", wantErr: true},
		{name: "no path", uri: "file://", wantErr: true},
		{name: "windows drive", uri: "file:///C:/Users/dev/pod.yaml", windows: true, want: `C:\Users\dev\pod.yaml`},
		{name: "windows drive, VS Code encoding", uri: "file:///c%3A/Users/dev/my%20dir/pod.yaml", windows: true, want: `c:\Users\dev\my dir\pod.yaml`},
		{name: "windows UNC", uri: "file://server/share/dir/pod.yaml", windows: true, want: `\\server\share\dir\pod.yaml`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pathFromURIFor(tt.uri, tt.windows)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestURIFromPath(t *testing.T) {
	assert.Equal(t, "file:///home/dev/my%20dir/pod.yaml", uriFromPathFor("/home/dev/my dir/pod.yaml", false))
	assert.Equal(t, "file:///C:/Users/dev/pod.yaml", uriFromPathFor(`C:\Users\dev\pod.yaml`, true))
	assert.Equal(t, "file://server/share/pod.yaml", uriFromPathFor(`\\server\share\pod.yaml`, true))
}

func TestURIRoundTrip(t *testing.T) {
	for _, p := range []string{"/a/b c/d.yaml", "/ünï/çode/p#d.yaml", "/a/100%/x.yaml"} {
		got, err := pathFromURIFor(uriFromPathFor(p, false), false)
		require.NoError(t, err)
		assert.Equal(t, p, got)
	}
}
