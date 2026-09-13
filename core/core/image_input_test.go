package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClassifyImageInput(t *testing.T) {
	statWith := func(existing ...string) func(string) bool {
		set := map[string]struct{}{}
		for _, p := range existing {
			set[p] = struct{}{}
		}
		return func(p string) bool {
			_, ok := set[p]
			return ok
		}
	}

	tests := []struct {
		name         string
		image        string
		statExisting []string
		wantRegistry bool
		wantScheme   string
		wantEmptyErr bool
	}{
		{name: "registry simple", image: "nginx:1.27", wantRegistry: true},
		{name: "registry with port and tar-like repo keeps registry", image: "myregistry.io:5000/team/my.tar:v1", wantRegistry: true},
		{name: "docker-archive scheme", image: "docker-archive:/tmp/x.tar", wantRegistry: false, wantScheme: "docker-archive"},
		{name: "uppercase scheme", image: "DOCKER-ARCHIVE:/tmp/x.tar", wantRegistry: false, wantScheme: "DOCKER-ARCHIVE"},
		{name: "oci-archive scheme", image: "oci-archive:/tmp/x.tar", wantRegistry: false, wantScheme: "oci-archive"},
		{name: "oci-dir scheme", image: "oci-dir:/tmp/layout", wantRegistry: false, wantScheme: "oci-dir"},
		{name: "dir scheme", image: "dir:/tmp/rootfs", wantRegistry: false, wantScheme: "dir"},
		{name: "sbom scheme", image: "sbom:/tmp/sbom.json", wantRegistry: false, wantScheme: "sbom"},
		{name: "bare tar existing file", image: "/tmp/x.tar", statExisting: []string{"/tmp/x.tar"}, wantRegistry: false},
		{name: "bare tgz path", image: "./rel/a.tgz", statExisting: []string{"./rel/a.tgz"}, wantRegistry: false},
		{name: "bare dir existing", image: "./mydir", statExisting: []string{"./mydir"}, wantRegistry: false},
		{name: "nonexistent relative no slash stays registry", image: "myimage", wantRegistry: true},
		{name: "empty", image: "   ", wantRegistry: false, wantEmptyErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry, scheme, errEmpty := classifyImageInput(tt.image, statWith(tt.statExisting...))
			assert.Equal(t, tt.wantRegistry, registry)
			assert.Equal(t, tt.wantScheme, scheme)
			if tt.wantEmptyErr {
				assert.Error(t, errEmpty)
			} else {
				assert.NoError(t, errEmpty)
			}
		})
	}
}

func TestGetAttributesFromImageRejectsArchive(t *testing.T) {
	_, err := getAttributesFromImage("docker-archive:/tmp/x.tar")
	assert.Error(t, err)
}
