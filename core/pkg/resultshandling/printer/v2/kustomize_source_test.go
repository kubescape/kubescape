package printer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A Kustomize resource is attributed to the file Kustomize read it from, but it
// has no document index: its own path is the Kustomize directory. The table must
// name the file and must not invent a line for it, because the rendered resource
// is a composition of a base and its overlays and no line in one file is the
// line of a field. The manifest is on disk and contains the field, so a line
// would be found if the table were willing to guess an index.
func TestResourceTableNamesTheKustomizeOriginFileWithoutALine(t *testing.T) {
	session := resourceTableLineNumberSession(t, lineNumberManifest, "")

	out := renderResourceTable(t, session, true)

	assert.Contains(t, out, "Source: deploy.yaml")
	assert.Contains(t, out, "@ deploy.yaml")
	assert.Contains(t, out, "privileged=false")
	assert.NotContains(t, out, "(line ", "no line is reported for a resource without a document index")
}

// When a field of a rendered resource can be traced to an overlay patch, the evidence
// names the patching file next to the base file (e.g. "@ base/deploy.yaml (patch: overlay/patch.yaml)").
func TestResourceTableNamesOverlayPatchInEvidence(t *testing.T) {
	root := t.TempDir()
	overlayDir := filepath.Join(root, "overlay")
	require.NoError(t, os.MkdirAll(overlayDir, 0o755))

	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "kustomization.yaml"), []byte(`
resources:
- ../base
patches:
- path: patch.yaml
  target:
    kind: Deployment
    name: demo
`), 0o600))

	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "patch.yaml"), []byte(`
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
spec:
  template:
    spec:
      containers:
      - name: nginx
        securityContext:
          privileged: true
`), 0o600))

	session := resourceTableLineNumberSession(t, lineNumberManifest, "")
	resourceID := "apps/v1/default/Deployment/demo"
	session.ResourceSource[resourceID] = reporthandling.Source{
		Path:                   root,
		RelativePath:           "base/deploy.yaml",
		FileType:               reporthandling.SourceTypeKustomizeDirectory,
		KustomizeDirectoryName: overlayDir,
	}

	out := renderResourceTable(t, session, true)

	assert.Contains(t, out, "Source: base/deploy.yaml")
	assert.Contains(t, out, "@ base/deploy.yaml (patch: overlay/patch.yaml)")
	assert.Contains(t, out, "privileged=false")
	assert.NotContains(t, out, "(line ")
}

// Where a field cannot be traced to a patch, today's behavior of naming only the base file
// in the evidence is preserved.
func TestResourceTableUnpatchedFieldKeepsBaseFileOnly(t *testing.T) {
	root := t.TempDir()
	overlayDir := filepath.Join(root, "overlay")
	require.NoError(t, os.MkdirAll(overlayDir, 0o755))

	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "kustomization.yaml"), []byte(`
resources:
- ../base
patches:
- path: patch.yaml
  target:
    kind: Deployment
    name: demo
`), 0o600))

	// patch only touches replicas, not the privileged field
	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "patch.yaml"), []byte(`
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
spec:
  replicas: 3
`), 0o600))

	session := resourceTableLineNumberSession(t, lineNumberManifest, "")
	resourceID := "apps/v1/default/Deployment/demo"
	session.ResourceSource[resourceID] = reporthandling.Source{
		Path:                   root,
		RelativePath:           "base/deploy.yaml",
		FileType:               reporthandling.SourceTypeKustomizeDirectory,
		KustomizeDirectoryName: overlayDir,
	}

	out := renderResourceTable(t, session, true)

	assert.Contains(t, out, "Source: base/deploy.yaml")
	assert.Contains(t, out, "@ base/deploy.yaml")
	assert.NotContains(t, out, "(patch:")
}
