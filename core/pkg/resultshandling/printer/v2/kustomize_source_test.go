package printer

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
