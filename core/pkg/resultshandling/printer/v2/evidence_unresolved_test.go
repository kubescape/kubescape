package printer

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/stretchr/testify/assert"
)

// In the terminal --show-evidence view a delete or review path that selects
// nothing in the resource is marked unresolved, so a reader can tell a path
// that was looked up and is absent from one that was never looked up.
func TestEvidenceMarksUnresolvedPaths(t *testing.T) {
	const (
		hostNetwork = "spec.template.spec.hostNetwork"
		missing     = "spec.template.spec.hostPID"
		marked      = missing + " (current: " + unresolvedValue + ")"
	)
	resource := deleteValuesDeployment()
	review := func(path string) armotypes.PosturePaths { return armotypes.PosturePaths{ReviewPath: path} }

	t.Run("a delete path", func(t *testing.T) {
		assert.Equal(t, []string{marked}, evidencePathsWithCurrentValues(deletePathControl(missing), resource, false))
	})

	t.Run("a review path", func(t *testing.T) {
		got := evidencePathsWithCurrentValues(shapeControl(review(missing)), resource, false)
		assert.Equal(t, []string{marked}, got)
	})

	t.Run("with --show-secrets", func(t *testing.T) {
		assert.Equal(t, []string{marked}, evidencePathsWithCurrentValues(deletePathControl(missing), resource, true))
		assert.Equal(t, []string{marked}, evidencePathsWithCurrentValues(shapeControl(review(missing)), resource, true))
	})

	t.Run("a malformed path resolves nothing", func(t *testing.T) {
		const malformed = "spec.template.spec.containers["
		got := evidencePathsWithCurrentValues(deletePathControl(malformed), resource, false)
		assert.Equal(t, []string{malformed + " (current: " + unresolvedValue + ")"}, got)
	})

	t.Run("a path that resolves is not marked", func(t *testing.T) {
		got := evidencePathsWithCurrentValues(deletePathControl(hostNetwork), resource, false)
		assert.Equal(t, []string{hostNetwork + " (current: true)"}, got)
	})

	t.Run("a fix path is left as the rule wrote it", func(t *testing.T) {
		// A fix path names a field to add, so it is expected to be absent.
		control := shapeControl(armotypes.PosturePaths{FixPath: armotypes.FixPath{Path: missing, Value: "false"}})
		got := evidencePathsWithCurrentValues(control, resource, false)
		assert.Equal(t, []string{missing + "=false"}, got)
	})
}

// The other outputs that share these functions must be exactly what they were:
// the marker is a terminal --show-evidence change.
func TestUnresolvedMarkerStaysInTheTerminalView(t *testing.T) {
	const missing = "spec.template.spec.hostPID"
	resource := deleteValuesDeployment()
	review := armotypes.PosturePaths{ReviewPath: missing}

	t.Run("the exported function used by HTML, SARIF, GitLab SAST and GitHub Actions", func(t *testing.T) {
		got := AssistedRemediationPathsWithCurrentValuesFiltered(shapeControl(review), resource, false)
		assert.Equal(t, []string{missing}, got)
	})

	t.Run("the review-path variants", func(t *testing.T) {
		assert.Equal(t, []string{missing}, reviewPathsWithCurrentValuesRedacted(shapeControl(review), resource))
		assert.Equal(t, []string{missing}, reviewPathsWithCurrentValuesUnredacted(shapeControl(review), resource))
	})
}
