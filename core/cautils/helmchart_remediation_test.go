// This file is an external test package on purpose: fixhandler imports
// cautils, so the remediation side of the ":<index>" suffix contract can only
// be exercised from outside cautils itself.
package cautils_test

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/fixhandler"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// helmWorkloadPath renders the layout fixture chart and returns the path
// GetWorkloads* assigned to the named workload of one template.
func helmWorkloadPath(t *testing.T, template, name string) (string, string) {
	t.Helper()

	wd, err := os.Getwd()
	require.NoError(t, err)
	chartPath := filepath.Join(wd, "testdata", "helm_chart_layout", "mychart")

	chart, err := cautils.NewHelmChart(chartPath)
	require.NoError(t, err)

	fileToWorkloads, errs := chart.GetWorkloadsWithDefaultValues()
	require.Empty(t, errs)

	absPath := filepath.Join(chartPath, "templates", template)
	for _, wl := range fileToWorkloads[absPath] {
		if wl.GetName() == name {
			return absPath, wl.(*localworkload.LocalWorkload).GetPath()
		}
	}
	t.Fatalf("no workload named %q in %s", name, template)
	return "", ""
}

// docIndexOf reads the ":<index>" suffix the scanner assigned, the same way
// sarifprinter.getDocIndex does before handing it to remediation.
func docIndexOf(t *testing.T, absPath, scannerPath string) (int, bool) {
	t.Helper()
	if !strings.HasPrefix(scannerPath, absPath+":") {
		return 0, false
	}
	index, err := strconv.Atoi(strings.TrimPrefix(scannerPath, absPath+":"))
	require.NoError(t, err)
	return index, true
}

// TestHelmDocumentIndex_RemediationEditsOnlyTheIntendedResource is the
// regression matthyx's third review asked for. The ":<index>" suffix
// GetWorkloads* writes is consumed twice with different numbering: line
// resolution reads it as a raw YAML document index, while SARIF remediation
// turns it into "select(di==n)" for fixhandler.YAMLTreeEditor, which resolves
// n against the compacted list of workload-bearing documents. An index that
// is only right for the first consumer silently rewrites a different
// resource.
//
// This drives the remediation half end to end on a real rendered chart: take
// the index the scanner actually assigned to the middle ConfigMap, build the
// same yq expression collectFixes would, apply it with the same editor, and
// require that the other two documents come out byte-identical.
func TestHelmDocumentIndex_RemediationEditsOnlyTheIntendedResource(t *testing.T) {
	absPath, scannerPath := helmWorkloadPath(t, "aligned-multidoc.yaml", "mychart-aligned-second")

	index, ok := docIndexOf(t, absPath, scannerPath)
	require.True(t, ok, "an all-plain-documents template should still carry an index")

	source, err := os.ReadFile(absPath)
	require.NoError(t, err)

	expression := fixhandler.FixPathToValidYamlExpression("metadata.labels.marker", "patched", index)
	require.NotEmpty(t, expression)

	fixed, err := (fixhandler.YAMLTreeEditor{}).Apply(context.Background(), string(source), expression)
	require.NoError(t, err)

	assert.Equal(t, strings.Replace(string(source), "marker: second", "marker: patched", 1), fixed,
		"only the ConfigMap the index names may be rewritten")
	assert.Contains(t, fixed, "marker: first", "the preceding document must be untouched")
	assert.Contains(t, fixed, "marker: third", "the following document must be untouched")
}

// TestHelmDocumentIndex_UnalignedSourcesCarryNoRemediationIndex is the other
// half: every shape where the raw document index and the workload ordinal
// disagree must arrive at remediation with no index at all, so collectFixes
// returns early instead of selecting a document by a number that means
// something else there. Before this revision the skipped-document case handed
// remediation a raw index that named the wrong ConfigMap, and an index one
// past the end of the compacted list for the last one.
func TestHelmDocumentIndex_UnalignedSourcesCarryNoRemediationIndex(t *testing.T) {
	for _, tc := range []struct {
		template string
		name     string
	}{
		{"skipped-document.yaml", "mychart-static-a"},
		{"skipped-document.yaml", "mychart-static-b"},
		{"singleton-list.yaml", "mychart-singleton-list-item"},
		{"singleton-podlist.yaml", "mychart-singleton-podlist-item"},
		{"list-envelope.yaml", "mychart-list-item-a"},
	} {
		absPath, scannerPath := helmWorkloadPath(t, tc.template, tc.name)

		_, ok := docIndexOf(t, absPath, scannerPath)
		assert.Falsef(t, ok, "%s/%s must reach remediation unindexed", tc.template, tc.name)
	}
}
