package printer

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/require"
)

// The Role is the second document, so its own document index is used.
const rbacRoleFile = `apiVersion: v1
kind: ConfigMap
metadata: {name: other, namespace: demo}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: wild, namespace: demo}
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
`

const rbacBindingFile = `apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: wild, namespace: demo}
subjects:
- {kind: ServiceAccount, name: ci, namespace: demo}
roleRef: {kind: Role, name: wild, apiGroup: rbac.authorization.k8s.io}
`

// rbacSplitFilesSession is singleRBACSubjectSession with the Role in role.yaml
// and the RoleBinding in binding.yaml.
func rbacSplitFilesSession(t *testing.T) *cautils.OPASessionObj {
	t.Helper()
	role := rbacRole("wild", "role.yaml:1")
	binding := rbacBinding("wild", "wild", "binding.yaml:0")
	session := rbacSubjectSession(t, rbacSubjectManifest, role, binding)

	dir := session.ResourceSource[role.GetID()].Path
	require.NoError(t, os.WriteFile(filepath.Join(dir, "role.yaml"), []byte(rbacRoleFile), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "binding.yaml"), []byte(rbacBindingFile), 0600))
	session.ResourceSource[role.GetID()] = reporthandling.Source{Path: dir, RelativePath: "role.yaml", FileType: reporthandling.SourceTypeYaml}
	session.ResourceSource[binding.GetID()] = reporthandling.Source{Path: dir, RelativePath: "binding.yaml", FileType: reporthandling.SourceTypeYaml}
	return session
}

// The finding is on the subject in the binding, and the Role's failed rule is
// where the permission comes from, even when it is in another file.
func TestSARIFPrinter_RBACSubjectRelatedLocations(t *testing.T) {
	raw := renderSARIF(t, NewSARIFPrinter(false), rbacSplitFilesSession(t))
	requireValidSARIF(t, raw)
	results := parseSARIFResults(t, raw)
	require.Len(t, results, 1)

	primary := results[0].Locations[0].PhysicalLocation
	require.Equal(t, "binding.yaml", *primary.ArtifactLocation.URI)
	require.Equal(t, 5, *primary.Region.StartLine)

	var related []string
	for _, location := range results[0].RelatedLocations {
		related = append(related, fmt.Sprintf("%s:%d %s", *location.PhysicalLocation.ArtifactLocation.URI, *location.PhysicalLocation.Region.StartLine, *location.Message.Text))
	}
	require.Equal(t, []string{
		"binding.yaml:6 relatedObjects[0].roleRef.name",
		"binding.yaml:5 relatedObjects[0].subjects[0]",
		"role.yaml:11 relatedObjects[1].rules[0].verbs[0]",
	}, related)
}

// Some rules report no paths at all (C-0053). The finding still belongs on the
// binding, not on line 1 of the file.
func TestSARIFPrinter_RBACSubjectWithoutPaths(t *testing.T) {
	session := singleRBACSubjectSession(t)
	for id, result := range session.ResourcesResult {
		result.AssociatedControls[0].ResourceAssociatedRules[0].Paths = nil
		session.ResourcesResult[id] = result
	}

	results := parseSARIFResults(t, renderSARIF(t, NewSARIFPrinter(false), session))

	require.Len(t, results, 1)
	require.Equal(t, 10, *results[0].Locations[0].PhysicalLocation.Region.StartLine, "the binding's kind line")
}

// A rule may list the roleRef before the subject. The finding still belongs on
// the subject's line.
func TestSARIFPrinter_RBACSubjectLineWhenRoleRefComesFirst(t *testing.T) {
	session := singleRBACSubjectSession(t)
	for id, result := range session.ResourcesResult {
		result.AssociatedControls[0].ResourceAssociatedRules[0].Paths = []armotypes.PosturePaths{
			{ReviewPath: "relatedObjects[0].roleRef.name"},
			{ReviewPath: "relatedObjects[0].subjects[0]"},
		}
		session.ResourcesResult[id] = result
	}

	results := parseSARIFResults(t, renderSARIF(t, NewSARIFPrinter(false), session))

	require.Len(t, results, 1)
	require.Equal(t, rbacSubjectLine, *results[0].Locations[0].PhysicalLocation.Region.StartLine)
}
