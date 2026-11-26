package printer

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/require"
)

const rbacSubjectManifest = `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: wild, namespace: demo}
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: wild, namespace: demo}
subjects:
- {kind: ServiceAccount, name: ci, namespace: demo}
roleRef: {kind: Role, name: wild, apiGroup: rbac.authorization.k8s.io}
`

// The subject entry in the RoleBinding.
const rbacSubjectLine = 13

func rbacRole(name, path string) *localworkload.LocalWorkload {
	role := localworkload.NewLocalWorkload(map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "Role",
		"metadata":   map[string]any{"name": name, "namespace": "demo"},
		"rules": []any{map[string]any{
			"apiGroups": []any{"*"}, "resources": []any{"*"}, "verbs": []any{"*"},
		}},
	})
	role.SetPath(path)
	return role
}

func rbacBinding(name, role, path string) *localworkload.LocalWorkload {
	binding := localworkload.NewLocalWorkload(map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "RoleBinding",
		"metadata":   map[string]any{"name": name, "namespace": "demo"},
		"subjects": []any{map[string]any{
			"kind": "ServiceAccount", "name": "ci", "namespace": "demo",
		}},
		"roleRef": map[string]any{"kind": "Role", "name": role, "apiGroup": "rbac.authorization.k8s.io"},
	})
	binding.SetPath(path)
	return binding
}

// rbacSubjectSession is a file scan of rbac.yaml where an RBAC control fails on
// every subject. Subjects are built the way a scan builds them, from a binding and
// its role, so they have no source of their own.
func rbacSubjectSession(t *testing.T, manifest string, objects ...*localworkload.LocalWorkload) *cautils.OPASessionObj {
	t.Helper()
	t.Setenv("GITHUB_STEP_SUMMARY", "")

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "rbac.yaml"), []byte(manifest), 0600))
	source := reporthandling.Source{Path: dir, RelativePath: "rbac.yaml", FileType: reporthandling.SourceTypeYaml}

	const controlID = "C-0035"
	session := cautils.NewOPASessionObjMock()
	session.Metadata = &reporthandlingv2.Metadata{
		ScanMetadata: reporthandlingv2.ScanMetadata{ScanningTarget: reporthandlingv2.Directory},
		ContextMetadata: reporthandlingv2.ContextMetadata{
			DirectoryContextMetadata: &reporthandlingv2.DirectoryContextMetadata{BasePath: dir},
		},
	}
	session.ResourceSource = map[string]reporthandling.Source{}
	inputs := make([]workloadinterface.IMetadata, 0, len(objects))
	for _, object := range objects {
		session.AllResources[object.GetID()] = object
		session.ResourceSource[object.GetID()] = source
		inputs = append(inputs, object)
	}

	subjects, err := reporthandling.AggregateResourcesBySubjects(inputs)
	require.NoError(t, err)
	require.NotEmpty(t, subjects)
	for _, subject := range subjects {
		session.AllResources[subject.GetID()] = subject
		session.ResourcesResult[subject.GetID()] = resourcesresults.Result{
			ResourceID: subject.GetID(),
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{{
				ControlID: controlID,
				Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
				ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{
					Name:   "rule-list-all-cluster-admins-v1",
					Status: apis.StatusFailed,
					// the paths a scan reports for a subject
					Paths: []armotypes.PosturePaths{
						{ReviewPath: "relatedObjects[1].rules[0].verbs[0]"},
						{ReviewPath: "relatedObjects[0].subjects[0]"},
						{ReviewPath: "relatedObjects[0].roleRef.name"},
					},
				}},
			}},
		}
	}
	session.Report = &reporthandlingv2.PostureReport{
		SummaryDetails: reportsummary.SummaryDetails{
			Controls: reportsummary.ControlSummaries{
				controlID: reportsummary.ControlSummary{
					ControlID:   controlID,
					Name:        "Administrative Roles",
					Description: "Attackers who have cluster admin permissions can take advantage of their privileges",
					Remediation: "Remove the binding",
					ScoreFactor: 8.0,
				},
			},
		},
	}
	return session
}

func singleRBACSubjectSession(t *testing.T) *cautils.OPASessionObj {
	return rbacSubjectSession(t, rbacSubjectManifest,
		rbacRole("wild", "rbac.yaml:0"),
		rbacBinding("wild", "wild", "rbac.yaml:1"))
}

func TestSARIFPrinter_RBACSubjectInFileScan(t *testing.T) {
	raw := renderSARIF(t, NewSARIFPrinter(false), singleRBACSubjectSession(t))
	requireValidSARIF(t, raw)
	results := parseSARIFResults(t, raw)

	require.Len(t, results, 1, "a failed RBAC subject must not be dropped from a file scan")
	require.Len(t, results[0].Locations, 1)
	location := results[0].Locations[0].PhysicalLocation
	require.Equal(t, "rbac.yaml", *location.ArtifactLocation.URI)
	require.Equal(t, rbacSubjectLine, *location.Region.StartLine)
}

func TestGitLabSASTPrinter_RBACSubjectInFileScan(t *testing.T) {
	report := gitLabReportFor(t, singleRBACSubjectSession(t))

	require.Len(t, report.Vulnerabilities, 1, "a failed RBAC subject must not be dropped from a file scan")
	require.Equal(t, "rbac.yaml", report.Vulnerabilities[0].Location.File)
	require.Equal(t, rbacSubjectLine, report.Vulnerabilities[0].Location.StartLine)
}

func TestGitLabCodeQualityPrinter_RBACSubjectInFileScan(t *testing.T) {
	issues, _ := codeQualityReportFor(t, singleRBACSubjectSession(t))

	require.Len(t, issues, 1, "a failed RBAC subject must not be dropped from a file scan")
	require.Equal(t, "rbac.yaml", issues[0].Location.Path)
	require.Equal(t, rbacSubjectLine, issues[0].Location.Lines.Begin)
}

func TestGitHubActionsPrinter_RBACSubjectInFileScan(t *testing.T) {
	output := ghOutputFor(t, singleRBACSubjectSession(t))

	require.Contains(t, output, fmt.Sprintf("::error file=rbac.yaml,line=%d,title=C-0035 Administrative Roles::", rbacSubjectLine))
}

// A live cluster scan has no files, so a subject keeps its virtual location.
func TestSARIFPrinter_RBACSubjectInClusterScan(t *testing.T) {
	session := singleRBACSubjectSession(t)
	session.Metadata = &reporthandlingv2.Metadata{
		ScanMetadata: reporthandlingv2.ScanMetadata{ScanningTarget: reporthandlingv2.Cluster},
	}
	session.ResourceSource = map[string]reporthandling.Source{}

	results := parseSARIFResults(t, renderSARIF(t, NewSARIFPrinter(false), session))

	require.Len(t, results, 1)
	require.Equal(t, "cluster/demo/serviceaccount/ci.yaml", *results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI)
}

// A subject whose binding has no file still cannot be anchored.
func TestSARIFPrinter_RBACSubjectWithoutBindingSource(t *testing.T) {
	session := singleRBACSubjectSession(t)
	session.ResourceSource = map[string]reporthandling.Source{}

	results := parseSARIFResults(t, renderSARIF(t, NewSARIFPrinter(false), session))

	require.Empty(t, results)
}

// One ServiceAccount bound twice in the same file is two findings, and GitLab
// keeps only one issue per fingerprint.
func TestGitLabCodeQualityPrinter_RBACSubjectBoundTwiceInOneFile(t *testing.T) {
	manifest := rbacSubjectManifest + `---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: second, namespace: demo}
subjects:
- {kind: ServiceAccount, name: ci, namespace: demo}
roleRef: {kind: Role, name: wild, apiGroup: rbac.authorization.k8s.io}
`
	session := rbacSubjectSession(t, manifest,
		rbacRole("wild", "rbac.yaml:0"),
		rbacBinding("wild", "wild", "rbac.yaml:1"),
		rbacBinding("second", "wild", "rbac.yaml:2"))

	issues, _ := codeQualityReportFor(t, session)

	require.Len(t, issues, 2)
	require.ElementsMatch(t, []int{rbacSubjectLine, 20}, []int{issues[0].Location.Lines.Begin, issues[1].Location.Lines.Begin})
	require.NotEqual(t, issues[0].Fingerprint, issues[1].Fingerprint)
}

// When no subject path is reported, SARIF must prefer roleRef.name over other
// binding paths regardless of report order, and fall back to kind when absent.
func TestSARIFPrinter_RBACSubjectPrefersRoleRefOverOtherBindingPaths(t *testing.T) {
	session := singleRBACSubjectSession(t)
	for id, res := range session.ResourcesResult {
		res.AssociatedControls[0].ResourceAssociatedRules[0].Paths = []armotypes.PosturePaths{
			{ReviewPath: "relatedObjects[0].metadata.name"},
			{ReviewPath: "relatedObjects[0].roleRef.name"},
		}
		session.ResourcesResult[id] = res
	}

	results := parseSARIFResults(t, renderSARIF(t, NewSARIFPrinter(false), session))

	require.Len(t, results, 1)
	require.Equal(t, 14, *results[0].Locations[0].PhysicalLocation.Region.StartLine)
}

func TestRBACSubjectPaths_PriorityOrder(t *testing.T) {
	session := singleRBACSubjectSession(t)
	var subjectID string
	for id := range session.ResourcesResult {
		subjectID = id
	}

	_, paths, ok := rbacSubjectPaths(session, subjectID, []string{
		"relatedObjects[0].metadata.name",
		"relatedObjects[0].roleRef.name",
		"relatedObjects[0].subjects[0]",
	})
	require.True(t, ok)
	require.Equal(t, []string{"subjects[0]", "roleRef.name", "metadata.name"}, paths)

	_, paths, ok = rbacSubjectPaths(session, subjectID, []string{
		"relatedObjects[0].metadata.name",
		"relatedObjects[0].roleRef.name",
	})
	require.True(t, ok)
	require.Equal(t, []string{"roleRef.name", "metadata.name"}, paths)

	_, paths, ok = rbacSubjectPaths(session, subjectID, []string{
		"relatedObjects[1].rules[0].verbs[0]",
	})
	require.True(t, ok)
	require.Equal(t, []string{"kind"}, paths)
}
