package mcpserver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const privilegedFixPath = "spec.template.spec.containers[0].securityContext.privileged"

// remediationClusterResource builds a resource the way a live-cluster scan
// records one: a plain Kubernetes object with no file path. An empty namespace
// is left out of the metadata entirely, as it is for a cluster-scoped object.
func remediationClusterResource(kind, name, namespace string) *reporthandling.Resource {
	meta := map[string]any{"name": name}
	if namespace != "" {
		meta["namespace"] = namespace
	}
	return &reporthandling.Resource{Object: map[string]any{
		"apiVersion": "apps/v1",
		"kind":       kind,
		"metadata":   meta,
		"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
			"containers": []any{map[string]any{
				"name":            name,
				"image":           "nginx",
				"securityContext": map[string]any{"privileged": true},
			}},
		}}},
	}}
}

// remediationClusterResult is a result as a cluster scan records it: the
// resource is in the report's resources list, not embedded in the result.
func remediationClusterResult(res *reporthandling.Resource, controls ...resourcesresults.ResourceAssociatedControl) resourcesresults.Result {
	return resourcesresults.Result{ResourceID: res.GetID(), AssociatedControls: controls}
}

func remediationClusterReport(results []resourcesresults.Result, resources ...*reporthandling.Resource) *reporthandlingv2.PostureReport {
	report := &reporthandlingv2.PostureReport{
		Metadata: reporthandlingv2.Metadata{
			ScanMetadata: reporthandlingv2.ScanMetadata{ScanningTarget: reporthandlingv2.Cluster},
			ContextMetadata: reporthandlingv2.ContextMetadata{
				ClusterContextMetadata: &reporthandlingv2.ClusterMetadata{ContextName: "kind-test"},
			},
		},
		Results: results,
	}
	for _, r := range resources {
		report.Resources = append(report.Resources, *r)
	}
	return report
}

// writeRemediationReport serialises a report the way `kubescape scan --format
// json` does, with an optional top-level scanCoverage, and returns its path.
func writeRemediationReport(t *testing.T, dir string, report *reporthandlingv2.PostureReport, coverage *cautils.ScanCoverage) string {
	t.Helper()
	doc := struct {
		*reporthandlingv2.PostureReport
		ScanCoverage *cautils.ScanCoverage `json:"scanCoverage,omitempty"`
	}{PostureReport: report, ScanCoverage: coverage}
	raw, err := json.Marshal(&doc)
	require.NoError(t, err)
	path := filepath.Join(dir, "report.json")
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	return path
}

// forbidScan makes a test fail if a report-path call reaches the scan seam: an
// existing report must never trigger a scan.
func forbidScan(t *testing.T) {
	t.Helper()
	orig := iacScanReportFn
	t.Cleanup(func() { iacScanReportFn = orig })
	iacScanReportFn = func(*KubescapeMcpserver, context.Context, string, []string) (*iacScanOutcome, error) {
		t.Fatal("report_path must not run a scan")
		return nil, nil
	}
}

func callReport(t *testing.T, args map[string]any) remediationResponse {
	t.Helper()
	result := callApplyRemediation(t, &KubescapeMcpserver{}, args)
	require.False(t, result.IsError, "unexpected error: %s", toolResultText(t, result))
	var resp remediationResponse
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &resp))
	return resp
}

func callReportError(t *testing.T, args map[string]any) string {
	t.Helper()
	result := callApplyRemediation(t, &KubescapeMcpserver{}, args)
	require.True(t, result.IsError, "expected an error, got: %s", toolResultText(t, result))
	return toolResultText(t, result)
}

func itemFor(t *testing.T, resp remediationResponse, resourceID, controlID string) remediationItem {
	t.Helper()
	for _, item := range resp.Items {
		if item.ResourceID == resourceID && item.Control.ID == controlID {
			return item
		}
	}
	t.Fatalf("no item for %q / %s in %+v", resourceID, controlID, resp.Items)
	return remediationItem{}
}

// --- cluster reports -------------------------------------------------------

func TestApplyRemediation_ClusterReportRendersManifestsSeparately(t *testing.T) {
	forbidScan(t)
	res := remediationClusterResource("Deployment", "nginx", "default")
	report := remediationClusterReport([]resourcesresults.Result{
		remediationClusterResult(res,
			remediationFailedControl("C-0057", "Privileged container", remediationFailedRuleWithFix(privilegedFixPath, "false")),
			remediationFailedControl("C-0041", "HostNetwork access", remediationFailedRuleNoFix()),
		),
	}, res)
	path := writeRemediationReport(t, t.TempDir(), report, &cautils.ScanCoverage{
		Degraded: true, EvaluatedControls: 20, TotalControls: 22,
		NotEvaluatedControls: []cautils.NotEvaluatedControl{{ControlID: "C-0069"}},
		FailedGVRPulls:       []cautils.FailedGVRPull{{GVR: "a/v1/B"}},
		SilentFailedGVRCount: 3,
		UnexaminedKinds:      []cautils.UnexaminedKind{{Kind: "Lease"}, {Kind: "Event"}},
	})

	resp := callReport(t, map[string]any{"report_path": path, "control_ids": "C-0057,C-0041"})

	assert.Empty(t, resp.Files, "a cluster resource has no file")
	require.Len(t, resp.RenderedManifests, 1)
	assert.Equal(t, res.GetID(), resp.RenderedManifests[0].ResourceID)
	assert.Contains(t, resp.RenderedManifests[0].Manifest, "privileged: false")
	assert.Equal(t, 1, resp.FixedControlInstances)

	fixed := itemFor(t, resp, res.GetID(), "C-0057")
	assert.Equal(t, classPatchAvailable, fixed.Classification)
	assert.Empty(t, fixed.FilePath)
	require.NotNil(t, fixed.Resource)
	assert.Equal(t, "Deployment", fixed.Resource.Kind)
	assert.Equal(t, "nginx", fixed.Resource.Name)
	assert.Equal(t, "default", fixed.Resource.Namespace)
	require.Len(t, fixed.Evidence, 1)
	assert.Equal(t, privilegedFixPath, fixed.Evidence[0].Paths[0].FixPath)
	assert.Equal(t, "false", fixed.Evidence[0].Paths[0].FixValue)

	manual := itemFor(t, resp, res.GetID(), "C-0041")
	assert.Equal(t, classManual, manual.Classification)
	assert.Equal(t, "no auto-fix available for this control", manual.Reason)
	require.Len(t, resp.UnfixedControls, 1)
	assert.Equal(t, manual.Reason, resp.UnfixedControls[0].Reason, "the item carries the fixer's reason verbatim")

	require.NotNil(t, resp.Report)
	assert.Equal(t, "cluster", resp.Report.Kind)
	assert.True(t, resp.Report.CoverageAvailable)
	assert.True(t, resp.Degraded)
	assert.True(t, resp.Report.Degraded)
	assert.Equal(t, 20, resp.Report.EvaluatedControls)
	assert.Equal(t, 22, resp.Report.TotalControls)
	assert.Equal(t, []string{"C-0069"}, resp.Report.NotEvaluatedControlIDs)
	assert.Equal(t, 1, resp.Report.FailedGVRPulls)
	assert.Equal(t, 3, resp.Report.SilentFailedGVRCount)
	assert.Equal(t, 2, resp.Report.UnexaminedKinds)
}

func TestApplyRemediation_ClusterReportSkipsAreManualWithFixerReason(t *testing.T) {
	forbidScan(t)

	envBearing := remediationClusterResource("Deployment", "with-env", "default")
	containers := envBearing.Object.(map[string]any)["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)
	containers[0].(map[string]any)["env"] = []any{map[string]any{"name": "TOKEN", "value": "XXXXXX"}}

	owned := remediationClusterResource("Deployment", "owned", "default")
	owned.Object.(map[string]any)["metadata"].(map[string]any)["ownerReferences"] = []any{map[string]any{"kind": "ReplicaSet", "name": "rs"}}

	secret := &reporthandling.Resource{Object: map[string]any{
		"apiVersion": "v1", "kind": "Secret",
		"metadata": map[string]any{"name": "creds", "namespace": "default"},
		"data":     map[string]any{"k": "XXXXXX"},
	}}

	// Every control below carries a fixPath. None of them is fixable, which is
	// the point: a fixPath alone does not make a control fixable.
	withFix := func(res *reporthandling.Resource) resourcesresults.Result {
		return remediationClusterResult(res,
			remediationFailedControl("C-0057", "Privileged container", remediationFailedRuleWithFix(privilegedFixPath, "false")))
	}
	report := remediationClusterReport([]resourcesresults.Result{withFix(envBearing), withFix(owned), withFix(secret)}, envBearing, owned, secret)
	path := writeRemediationReport(t, t.TempDir(), report, nil)

	resp := callReport(t, map[string]any{"report_path": path, "control_ids": []any{"C-0057"}})

	assert.Empty(t, resp.RenderedManifests)
	assert.Equal(t, 0, resp.FixedControlInstances)
	require.Len(t, resp.Items, 3)
	for _, item := range resp.Items {
		assert.Equal(t, classManual, item.Classification, "%s", item.ResourceID)
		assert.NotEmpty(t, item.Reason)
	}
	assert.Contains(t, itemFor(t, resp, envBearing.GetID(), "C-0057").Reason, "redact container environment variables")
	assert.Contains(t, itemFor(t, resp, owned.GetID(), "C-0057").Reason, "managed by another resource")
	assert.Contains(t, itemFor(t, resp, secret.GetID(), "C-0057").Reason, "redact this resource's data")
	assert.Contains(t, resp.Warnings[0], "no scanCoverage", "a report without coverage must say completeness is unknown")
	require.NotNil(t, resp.Report)
	assert.False(t, resp.Report.CoverageAvailable)
}

func TestApplyRemediation_ClusterReportCompositeRBACIDIsOpaque(t *testing.T) {
	forbidScan(t)
	vector := &reporthandling.Resource{Object: map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "RoleBinding",
		"name":       "binding",
		"relatedObjects": []any{
			map[string]any{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": map[string]any{"name": "sa"}},
		},
	}}
	const composite = "/dev/ServiceAccount/sa/rbac.authorization.k8s.io/v1//ClusterRole/sa/rbac.authorization.k8s.io/v1//ClusterRoleBinding/sa"
	vector.ResourceID = composite

	report := remediationClusterReport([]resourcesresults.Result{{
		ResourceID: composite,
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{
			remediationFailedControl("C-0053", "Access container service account", remediationFailedRuleNoFix()),
		},
	}}, vector)
	path := writeRemediationReport(t, t.TempDir(), report, nil)

	resp := callReport(t, map[string]any{"report_path": path, "control_ids": "C-0053"})

	require.Len(t, resp.Items, 1)
	assert.Equal(t, composite, resp.Items[0].ResourceID, "the composite ID is passed through, not parsed")
	assert.Equal(t, classManual, resp.Items[0].Classification)
}

func TestApplyRemediation_MissingNamespaceStaysEmpty(t *testing.T) {
	forbidScan(t)
	res := remediationClusterResource("Deployment", "cluster-scoped-ish", "")
	report := remediationClusterReport([]resourcesresults.Result{
		remediationClusterResult(res, remediationFailedControl("C-0057", "Privileged container", remediationFailedRuleWithFix(privilegedFixPath, "false"))),
	}, res)
	path := writeRemediationReport(t, t.TempDir(), report, nil)

	resp := callReport(t, map[string]any{"report_path": path, "control_ids": "C-0057"})

	require.Len(t, resp.Items, 1)
	require.NotNil(t, resp.Items[0].Resource)
	assert.Equal(t, "", resp.Items[0].Resource.Namespace)

	// The empty namespace is serialised, not dropped.
	result := callApplyRemediation(t, &KubescapeMcpserver{}, map[string]any{"report_path": path, "control_ids": "C-0057"})
	assert.Contains(t, toolResultText(t, result), `"namespace": ""`)
}

func TestApplyRemediation_ReportItemsAreIndependentOfResultOrder(t *testing.T) {
	forbidScan(t)
	a := remediationClusterResource("Deployment", "a", "default")
	b := remediationClusterResource("Deployment", "b", "default")
	c := remediationClusterResource("Deployment", "c", "other")
	result := func(res *reporthandling.Resource) resourcesresults.Result {
		return remediationClusterResult(res,
			remediationFailedControl("C-0099", "Z", remediationFailedRuleNoFix()),
			remediationFailedControl("C-0057", "Privileged container", remediationFailedRuleWithFix(privilegedFixPath, "false")),
		)
	}
	dir := t.TempDir()
	forward := writeRemediationReport(t, dir, remediationClusterReport([]resourcesresults.Result{result(a), result(b), result(c)}, a, b, c), nil)
	first := callApplyRemediation(t, &KubescapeMcpserver{}, map[string]any{"report_path": forward, "control_ids": "C-0057,C-0099"})

	reversed := writeRemediationReport(t, t.TempDir(), remediationClusterReport([]resourcesresults.Result{result(c), result(b), result(a)}, c, b, a), nil)
	second := callApplyRemediation(t, &KubescapeMcpserver{}, map[string]any{"report_path": reversed, "control_ids": "C-0057,C-0099"})

	assert.Equal(t, toolResultText(t, first), toolResultText(t, second))
	var resp remediationResponse
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, first)), &resp))
	require.Len(t, resp.Items, 6)
	for i := 1; i < len(resp.Items); i++ {
		prev, cur := resp.Items[i-1], resp.Items[i]
		assert.LessOrEqual(t, prev.ResourceID+"\x00"+prev.Control.ID, cur.ResourceID+"\x00"+cur.Control.ID)
	}
}

func TestApplyRemediation_RequestedControlNotEvaluatedIsAnItem(t *testing.T) {
	forbidScan(t)
	res := remediationClusterResource("Deployment", "nginx", "default")
	report := remediationClusterReport([]resourcesresults.Result{
		remediationClusterResult(res, remediationFailedControl("C-0057", "Privileged container", remediationFailedRuleWithFix(privilegedFixPath, "false"))),
	}, res)
	path := writeRemediationReport(t, t.TempDir(), report, &cautils.ScanCoverage{
		Degraded:             true,
		NotEvaluatedControls: []cautils.NotEvaluatedControl{{ControlID: "C-0069", MissingGVRs: []string{"hostdata/v1/KubeletInfo"}}},
	})

	resp := callReport(t, map[string]any{"report_path": path, "control_ids": "C-0057,C-0069"})

	assert.True(t, resp.Degraded)
	item := itemFor(t, resp, "", "C-0069")
	assert.Equal(t, classNotEvaluated, item.Classification)
	assert.Contains(t, item.Reason, "hostdata/v1/KubeletInfo")
	assert.Nil(t, item.Resource)
	assert.NotNil(t, item.Evidence, "evidence is [] not null")

	var found bool
	for _, u := range resp.UnfixedControls {
		found = found || u.ControlID == "C-0069"
	}
	assert.True(t, found, "unfixed_controls keeps carrying the unevaluated control")
}

func TestApplyRemediation_ReportOnlyReportsRequestedControls(t *testing.T) {
	forbidScan(t)
	res := remediationClusterResource("Deployment", "nginx", "default")
	report := remediationClusterReport([]resourcesresults.Result{
		remediationClusterResult(res,
			remediationFailedControl("C-0057", "Privileged container", remediationFailedRuleWithFix(privilegedFixPath, "false")),
			remediationFailedControl("C-0041", "HostNetwork access", remediationFailedRuleNoFix()),
		),
	}, res)
	path := writeRemediationReport(t, t.TempDir(), report, nil)

	resp := callReport(t, map[string]any{"report_path": path, "control_ids": "c-0057"})

	require.Len(t, resp.Items, 1)
	assert.Equal(t, "C-0057", resp.Items[0].Control.ID)
	assert.Empty(t, resp.UnfixedControls)
}

// --- file-backed reports and path security --------------------------------

func writeFileReportFixture(t *testing.T) (dir, reportPath string, res *reporthandling.Resource) {
	t.Helper()
	dir = t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "deploy.yaml"), []byte(deploymentNoSecurityContext), 0o600))
	res = remediationResource(dir, "deploy.yaml", "Deployment", "demo", 0)
	report := remediationReport(dir, res,
		remediationFailedControl("C-0057", "Privileged container",
			remediationFailedRuleWithFix("spec.containers[0].securityContext.privileged", "false")),
	)
	reportPath = writeRemediationReport(t, t.TempDir(), report, nil)
	return dir, reportPath, res
}

func TestApplyRemediation_FileReportRequiresBasePath(t *testing.T) {
	forbidScan(t)
	_, reportPath, _ := writeFileReportFixture(t)

	msg := callReportError(t, map[string]any{"report_path": reportPath, "control_ids": "C-0057"})

	assert.Contains(t, msg, "INVALID_ARGUMENT")
	assert.Contains(t, msg, "base_path is required")
}

func TestApplyRemediation_FileReportWithBasePathUsesFilesNotRenderedManifests(t *testing.T) {
	forbidScan(t)
	dir, reportPath, res := writeFileReportFixture(t)
	before, err := os.ReadFile(filepath.Join(dir, "deploy.yaml"))
	require.NoError(t, err)

	resp := callReport(t, map[string]any{"report_path": reportPath, "base_path": dir, "control_ids": "C-0057"})

	require.Len(t, resp.Files, 1)
	assert.Contains(t, resp.Files[0].PatchedYAML, "privileged: false")
	assert.Empty(t, resp.RenderedManifests)
	item := itemFor(t, resp, res.GetID(), "C-0057")
	assert.Equal(t, classPatchAvailable, item.Classification)
	assert.Equal(t, resp.Files[0].FilePath, item.FilePath)
	assert.Equal(t, "directory", resp.Report.Kind)

	after, err := os.ReadFile(filepath.Join(dir, "deploy.yaml"))
	require.NoError(t, err)
	assert.Equal(t, string(before), string(after), "planning must not write the manifest")
}

func TestApplyRemediation_FileReportOutsideBasePathIsRejected(t *testing.T) {
	forbidScan(t)
	_, reportPath, _ := writeFileReportFixture(t)
	elsewhere := t.TempDir()

	msg := callReportError(t, map[string]any{"report_path": reportPath, "base_path": elsewhere, "control_ids": "C-0057"})

	assert.Contains(t, msg, "INVALID_ARGUMENT")
	assert.Contains(t, msg, "outside --base-path")
}

func TestApplyRemediation_FileReportTraversalInBasePathIsRejected(t *testing.T) {
	forbidScan(t)
	dir, reportPath, _ := writeFileReportFixture(t)
	// A base_path that spells a different directory with ".." must be resolved
	// before it is compared, and so does not widen what is permitted.
	sibling := filepath.Join(dir, "..", filepath.Base(t.TempDir()))
	require.NoError(t, os.MkdirAll(sibling, 0o750))

	msg := callReportError(t, map[string]any{"report_path": reportPath, "base_path": sibling, "control_ids": "C-0057"})

	assert.Contains(t, msg, "INVALID_ARGUMENT")
}

func TestApplyRemediation_FileReportSymlinkedBasePathResolvesBeforeComparing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	forbidScan(t)
	dir, reportPath, _ := writeFileReportFixture(t)

	// A symlink to the scanned directory is a legitimate base_path ...
	link := filepath.Join(t.TempDir(), "link")
	require.NoError(t, os.Symlink(dir, link))
	resp := callReport(t, map[string]any{"report_path": reportPath, "base_path": link, "control_ids": "C-0057"})
	assert.Len(t, resp.Items, 1)

	// ... and a symlink to somewhere else grants nothing, however it is named.
	other := t.TempDir()
	escape := filepath.Join(t.TempDir(), "escape")
	require.NoError(t, os.Symlink(other, escape))
	msg := callReportError(t, map[string]any{"report_path": reportPath, "base_path": escape, "control_ids": "C-0057"})
	assert.Contains(t, msg, "INVALID_ARGUMENT")
}

func TestApplyRemediation_DuplicateNamespaceKindNameKeepDistinctIDs(t *testing.T) {
	forbidScan(t)
	dir := t.TempDir()
	for _, f := range []string{"a.yaml", "b.yaml"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, f), []byte(deploymentNoSecurityContext), 0o600))
	}
	a := remediationResource(dir, "a.yaml", "Deployment", "demo", 0)
	b := remediationResource(dir, "b.yaml", "Deployment", "demo", 0)
	require.NotEqual(t, a.GetID(), b.GetID())

	report := remediationReport(dir, a, remediationFailedControl("C-0057", "Privileged container",
		remediationFailedRuleWithFix("spec.containers[0].securityContext.privileged", "false")))
	report.Results = append(report.Results, resourcesresults.Result{
		ResourceID:  b.GetID(),
		RawResource: b,
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{
			remediationFailedControl("C-0057", "Privileged container",
				remediationFailedRuleWithFix("spec.containers[0].securityContext.privileged", "false")),
		},
	})
	report.Resources = append(report.Resources, *b)
	reportPath := writeRemediationReport(t, t.TempDir(), report, nil)

	resp := callReport(t, map[string]any{"report_path": reportPath, "base_path": dir, "control_ids": "C-0057"})

	require.Len(t, resp.Items, 2, "same namespace/kind/name must not collapse")
	assert.NotEqual(t, resp.Items[0].ResourceID, resp.Items[1].ResourceID)
	assert.Equal(t, resp.Items[0].Resource.Name, resp.Items[1].Resource.Name)
	assert.Equal(t, 2, resp.FixedControlInstances)
	assert.Len(t, resp.Files, 2)
}

func TestApplyRemediation_ReportPathInputErrors(t *testing.T) {
	forbidScan(t)
	dir := t.TempDir()

	notJSON := filepath.Join(dir, "garbage.json")
	require.NoError(t, os.WriteFile(notJSON, []byte("not json at all"), 0o600))
	notAReport := filepath.Join(dir, "other.json")
	require.NoError(t, os.WriteFile(notAReport, []byte(`{"hello":"world"}`), 0o600))
	oversized := filepath.Join(dir, "big.json")
	f, err := os.Create(oversized)
	require.NoError(t, err)
	require.NoError(t, f.Truncate(maxRemediationReportLen+1)) // sparse
	require.NoError(t, f.Close())

	cases := map[string]string{
		"missing file": filepath.Join(dir, "absent.json"),
		"directory":    dir,
		"malformed":    notJSON,
		"not a report": notAReport,
		"oversized":    oversized,
	}
	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			msg := callReportError(t, map[string]any{"report_path": path, "control_ids": "C-0057"})
			assert.Contains(t, msg, "INVALID_ARGUMENT")
			assert.Contains(t, msg, "report_path")
		})
	}
	assert.Equal(t, 0, countTempReports(t), "no staged report may be left behind")
}

func TestApplyRemediation_ArgumentCombinations(t *testing.T) {
	forbidScan(t)
	ksServer := &KubescapeMcpserver{}

	cases := map[string]struct {
		args map[string]any
		want string
	}{
		"both path and report_path": {
			map[string]any{"path": "/x", "report_path": "/y", "control_ids": "C-0013"},
			"mutually exclusive",
		},
		"neither": {
			map[string]any{"control_ids": "C-0013"},
			"path argument is required",
		},
		"base_path with path": {
			map[string]any{"path": "/x", "base_path": "/y", "control_ids": "C-0013"},
			"base_path applies only with report_path",
		},
		"report_path without control_ids": {
			map[string]any{"report_path": "/y"},
			"control_ids",
		},
		"non-string report_path": {
			map[string]any{"report_path": 7, "control_ids": "C-0013"},
			"report_path argument must be a string",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			result := callApplyRemediation(t, ksServer, tc.args)
			assert.True(t, result.IsError)
			text := toolResultText(t, result)
			assert.Contains(t, text, "INVALID_ARGUMENT")
			assert.Contains(t, text, tc.want)
		})
	}
}

func TestRemediationKey_ReportPathAndBasePathAreDistinguishing(t *testing.T) {
	ids := []string{"C-0013"}
	base := remediationKey("", "/r.json", "/b", ids)

	assert.NotEqual(t, base, remediationKey("", "/other.json", "/b", ids))
	assert.NotEqual(t, base, remediationKey("", "/r.json", "/other", ids))
	assert.NotEqual(t, base, remediationKey("", "/r.json", "", ids))
	assert.NotEqual(t, base, remediationKey("/r.json", "", "/b", ids), "path and report_path must not alias")
	assert.Equal(t, base, remediationKey("", "/r.json", "/b", []string{"C-0013"}))
}

// --- backward compatibility ------------------------------------------------

func TestApplyRemediation_PathModeKeepsLegacyFieldsAndAddsItems(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "deploy.yaml")
	require.NoError(t, os.WriteFile(manifest, []byte(deploymentNoSecurityContext), 0o600))
	res := remediationResource(dir, "deploy.yaml", "Deployment", "demo", 0)
	stubScanReport(t, remediationReport(dir, res,
		remediationFailedControl("C-0057", "Privileged container",
			remediationFailedRuleWithFix("spec.containers[0].securityContext.privileged", "false")),
		remediationFailedControl("C-0041", "HostNetwork access", remediationFailedRuleNoFix()),
	))

	result := callApplyRemediation(t, &KubescapeMcpserver{}, map[string]any{"path": dir, "control_ids": "C-0057,C-0041"})
	require.False(t, result.IsError, toolResultText(t, result))

	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &raw))
	for _, legacy := range []string{"files", "fixed_control_instances", "degraded", "unfixed_controls"} {
		assert.Contains(t, raw, legacy, "legacy field %q must survive", legacy)
	}
	assert.Equal(t, "[]", strings.ReplaceAll(strings.TrimSpace(string(raw["rendered_manifests"])), " ", ""))

	var resp remediationResponse
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &resp))
	assert.Equal(t, 1, resp.FixedControlInstances)
	require.Len(t, resp.Files, 1)
	require.Len(t, resp.UnfixedControls, 1)
	require.Len(t, resp.Items, 2)
	assert.Equal(t, classPatchAvailable, itemFor(t, resp, res.GetID(), "C-0057").Classification)
	assert.Equal(t, classManual, itemFor(t, resp, res.GetID(), "C-0041").Classification)
	assert.Equal(t, resp.Files[0].FilePath, itemFor(t, resp, res.GetID(), "C-0057").FilePath)
}

func TestApplyRemediation_EmptyItemsSerialiseAsArrays(t *testing.T) {
	dir := t.TempDir()
	res := remediationResource(dir, "deploy.yaml", "Deployment", "demo", 0)
	// A report whose only control passed: nothing to remediate.
	passing := remediationFailedControl("C-0057", "Privileged container")
	passing.Status.InnerStatus = "passed"
	stubScanReport(t, remediationReport(dir, res, passing))

	result := callApplyRemediation(t, &KubescapeMcpserver{}, map[string]any{"path": dir, "control_ids": "C-0057"})
	require.False(t, result.IsError, toolResultText(t, result))

	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &raw))
	assert.JSONEq(t, `[]`, string(raw["items"]))
	assert.JSONEq(t, `[]`, string(raw["files"]))
	assert.JSONEq(t, `[]`, string(raw["rendered_manifests"]))
}
