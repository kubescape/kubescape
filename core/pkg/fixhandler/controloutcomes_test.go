package fixhandler

import (
	"context"
	"testing"

	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const privilegedPath = "spec.template.spec.containers[0].securityContext.privileged"

// outcomeKey indexes outcomes by (resource, control) for assertions.
func outcomeKey(o ControlOutcome) string { return o.ResourceID + "|" + o.ControlID }

func outcomesByKey(h *FixHandler) map[string]ControlOutcome {
	out := make(map[string]ControlOutcome)
	for _, o := range h.ControlOutcomes() {
		out[outcomeKey(o)] = o
	}
	return out
}

// assertAccounting pins the contract that ControlOutcomes is a view over the
// accounting FixedControlsCount and UnfixedControls already report.
func assertAccounting(t *testing.T, h *FixHandler) {
	t.Helper()
	fixed, unfixed := 0, 0
	for _, o := range h.ControlOutcomes() {
		if o.Fixed {
			fixed++
			assert.Empty(t, o.Reason, "a fixed control carries no reason")
		} else {
			unfixed++
		}
	}
	assert.Equal(t, h.FixedControlsCount(), fixed)
	assert.Len(t, h.UnfixedControls(), unfixed)
}

func TestControlOutcomes_ClusterFixedAndUnfixed(t *testing.T) {
	res := clusterResource("Deployment", "nginx")
	h := newClusterHandler([]resourcesresults.Result{
		clusterResultFor(res,
			failedControl("C-0057", "Privileged container", failedRuleWithFix(privilegedPath, "false")),
			failedControl("C-0041", "HostNetwork access", failedRuleNoFix()),
		),
	}, []reporthandling.Resource{*res})

	h.PrepareResourcesToFix(context.Background())

	outcomes := outcomesByKey(h)
	require.Len(t, outcomes, 2)

	fixed := outcomes[res.GetID()+"|C-0057"]
	assert.True(t, fixed.Fixed)
	assert.True(t, fixed.InMemory)
	assert.Empty(t, fixed.FilePath, "a cluster resource has no file")
	assert.Equal(t, "Privileged container", fixed.ControlName)
	assert.Equal(t, "nginx", fixed.ResourceName)
	assert.Equal(t, "Deployment", fixed.ResourceKind)

	unfixed := outcomes[res.GetID()+"|C-0041"]
	assert.False(t, unfixed.Fixed)
	assert.False(t, unfixed.Partial)
	assert.Equal(t, "no auto-fix available for this control", unfixed.Reason)
	assertAccounting(t, h)
}

func TestControlOutcomes_PartialControlKeepsFixerReason(t *testing.T) {
	res := clusterResource("Deployment", "nginx")
	h := newClusterHandler([]resourcesresults.Result{
		clusterResultFor(res,
			failedControl("C-0099", "Mixed",
				failedRuleWithFix(privilegedPath, "false"),
				failedRuleNoFix(),
			),
		),
	}, []reporthandling.Resource{*res})

	h.PrepareResourcesToFix(context.Background())

	o := outcomesByKey(h)[res.GetID()+"|C-0099"]
	assert.False(t, o.Fixed, "a control with an unaddressed rule is not fixed")
	assert.True(t, o.Partial)
	assert.Contains(t, o.Reason, "partial: ")
	assertAccounting(t, h)
}

func TestControlOutcomes_PromotedControlIsFixed(t *testing.T) {
	// C-0016's planned expression also covers the failed path C-0057 reports
	// without a fix of its own, so the fixer promotes C-0057 to fixed. The
	// outcome must follow the fixer, not the absence of a fixPath.
	res := clusterResource("Deployment", "nginx")
	h := newClusterHandler([]resourcesresults.Result{
		clusterResultFor(res,
			failedControl("C-0016", "Allow privilege escalation", failedRuleWithFix(privilegedPath, "false")),
			failedControl("C-0057", "Privileged container", failedRuleNoFixAtPath(privilegedPath)),
		),
	}, []reporthandling.Resource{*res})

	h.PrepareResourcesToFix(context.Background())

	outcomes := outcomesByKey(h)
	assert.True(t, outcomes[res.GetID()+"|C-0016"].Fixed)
	assert.True(t, outcomes[res.GetID()+"|C-0057"].Fixed, "promoted by another control's planned path")
	assertAccounting(t, h)
}

func TestControlOutcomes_FixPathAloneDoesNotDecideFixability(t *testing.T) {
	// The resource is declined for redacted environment data, so its controls
	// are unfixed even though every one carries a fixPath.
	res := clusterResource("Deployment", "nginx")
	containers := res.Object.(map[string]any)["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)
	containers[0].(map[string]any)["env"] = []any{map[string]any{"name": "A", "value": "XXXXXX"}}

	h := newClusterHandler([]resourcesresults.Result{
		clusterResultFor(res, failedControl("C-0057", "Privileged container", failedRuleWithFix(privilegedPath, "false"))),
	}, []reporthandling.Resource{*res})

	h.PrepareResourcesToFix(context.Background())

	o := outcomesByKey(h)[res.GetID()+"|C-0057"]
	assert.False(t, o.Fixed)
	assert.Contains(t, o.Reason, "redact container environment variables")
	assertAccounting(t, h)
}

func TestControlOutcomes_UserValueFollowsSkipUserValues(t *testing.T) {
	build := func(skip bool) *FixHandler {
		res := clusterResource("Deployment", "nginx")
		h := newClusterHandler([]resourcesresults.Result{
			clusterResultFor(res, failedControl("C-0270", "CPU limits",
				failedRuleWithFix("spec.template.spec.containers[0].resources.limits.cpu", UserValuePrefix+"VALUE"))),
		}, []reporthandling.Resource{*res})
		h.fixInfo.SkipUserValues = skip
		h.PrepareResourcesToFix(context.Background())
		return h
	}

	skipped := build(true).ControlOutcomes()
	require.Len(t, skipped, 1)
	assert.False(t, skipped[0].Fixed)
	assert.Contains(t, skipped[0].Reason, "user-supplied value")

	kept := build(false).ControlOutcomes()
	require.Len(t, kept, 1)
	assert.True(t, kept[0].Fixed, "without SkipUserValues the fixer plans the placeholder fix and counts the control")
}

func TestControlOutcomes_DuplicateNamespaceKindNameStayDistinct(t *testing.T) {
	// Two manifests declare default/Deployment/demo. A file scan records them
	// under different resource IDs, and the outcomes must keep both.
	dir := t.TempDir()
	writeManifest(t, dir, "a.yaml", "apiVersion: apps/v1\nkind: Deployment\n")
	writeManifest(t, dir, "b.yaml", "apiVersion: apps/v1\nkind: Deployment\n")
	a := buildResource(t, dir, "a.yaml", "Deployment", "demo", 0)
	b := buildResource(t, dir, "b.yaml", "Deployment", "demo", 0)
	require.NotEqual(t, a.GetID(), b.GetID(), "fixture must give the duplicates distinct resource IDs")
	require.Equal(t, a.GetName(), b.GetName())

	fix := failedRuleWithFix("spec.containers[0].securityContext.privileged", "false")
	h := newHandlerForResources(dir, []resourcesresults.Result{
		clusterResultFor(b, failedControl("C-0057", "Privileged container", fix)),
		clusterResultFor(a, failedControl("C-0057", "Privileged container", fix)),
	}, []reporthandling.Resource{*a, *b}, false)

	h.PrepareResourcesToFix(context.Background())

	outcomes := h.ControlOutcomes()
	require.Len(t, outcomes, 2)
	ids := []string{outcomes[0].ResourceID, outcomes[1].ResourceID}
	assert.ElementsMatch(t, []string{a.GetID(), b.GetID()}, ids)
	assert.Less(t, outcomes[0].ResourceID, outcomes[1].ResourceID)
	assertAccounting(t, h)
}

func TestControlOutcomes_OrderIgnoresResultOrder(t *testing.T) {
	a := clusterResource("Deployment", "a")
	b := clusterResource("Deployment", "b")
	resources := []reporthandling.Resource{*a, *b}
	fixable := func(r *reporthandling.Resource) resourcesresults.Result {
		return clusterResultFor(r,
			failedControl("C-0099", "Z", failedRuleNoFix()),
			failedControl("C-0057", "Privileged container", failedRuleWithFix(privilegedPath, "false")),
		)
	}

	forward := newClusterHandler([]resourcesresults.Result{fixable(a), fixable(b)}, resources)
	reverse := newClusterHandler([]resourcesresults.Result{fixable(b), fixable(a)}, resources)
	forward.PrepareResourcesToFix(context.Background())
	reverse.PrepareResourcesToFix(context.Background())

	assert.Equal(t, forward.ControlOutcomes(), reverse.ControlOutcomes())
}

func TestControlOutcomes_DeclinedResourceMovesToUnfixed(t *testing.T) {
	res := clusterResource("Deployment", "nginx")
	h := newClusterHandler([]resourcesresults.Result{
		clusterResultFor(res, failedControl("C-0057", "Privileged container", failedRuleWithFix(privilegedPath, "false"))),
	}, []reporthandling.Resource{*res})

	toFix := h.PrepareResourcesToFix(context.Background())
	require.Len(t, toFix, 1)
	h.DeclineResources(toFix)

	o := outcomesByKey(h)[res.GetID()+"|C-0057"]
	assert.False(t, o.Fixed)
	assert.Equal(t, "skipped: user declined the interactive prompt", o.Reason)
	assertAccounting(t, h)
}

func TestControlOutcomes_FileScanKeepsFilePath(t *testing.T) {
	dir := t.TempDir()
	manifest := writeManifest(t, dir, "deploy.yaml", "apiVersion: apps/v1\nkind: Deployment\n")
	res := buildResource(t, dir, "deploy.yaml", "Deployment", "demo", 0)

	h := newHandlerForResources(dir, []resourcesresults.Result{
		clusterResultFor(res, failedControl("C-0057", "Privileged container",
			failedRuleWithFix("spec.containers[0].securityContext.privileged", "false"))),
	}, []reporthandling.Resource{*res}, false)

	h.PrepareResourcesToFix(context.Background())

	outcomes := h.ControlOutcomes()
	require.Len(t, outcomes, 1)
	assert.True(t, outcomes[0].Fixed)
	assert.False(t, outcomes[0].InMemory)
	assert.Equal(t, manifest, outcomes[0].FilePath)
	assertAccounting(t, h)
}

func TestControlOutcomes_UnselectedControlsHaveNoOutcome(t *testing.T) {
	res := clusterResource("Deployment", "nginx")
	h := newClusterHandler([]resourcesresults.Result{
		clusterResultFor(res,
			failedControl("C-0057", "Privileged container", failedRuleWithFix(privilegedPath, "false")),
			failedControl("C-0041", "HostNetwork access", failedRuleNoFix()),
		),
	}, []reporthandling.Resource{*res})
	h.controls = newControlSelector([]string{"c-0057"}, nil)

	h.PrepareResourcesToFix(context.Background())

	outcomes := h.ControlOutcomes()
	require.Len(t, outcomes, 1)
	assert.Equal(t, "C-0057", outcomes[0].ControlID)
	assertAccounting(t, h)
}
