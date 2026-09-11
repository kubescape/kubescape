package fixhandler

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestControlSelector_Selects(t *testing.T) {
	tests := []struct {
		name      string
		include   []string
		skip      []string
		controlID string
		want      bool
	}{
		{name: "no filters selects everything", controlID: "C-0016", want: true},
		{name: "include matches", include: []string{"C-0016"}, controlID: "C-0016", want: true},
		{name: "include excludes everything else", include: []string{"C-0016"}, controlID: "C-0017", want: false},
		{name: "include is case-insensitive", include: []string{"c-0016"}, controlID: "C-0016", want: true},
		{name: "include tolerates surrounding space", include: []string{"  C-0016 "}, controlID: "C-0016", want: true},
		{name: "skip drops the control", skip: []string{"C-0016"}, controlID: "C-0016", want: false},
		{name: "skip leaves others alone", skip: []string{"C-0016"}, controlID: "C-0017", want: true},
		{name: "skip is case-insensitive", skip: []string{"C-0016"}, controlID: "c-0016", want: false},
		{name: "skip wins over include", include: []string{"C-0016"}, skip: []string{"C-0016"}, controlID: "C-0016", want: false},
		{name: "blank-only include behaves as no filter", include: []string{"", "   "}, controlID: "C-0016", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, newControlSelector(tt.include, tt.skip).selects(tt.controlID))
		})
	}
}

func TestPrepareResourcesToFix_HonorsControlSelection(t *testing.T) {
	dir := t.TempDir()
	manifest := writeManifest(t, dir, "deploy.yaml", "apiVersion: apps/v1\nkind: Deployment\n")
	rel, err := filepath.Rel(dir, manifest)
	assert.NoError(t, err)

	res := buildResource(t, dir, rel, "Deployment", "demo", 0)
	results := []resourcesresults.Result{
		{
			ResourceID:  res.GetID(),
			RawResource: res,
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				failedControl("C-0057", "Privileged container",
					failedRuleWithFix("spec.containers[0].securityContext.privileged", "false"),
				),
				failedControl("C-0017", "Immutable container filesystem",
					failedRuleWithFix("spec.containers[0].securityContext.readOnlyRootFilesystem", "true"),
				),
				failedControl("C-0041", "HostNetwork access", failedRuleNoFix()),
			},
		},
	}

	tests := []struct {
		name         string
		include      []string
		skip         []string
		wantFixed    int
		wantUnfixed  []string
		wantResource int
	}{
		{name: "no selection fixes both fixable controls", wantFixed: 2, wantUnfixed: []string{"C-0041"}, wantResource: 1},
		{name: "include narrows to one control", include: []string{"C-0057"}, wantFixed: 1, wantResource: 1},
		{name: "skip drops one fixable control", skip: []string{"C-0057"}, wantFixed: 1, wantUnfixed: []string{"C-0041"}, wantResource: 1},
		{name: "skipped unfixable control is not reported", skip: []string{"C-0041"}, wantFixed: 2, wantResource: 1},
		{name: "selecting nothing leaves the resource alone", include: []string{"C-9999"}, wantFixed: 0, wantResource: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHandlerForResources(dir, results, nil, false)
			h.controls = newControlSelector(tt.include, tt.skip)

			rtf := h.PrepareResourcesToFix(context.Background())

			assert.Len(t, rtf, tt.wantResource)
			assert.Equal(t, tt.wantFixed, h.FixedControlsCount())

			unfixed := make([]string, 0, len(h.UnfixedControls()))
			for _, u := range h.UnfixedControls() {
				unfixed = append(unfixed, u.ControlID)
			}
			assert.ElementsMatch(t, tt.wantUnfixed, unfixed)
		})
	}
}

func TestControlSelector_ActiveAndDescribe(t *testing.T) {
	assert.False(t, newControlSelector(nil, nil).active())
	assert.False(t, newControlSelector([]string{" "}, nil).active())
	assert.True(t, newControlSelector([]string{"C-0016"}, nil).active())

	assert.Equal(t, "--include-controls", newControlSelector([]string{"C-0016"}, nil).describe())
	assert.Equal(t, "--skip-controls", newControlSelector(nil, []string{"C-0016"}).describe())
	assert.Equal(t, "--include-controls/--skip-controls", newControlSelector([]string{"C-0016"}, []string{"C-0017"}).describe())
}

func TestControlSelectionCounts(t *testing.T) {
	dir := t.TempDir()
	manifest := writeManifest(t, dir, "deploy.yaml", "apiVersion: apps/v1\nkind: Deployment\n")
	rel, err := filepath.Rel(dir, manifest)
	assert.NoError(t, err)

	res := buildResource(t, dir, rel, "Deployment", "demo", 0)
	results := []resourcesresults.Result{
		{
			ResourceID:  res.GetID(),
			RawResource: res,
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				failedControl("C-0057", "Privileged container",
					failedRuleWithFix("spec.containers[0].securityContext.privileged", "false"),
				),
				failedControl("C-0017", "Immutable container filesystem",
					failedRuleWithFix("spec.containers[0].securityContext.readOnlyRootFilesystem", "true"),
				),
				{
					ControlID: "C-9998",
					Name:      "passed control",
					Status:    apis.StatusInfo{InnerStatus: apis.StatusPassed},
				},
			},
		},
	}

	tests := []struct {
		name         string
		include      []string
		skip         []string
		wantSelected int
	}{
		{name: "no selection keeps every failed control", wantSelected: 2},
		{name: "include keeps one", include: []string{"C-0057"}, wantSelected: 1},
		{name: "skip drops one", skip: []string{"C-0057"}, wantSelected: 1},
		{name: "unmatched include keeps nothing", include: []string{"C-9999"}, wantSelected: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHandlerForResources(dir, results, nil, false)
			h.controls = newControlSelector(tt.include, tt.skip)

			selected, total := h.controlSelectionCounts()

			assert.Equal(t, tt.wantSelected, selected)
			assert.Equal(t, 2, total, "passed controls are never counted")
		})
	}
}

// buildWorkloadResource mirrors buildResource but records a container, which
// profile drift detection needs to produce any fix at all.
func buildWorkloadResource(t *testing.T, baseDir, filename, name, container string, documentIndex int) *reporthandling.Resource {
	t.Helper()
	obj := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]any{
			"name":      name,
			"namespace": "default",
		},
		"spec": map[string]any{
			"template": map[string]any{
				"spec": map[string]any{
					"containers": []any{
						map[string]any{"name": container, "image": "nginx"},
					},
				},
			},
		},
	}
	lw := localworkload.NewLocalWorkload(obj)
	lw.SetPath(filename + ":" + itoa(documentIndex))

	return &reporthandling.Resource{
		ResourceID: lw.GetID(),
		Object:     lw.GetObject(),
		Source:     &reporthandling.Source{FileType: reporthandling.SourceTypeYaml, Path: baseDir},
	}
}

func writeContainerProfile(t *testing.T, dir, kind, name, namespace, container string) string {
	t.Helper()
	profile := map[string]any{
		"metadata": map[string]any{
			"name": "profile",
			"labels": map[string]string{
				"kubescape.io/workload-kind":           kind,
				"kubescape.io/workload-name":           name,
				"kubescape.io/workload-namespace":      namespace,
				"kubescape.io/workload-container-name": container,
			},
		},
		"spec": map[string]any{},
	}
	raw, err := json.Marshal(profile)
	require.NoError(t, err)
	path := filepath.Join(dir, "profile.json")
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	return path
}

// A control selection must not be quietly widened by --container-profile:
// drift fixes carry no control, so applying them under a selection would edit
// the manifest for controls the user excluded (review of #3707).
func TestPrepareResourcesToFix_ContainerProfileRespectsControlSelection(t *testing.T) {
	dir := t.TempDir()
	manifest := writeManifest(t, dir, "deploy.yaml", `apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
  namespace: default
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx
`)
	rel, err := filepath.Rel(dir, manifest)
	require.NoError(t, err)

	res := buildWorkloadResource(t, dir, rel, "demo", "app", 0)
	results := []resourcesresults.Result{
		{
			ResourceID:  res.GetID(),
			RawResource: res,
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				failedControl("C-0057", "Privileged container",
					failedRuleWithFix("spec.containers[0].securityContext.privileged", "false"),
				),
			},
		},
	}
	profilePath := writeContainerProfile(t, dir, "Deployment", "demo", "default", "app")

	tests := []struct {
		name         string
		include      []string
		wantResource int
		wantDrift    bool
	}{
		{name: "no selection still applies profile drift", wantResource: 1, wantDrift: true},
		{name: "selection matching no control applies nothing", include: []string{"C-9999"}, wantResource: 0},
		{name: "selection matching a control applies only its fix", include: []string{"C-0057"}, wantResource: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHandlerForResources(dir, results, nil, false)
			h.fixInfo.ContainerProfilePath = profilePath
			h.controls = newControlSelector(tt.include, nil)

			rtf := h.PrepareResourcesToFix(context.Background())

			require.Len(t, rtf, tt.wantResource)
			if tt.wantResource == 0 {
				return
			}

			var drift int
			for expression := range rtf[0].YamlExpressions {
				if strings.Contains(expression, "readOnlyRootFilesystem") || strings.Contains(expression, "capabilities.drop") {
					drift++
				}
			}
			if tt.wantDrift {
				assert.NotZero(t, drift, "profile drift must still apply when no control is selected")
				return
			}
			assert.Zero(t, drift, "profile drift must not bypass an active control selection")
		})
	}
}
