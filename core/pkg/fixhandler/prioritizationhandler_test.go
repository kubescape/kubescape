package fixhandler

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	idhelpers "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	storagev1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const driftTestManifest = "apiVersion: v1\nkind: Pod\nmetadata: {name: demo}\nspec:\n  containers:\n  - name: app\n    image: nginx\n"

func driftProfile(annotations map[string]string, caps, syscalls []string) *storagev1beta1.ContainerProfile {
	return &storagev1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "profile", Annotations: annotations},
		Spec: storagev1beta1.ContainerProfileSpec{
			Capabilities: caps,
			Syscalls:     syscalls,
		},
	}
}

func driftKinds(fixes []FixSuggestion) (rootfs, drop bool) {
	for _, f := range fixes {
		rootfs = rootfs || strings.Contains(f.YamlExpression, "readOnlyRootFilesystem")
		drop = drop || strings.Contains(f.YamlExpression, "capabilities.drop")
	}
	return rootfs, drop
}

func TestDetectProfileDrift_EvidencePolicy(t *testing.T) {
	completedFull := map[string]string{idhelpers.StatusMetadataKey: idhelpers.Completed, idhelpers.CompletionMetadataKey: idhelpers.Full}
	tests := []struct {
		name       string
		profile    *storagev1beta1.ContainerProfile
		wantRootfs bool
		wantDrop   bool
	}{
		{
			name:       "missing annotations keep existing behavior",
			profile:    driftProfile(nil, nil, nil),
			wantRootfs: true, wantDrop: true,
		},
		{
			name:       "completed/full with no write evidence keeps existing behavior",
			profile:    driftProfile(completedFull, nil, []string{"read", "write", "openat"}),
			wantRootfs: true, wantDrop: true,
		},
		{
			name:    "learning profile gets no absence-based suggestions",
			profile: driftProfile(map[string]string{idhelpers.StatusMetadataKey: idhelpers.Learning, idhelpers.CompletionMetadataKey: idhelpers.Partial}, nil, nil),
		},
		{
			name:    "completed/partial profile gets no absence-based suggestions",
			profile: driftProfile(map[string]string{idhelpers.StatusMetadataKey: idhelpers.Completed, idhelpers.CompletionMetadataKey: idhelpers.Partial}, nil, nil),
		},
		{
			name:    "incomplete status alone is enough",
			profile: driftProfile(map[string]string{idhelpers.StatusMetadataKey: idhelpers.Incomplete}, nil, nil),
		},
		{
			name:     "recorded filesystem-mutating syscall vetoes only rootfs",
			profile:  driftProfile(completedFull, nil, []string{"unlinkat"}),
			wantDrop: true,
		},
		{
			name:     "descriptor and mount mutations also veto rootfs",
			profile:  driftProfile(completedFull, nil, []string{"fallocate", "mount"}),
			wantDrop: true,
		},
		{
			name:     "syscall match is case-insensitive",
			profile:  driftProfile(completedFull, nil, []string{"Rename"}),
			wantDrop: true,
		},
		{
			name:     "incomplete profile with exercised capabilities keeps the unchanged non-empty branch",
			profile:  driftProfile(map[string]string{idhelpers.CompletionMetadataKey: idhelpers.Partial}, []string{"CHOWN"}, nil),
			wantDrop: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixes := DetectProfileDrift([]byte(driftTestManifest), tt.profile, "Pod", "app", 0)
			rootfs, drop := driftKinds(fixes)
			assert.Equal(t, tt.wantRootfs, rootfs, "readOnlyRootFilesystem suggestion")
			assert.Equal(t, tt.wantDrop, drop, "drop ALL suggestion")
		})
	}
}

// The non-empty capability branch compares against positive evidence and is
// left as it was, so a complete profile keeps getting SYS_ADMIN/NET_ADMIN drops.
func TestDetectProfileDrift_NonEmptyCapabilitiesUnchanged(t *testing.T) {
	profile := driftProfile(map[string]string{idhelpers.StatusMetadataKey: idhelpers.Completed, idhelpers.CompletionMetadataKey: idhelpers.Full}, []string{"CHOWN"}, nil)
	fixes := DetectProfileDrift([]byte(driftTestManifest), profile, "Pod", "app", 0)
	_, drop := driftKinds(fixes)
	assert.True(t, drop)
}

// A suppressed suggestion must not reach the application list of the CLI path.
func TestPrepareResourcesToFix_IncompleteProfileSuppressesDrift(t *testing.T) {
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
	results := []resourcesresults.Result{{
		ResourceID:  res.GetID(),
		RawResource: res,
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{
			failedControl("C-0057", "Privileged container",
				failedRuleWithFix("spec.containers[0].securityContext.privileged", "false")),
		},
	}}

	tests := []struct {
		name        string
		annotations map[string]string
		wantDrift   bool
	}{
		{name: "unannotated profile", wantDrift: true},
		{name: "learning profile", annotations: map[string]string{idhelpers.StatusMetadataKey: idhelpers.Learning}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := map[string]any{
				"metadata": map[string]any{
					"name":        "profile",
					"annotations": tt.annotations,
					"labels": map[string]string{
						"kubescape.io/workload-kind":           "Deployment",
						"kubescape.io/workload-name":           "demo",
						"kubescape.io/workload-namespace":      "default",
						"kubescape.io/workload-container-name": "app",
					},
				},
				"spec": map[string]any{},
			}
			raw, err := json.Marshal(profile)
			require.NoError(t, err)
			profilePath := filepath.Join(t.TempDir(), "profile.json")
			require.NoError(t, os.WriteFile(profilePath, raw, 0o600))

			h := newHandlerForResources(dir, results, nil, false)
			h.fixInfo.ContainerProfilePath = profilePath
			rtf := h.PrepareResourcesToFix(context.Background())

			require.Len(t, rtf, 1, "the control fix is still planned")
			var drift int
			for expression := range rtf[0].YamlExpressions {
				if strings.Contains(expression, "readOnlyRootFilesystem") || strings.Contains(expression, "capabilities.drop") {
					drift++
				}
			}
			if tt.wantDrift {
				assert.NotZero(t, drift)
			} else {
				assert.Zero(t, drift)
			}
		})
	}
}
