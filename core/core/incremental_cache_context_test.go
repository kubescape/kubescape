package core

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/scancache"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testRuntimeVersion = "v4.0.0-test"

func cacheVersionFixture() (*cautils.ScanInfo, *cautils.OPASessionObj) {
	rule := reporthandling.PolicyRule{
		Rule:         "package armo_builtins\ndeny[msg] { data.dataControlInputs.cloudProvider == \"eks\"; msg := {} }",
		RuleLanguage: reporthandling.RegoLanguage,
	}
	rule.Name = "provider-specific-rule"
	control := reporthandling.Control{
		ControlID: "C-CACHE-CONTEXT",
		Rules:     []reporthandling.PolicyRule{rule},
	}
	control.Name = "provider-specific-control"
	framework := reporthandling.Framework{Controls: []reporthandling.Control{control}}
	framework.Name = "provider-specific-framework"

	return &cautils.ScanInfo{
			Incremental:     true,
			ControlsVersion: "controls-v1",
		}, &cautils.OPASessionObj{
			Policies: []reporthandling.Framework{framework},
			AllPolicies: &cautils.Policies{
				Controls:   map[string]reporthandling.Control{control.ControlID: control},
				Frameworks: []string{framework.Name},
			},
			RegoInputData: cautils.RegoInputData{
				PostureControlInputs: map[string][]string{"tenantSetting": {"one"}},
				DataControlInputs:    map[string]string{"mode": "strict"},
			},
			Report: &reporthandlingv2.PostureReport{
				ClusterCloudProvider: "eks",
			},
		}
}

func requireCacheVersion(t *testing.T, scanInfo *cautils.ScanInfo, scanData *cautils.OPASessionObj, runtimeVersion string) string {
	t.Helper()
	version, err := incrementalCacheVersion(scanInfo, scanData, runtimeVersion)
	require.NoError(t, err)
	require.Len(t, version, 64)
	return version
}

func TestIncrementalCacheVersionIsStableForIdenticalInputs(t *testing.T) {
	scanInfo, scanData := cacheVersionFixture()

	first := requireCacheVersion(t, scanInfo, scanData, testRuntimeVersion)
	second := requireCacheVersion(t, scanInfo, scanData, testRuntimeVersion)

	assert.Equal(t, first, second)
}

func TestIncrementalCacheVersionSeparatesCloudProviders(t *testing.T) {
	scanInfo, scanData := cacheVersionFixture()
	eksVersion := requireCacheVersion(t, scanInfo, scanData, testRuntimeVersion)

	// The exact same Kubernetes object can produce a different verdict because
	// cloudProvider is available to Rego through dataControlInputs. This was the
	// missing namespace dimension that allowed an EKS verdict to be reused for
	// an AKS or GKE scan.
	scanData.Report.ClusterCloudProvider = "aks"
	aksVersion := requireCacheVersion(t, scanInfo, scanData, testRuntimeVersion)
	scanData.Report.ClusterCloudProvider = "gke"
	gkeVersion := requireCacheVersion(t, scanInfo, scanData, testRuntimeVersion)

	assert.NotEqual(t, eksVersion, aksVersion)
	assert.NotEqual(t, eksVersion, gkeVersion)
	assert.NotEqual(t, aksVersion, gkeVersion)
}

func TestIncrementalCacheVersionSeparatesUnknownAndKnownProvider(t *testing.T) {
	scanInfo, scanData := cacheVersionFixture()
	scanData.Report.ClusterCloudProvider = ""
	unknownVersion := requireCacheVersion(t, scanInfo, scanData, testRuntimeVersion)

	scanData.Report.ClusterCloudProvider = "eks"
	knownVersion := requireCacheVersion(t, scanInfo, scanData, testRuntimeVersion)

	assert.NotEqual(t, unknownVersion, knownVersion)
}

func TestIncrementalCacheVersionSeparatesRuntimeVersions(t *testing.T) {
	scanInfo, scanData := cacheVersionFixture()

	oldRuntime := requireCacheVersion(t, scanInfo, scanData, "v4.0.0")
	newRuntime := requireCacheVersion(t, scanInfo, scanData, "v4.1.0")

	assert.NotEqual(t, oldRuntime, newRuntime)
	for _, runtimeVersion := range []string{"", "dev"} {
		t.Run("rejects "+runtimeVersion, func(t *testing.T) {
			version, err := incrementalCacheVersion(scanInfo, scanData, runtimeVersion)

			assert.Empty(t, version)
			require.EqualError(t, err, "incremental cache requires a release build identity")
		})
	}
}

func TestIncrementalCacheVersionTracksControlsVersion(t *testing.T) {
	scanInfo, scanData := cacheVersionFixture()
	first := requireCacheVersion(t, scanInfo, scanData, testRuntimeVersion)

	scanInfo.ControlsVersion = "controls-v2"
	second := requireCacheVersion(t, scanInfo, scanData, testRuntimeVersion)

	assert.NotEqual(t, first, second)
}

func TestIncrementalCacheVersionTracksResolvedFrameworks(t *testing.T) {
	scanInfo, scanData := cacheVersionFixture()
	first := requireCacheVersion(t, scanInfo, scanData, testRuntimeVersion)

	scanData.Policies[0].Name = "changed-framework"
	second := requireCacheVersion(t, scanInfo, scanData, testRuntimeVersion)

	assert.NotEqual(t, first, second)
}

func TestIncrementalCacheVersionTracksResolvedRules(t *testing.T) {
	scanInfo, scanData := cacheVersionFixture()
	first := requireCacheVersion(t, scanInfo, scanData, testRuntimeVersion)

	changed := scanData.AllPolicies.Controls["C-CACHE-CONTEXT"]
	changed.Rules[0].Rule += "\n# changed"
	scanData.AllPolicies.Controls["C-CACHE-CONTEXT"] = changed
	second := requireCacheVersion(t, scanInfo, scanData, testRuntimeVersion)

	assert.NotEqual(t, first, second)
}

func TestIncrementalCacheVersionTracksRegoInputData(t *testing.T) {
	scanInfo, scanData := cacheVersionFixture()
	first := requireCacheVersion(t, scanInfo, scanData, testRuntimeVersion)

	scanData.RegoInputData.PostureControlInputs["tenantSetting"] = []string{"two"}
	second := requireCacheVersion(t, scanInfo, scanData, testRuntimeVersion)

	assert.NotEqual(t, first, second)
}

func TestIncrementalCacheVersionTracksControlsInputContents(t *testing.T) {
	scanInfo, scanData := cacheVersionFixture()
	path := filepath.Join(t.TempDir(), "controls-inputs.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"allowedRegistries":["one.example"]}`), 0o600))
	scanInfo.ControlsInputs = path
	first := requireCacheVersion(t, scanInfo, scanData, testRuntimeVersion)

	require.NoError(t, os.WriteFile(path, []byte(`{"allowedRegistries":["two.example"]}`), 0o600))
	second := requireCacheVersion(t, scanInfo, scanData, testRuntimeVersion)

	assert.NotEqual(t, first, second)
}

func TestIncrementalCacheVersionFailsClosedWhenControlsInputDisappears(t *testing.T) {
	scanInfo, scanData := cacheVersionFixture()
	scanInfo.ControlsInputs = filepath.Join(t.TempDir(), "missing-controls-inputs.json")

	version, err := incrementalCacheVersion(scanInfo, scanData, testRuntimeVersion)

	assert.Empty(t, version)
	require.Error(t, err)
	assert.ErrorContains(t, err, "read controls inputs for cache version")
}

func TestIncrementalCacheVersionRejectsMissingInputs(t *testing.T) {
	scanInfo, scanData := cacheVersionFixture()

	tests := []struct {
		name     string
		scanInfo *cautils.ScanInfo
		scanData *cautils.OPASessionObj
		wantErr  string
	}{
		{
			name:     "missing scan info",
			scanData: scanData,
			wantErr:  "scan info is required",
		},
		{
			name:     "missing scan data",
			scanInfo: scanInfo,
			wantErr:  "scan data is required",
		},
		{
			name:     "missing scan report",
			scanInfo: scanInfo,
			scanData: &cautils.OPASessionObj{},
			wantErr:  "scan report is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, err := incrementalCacheVersion(tt.scanInfo, tt.scanData, testRuntimeVersion)
			assert.Empty(t, version)
			require.EqualError(t, err, tt.wantErr)
		})
	}
}

func TestIncrementalCacheContextHasExplicitSchemaVersion(t *testing.T) {
	scanInfo, scanData := cacheVersionFixture()
	original := incrementalCacheSchemaVersion
	first := requireCacheVersion(t, scanInfo, scanData, testRuntimeVersion)

	// The constant is deliberately asserted here so a future wire-format
	// change is visible in review and old entries are invalidated on purpose.
	assert.Equal(t, "2", original)
	assert.NotEmpty(t, first)
}

func TestIncrementalCacheVersionDoesNotDependOnMapInsertionOrder(t *testing.T) {
	scanInfo, scanData := cacheVersionFixture()
	scanData.RegoInputData = cautils.RegoInputData{
		PostureControlInputs: map[string][]string{
			"alpha": {"one", "two"},
			"beta":  {"a", "b"},
		},
		DataControlInputs: map[string]string{"gamma": "three", "delta": "four"},
	}
	first := requireCacheVersion(t, scanInfo, scanData, testRuntimeVersion)

	// encoding/json sorts string map keys. Prove the cache namespace remains
	// stable when callers build semantically identical maps in another order.
	scanData.RegoInputData = cautils.RegoInputData{
		DataControlInputs: map[string]string{"delta": "four", "gamma": "three"},
		PostureControlInputs: map[string][]string{
			"beta":  {"a", "b"},
			"alpha": {"one", "two"},
		},
	}
	second := requireCacheVersion(t, scanInfo, scanData, testRuntimeVersion)

	assert.Equal(t, first, second)
}

func TestIncrementalCacheVersionDistinguishesPartBoundaries(t *testing.T) {
	firstInfo, firstData := cacheVersionFixture()
	firstInfo.ControlsVersion = "ab"
	firstData.Report.ClusterCloudProvider = "c"
	first := requireCacheVersion(t, firstInfo, firstData, testRuntimeVersion)

	secondInfo, secondData := cacheVersionFixture()
	secondInfo.ControlsVersion = "a"
	secondData.Report.ClusterCloudProvider = "bc"
	second := requireCacheVersion(t, secondInfo, secondData, testRuntimeVersion)

	assert.NotEqual(t, first, second)
}

func TestIncrementalCacheVersionPreventsCrossContextVerdictReuse(t *testing.T) {
	// Exercise the actual store contract, not only hash inequality. A verdict
	// written under one provider/version namespace must be a miss when the
	// caller opens the same cache directory for another evaluation context.
	dir := t.TempDir()
	scanInfo, scanData := cacheVersionFixture()
	eksVersion := requireCacheVersion(t, scanInfo, scanData, "v4.0.0")

	eksStore, err := scancache.Load(dir, eksVersion)
	require.NoError(t, err)
	eksStore.Put(
		"C-CACHE-CONTEXT",
		"v1/default/Pod/provider-sensitive",
		"unchanged-resource-hash",
		resourcesresults.ResourceAssociatedControl{ControlID: "C-CACHE-CONTEXT"},
	)
	require.NoError(t, eksStore.Flush())

	tests := []struct {
		name           string
		provider       string
		runtimeVersion string
	}{
		{name: "another provider", provider: "gke", runtimeVersion: "v4.0.0"},
		{name: "another runtime", provider: "eks", runtimeVersion: "v4.1.0"},
		{name: "unknown provider", provider: "", runtimeVersion: "v4.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanData.Report.ClusterCloudProvider = tt.provider
			version := requireCacheVersion(t, scanInfo, scanData, tt.runtimeVersion)
			store, loadErr := scancache.Load(dir, version)
			require.NoError(t, loadErr)

			_, hit := store.Get(
				"C-CACHE-CONTEXT",
				"v1/default/Pod/provider-sensitive",
				"unchanged-resource-hash",
			)
			assert.False(t, hit, "a verdict from a different evaluation context must not be reused")
		})
	}

	// Reopening with the original context remains a hit. This guards against a
	// fix that simply disables persistence instead of correctly namespacing it.
	scanData.Report.ClusterCloudProvider = "eks"
	originalVersion := requireCacheVersion(t, scanInfo, scanData, "v4.0.0")
	originalStore, err := scancache.Load(dir, originalVersion)
	require.NoError(t, err)
	verdict, hit := originalStore.Get(
		"C-CACHE-CONTEXT",
		"v1/default/Pod/provider-sensitive",
		"unchanged-resource-hash",
	)
	assert.True(t, hit)
	assert.Equal(t, "C-CACHE-CONTEXT", verdict.ControlID)
}

func TestIncrementalCacheVersionIncludesAllRegoInputSections(t *testing.T) {
	scanInfo, scanData := cacheVersionFixture()
	base := requireCacheVersion(t, scanInfo, scanData, testRuntimeVersion)

	scanData.RegoInputData.DataControlInputs["mode"] = "permissive"
	dataControlChanged := requireCacheVersion(t, scanInfo, scanData, testRuntimeVersion)
	assert.NotEqual(t, base, dataControlChanged)

	scanData.RegoInputData.DataControlInputs["mode"] = "strict"
	scanData.RegoInputData.PostureControlInputs["tenantSetting"] = []string{"one", "two"}
	postureControlChanged := requireCacheVersion(t, scanInfo, scanData, testRuntimeVersion)
	assert.NotEqual(t, base, postureControlChanged)
	assert.NotEqual(t, dataControlChanged, postureControlChanged)
}
