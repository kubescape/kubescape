package resourcehandler

import (
	"context"
	"strings"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
)

const (
	// discoveredHostKubeletGVR is what partialGVRPullsForResource emits with
	// the host CRD installed: the discovered (lowercase plural) spelling.
	discoveredHostKubeletGVR = "hostdata.kubescape.cloud/v1beta0/kubeletinfos"
	discoveredHostProxyGVR   = "hostdata.kubescape.cloud/v1beta0/kubeproxyinfos"
	// rawHostKubeletGVR is what a DynamicMatch stores via insertControls:
	// the policy's Kind spelling, bypassing the resolver.
	rawHostKubeletGVR = "hostdata.kubescape.cloud/v1beta0/KubeletInfo"
	rawHostProxyGVR   = "hostdata.kubescape.cloud/v1beta0/KubeProxyInfo"
)

// hostCRDResourceLists advertises the host-sensor CRDs the way a cluster
// with the node-agent installed reports them: lowercase plural resources
// served under the hostdata group.
func hostCRDResourceLists() []*metav1.APIResourceList {
	verbs := []string{"get", "list", "watch"}
	return []*metav1.APIResourceList{
		{
			GroupVersion: "hostdata.kubescape.cloud/v1beta0",
			APIResources: []metav1.APIResource{
				{Name: "kubeletinfos", Kind: "KubeletInfo", Namespaced: false, Verbs: verbs},
				{Name: "kubeproxyinfos", Kind: "KubeProxyInfo", Namespaced: false, Verbs: verbs},
			},
		},
	}
}

// newHandlerWithHostCRDs builds a handler whose discovery resolver sees the
// host CRDs (like a cluster with the node-agent installed) and whose dynamic
// client lists nothing, so collection reaches the host-sensor stub.
func newHandlerWithHostCRDs(t *testing.T) *K8sResourceHandler {
	t.Helper()
	client := fakeclientset.NewClientset()
	client.Resources = hostCRDResourceLists()
	handler := getResourceHandlerMock()
	handler.k8s.KubernetesClient = client
	handler.k8s.DiscoveryClient = client.Discovery()
	handler.k8s.DynamicClient = &mockDynamicClient{
		listFunc: func(_ context.Context, _ metav1.ListOptions) (*unstructured.UnstructuredList, error) {
			return &unstructured.UnstructuredList{}, nil
		},
	}
	return handler
}

// dynamicMatchControl builds a C-0069-shaped control: its host dependency
// arrives via DynamicMatch, which stores the raw Kind spelling in
// ResourceToControlsMap without consulting the resolver.
func dynamicMatchControl(controlID, resource string) reporthandling.Control {
	rule := mockRule(controlID+"-rule", nil, "")
	rule.DynamicMatch = []reporthandling.RuleMatchObjects{{
		APIGroups:   []string{""},
		APIVersions: []string{"v1"},
		Resources:   []string{resource},
	}}
	control := mockControl(controlID, nil)
	control.ControlID = controlID
	control.Rules = []reporthandling.PolicyRule{rule}
	return control
}

// dynamicMatchFramework selects a KubeletInfo control and a KubeProxyInfo
// control, both through DynamicMatch.
func dynamicMatchFramework() *reporthandling.Framework {
	framework := mockFramework("host-dynamic-framework", nil)
	framework.Controls = []reporthandling.Control{
		dynamicMatchControl("C-0069", "KubeletInfo"),
		dynamicMatchControl("C-0070", "KubeProxyInfo"),
	}
	return framework
}

// discoveryStubPartials are conversion gaps in the discovered spelling, as
// partialGVRPullsForResource emits them with the host CRD installed.
func discoveryStubPartials() []cautils.PartialGVRPull {
	return []cautils.PartialGVRPull{
		{GVR: discoveredHostKubeletGVR, Selector: "conversion", Error: "node-agent reported 2 KubeletInfo but only 1 could be read"},
		{GVR: discoveredHostProxyGVR, Selector: "conversion", Error: "node-agent reported 2 KubeProxyInfo but only 1 could be read"},
	}
}

// TestGetResources_HostGapDiscoveryAwareDynamicMatch is the HIGH regression:
// with the host CRD installed, a relevant conversion gap in the discovered
// spelling must survive even though the DynamicMatch map holds the raw Kind
// spelling. Dropping it would let passing results escape IncompleteCoverage.
func TestGetResources_HostGapDiscoveryAwareDynamicMatch(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()
	handler := newHandlerWithHostCRDs(t)
	handler.hostSensorHandler = &stubHostSensor{partials: discoveryStubPartials()}

	scanInfo := &cautils.ScanInfo{}
	scanInfo.HostSensorEnabled.SetBool(true)
	sessionObj := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo, nil)
	sessionObj.Policies = append(sessionObj.Policies, *dynamicMatchFramework())

	_, _, _, _, _ = handler.GetResources(context.Background(), sessionObj, scanInfo)

	require.Contains(t, sessionObj.ResourceToControlsMap, rawHostKubeletGVR,
		"precondition: DynamicMatch must store the raw Kind spelling")
	require.NotContains(t, sessionObj.ResourceToControlsMap, discoveredHostKubeletGVR,
		"precondition: nothing may store the discovered spelling, or raw membership alone would pass")
	require.Len(t, sessionObj.PartialGVRFailures, 2,
		"both discovered gaps back effective selected controls and must reach the session")
	assert.Equal(t, discoveredHostKubeletGVR, sessionObj.PartialGVRFailures[0].GVR)
	assert.Equal(t, discoveredHostProxyGVR, sessionObj.PartialGVRFailures[1].GVR)
}

// TestGetResources_HostGapRespectsIncludeSkipControls is the MEDIUM
// regression on the eager path: the flags are real session fields (not
// pre-narrowed fixtures), and a gap required only by a filtered-out control
// must not penalize the scan.
func TestGetResources_HostGapRespectsIncludeSkipControls(t *testing.T) {
	tests := []struct {
		name       string
		skip       string
		include    string
		wantGVRs   []string
		wantAbsent []string
	}{
		{name: "skip proxy control", skip: "C-0070", wantGVRs: []string{discoveredHostKubeletGVR}, wantAbsent: []string{discoveredHostProxyGVR}},
		{name: "include kubelet control", include: "C-0069", wantGVRs: []string{discoveredHostKubeletGVR}, wantAbsent: []string{discoveredHostProxyGVR}},
		{name: "no flags keeps both", wantGVRs: []string{discoveredHostKubeletGVR, discoveredHostProxyGVR}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k8sinterface.InitializeMapResourcesMock()
			handler := newHandlerWithHostCRDs(t)
			handler.hostSensorHandler = &stubHostSensor{partials: discoveryStubPartials()}

			scanInfo := &cautils.ScanInfo{SkipControls: tt.skip, IncludeControls: tt.include}
			scanInfo.HostSensorEnabled.SetBool(true)
			sessionObj := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo, nil)
			sessionObj.Policies = append(sessionObj.Policies, *dynamicMatchFramework())

			_, _, _, _, _ = handler.GetResources(context.Background(), sessionObj, scanInfo)

			got := make([]string, 0, len(sessionObj.PartialGVRFailures))
			for _, p := range sessionObj.PartialGVRFailures {
				got = append(got, p.GVR)
			}
			assert.ElementsMatch(t, tt.wantGVRs, got)
			for _, absent := range tt.wantAbsent {
				assert.NotContains(t, got, absent)
			}
			if len(tt.wantGVRs) == 1 {
				coverage := cautils.BuildScanCoverage(sessionObj.InfoMap, sessionObj.ResourceToControlsMap, nil, sessionObj.PartialGVRFailures, nil, nil)
				require.Len(t, coverage.PartialGVRPulls, 1)
			}
		})
	}
}

// discoveryBridgingResolver mimics cluster discovery for host kinds: the raw
// Kind spelling expands to the discovered (lowercase plural) triplet plus
// kind/plural comparison aliases, mirroring newDiscoveryResourceResolver.
func discoveryBridgingResolver(group, version, resource string) []resolvedResource {
	triplet := k8sinterface.JoinResourceTriplets(group, version, resource)
	lower := k8sinterface.JoinResourceTriplets(group, version, strings.ToLower(resource))
	plural := k8sinterface.JoinResourceTriplets(group, version, strings.ToLower(resource)+"s")
	if triplet == lower {
		return []resolvedResource{{groupVersionResourceTriplet: triplet}}
	}
	return []resolvedResource{{
		groupVersionResourceTriplet: lower,
		comparisonTriplets:          []string{triplet, plural},
	}}
}

func TestCollectAndStreamBatches_HostGapDiscoveryAware(t *testing.T) {
	// Streaming-path mirror of the HIGH regression: the resolver is the
	// real discovery resolver over a fake API server advertising the host
	// CRDs, so raw map keys bridge to discovered gap spellings exactly as
	// in production.
	ctx := context.Background()
	handler := newHandlerWithHostCRDs(t)
	handler.hostSensorHandler = &stubHostSensor{partials: discoveryStubPartials()}
	resolver, _, _ := newDiscoveryResourceResolverWithKinds(handler.k8s.DiscoveryClient)
	scanInfo, session := streamingTestSession(ctx)
	session.Metadata.ScanMetadata.HostScanner = true
	framework := dynamicMatchFramework()
	session.Policies = append(session.Policies, *framework)
	session.ResourceToControlsMap = map[string][]string{
		rawHostKubeletGVR: {framework.Controls[0].ControlID},
		rawHostProxyGVR:   {framework.Controls[1].ControlID},
	}
	batches := make(chan *cautils.ResourceBatch, 1)

	err := handler.collectAndStreamBatches(
		ctx,
		QueryableResources{},
		&EmptySelector{},
		session,
		scanInfo,
		cautils.ExternalResources{rawHostKubeletGVR: nil, rawHostProxyGVR: nil},
		batches,
		resolver,
	)

	require.NoError(t, err)
	require.Len(t, session.PartialGVRFailures, 2,
		"resolver expansion must bridge raw map keys to discovered gap spellings")
}

// TestCollectAndStreamBatches_HostGapRespectsIncludeSkipControls is the
// streaming-path mirror of the MEDIUM regression with real flag fields.
func TestCollectAndStreamBatches_HostGapRespectsIncludeSkipControls(t *testing.T) {
	tests := []struct {
		name     string
		skip     string
		include  string
		wantGVRs []string
	}{
		{name: "skip proxy control", skip: "C-0070", wantGVRs: []string{discoveredHostKubeletGVR}},
		{name: "include kubelet control", include: "C-0069", wantGVRs: []string{discoveredHostKubeletGVR}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			handler := newHandlerWithHostCRDs(t)
			handler.hostSensorHandler = &stubHostSensor{partials: discoveryStubPartials()}
			resolver, _, _ := newDiscoveryResourceResolverWithKinds(handler.k8s.DiscoveryClient)
			scanInfo, session := streamingTestSession(ctx)
			session.Metadata.ScanMetadata.HostScanner = true
			framework := dynamicMatchFramework()
			session.Policies = append(session.Policies, *framework)
			session.SkipControls = tt.skip
			session.IncludeControls = tt.include
			session.ResourceToControlsMap = map[string][]string{
				rawHostKubeletGVR: {framework.Controls[0].ControlID},
				rawHostProxyGVR:   {framework.Controls[1].ControlID},
			}
			batches := make(chan *cautils.ResourceBatch, 1)

			err := handler.collectAndStreamBatches(
				ctx,
				QueryableResources{},
				&EmptySelector{},
				session,
				scanInfo,
				cautils.ExternalResources{rawHostKubeletGVR: nil, rawHostProxyGVR: nil},
				batches,
				resolver,
			)

			require.NoError(t, err)
			got := make([]string, 0, len(session.PartialGVRFailures))
			for _, p := range session.PartialGVRFailures {
				got = append(got, p.GVR)
			}
			assert.ElementsMatch(t, tt.wantGVRs, got)
		})
	}
}

// TestEffectiveHostGapAllowlist_Unit pins the allowlist semantics directly:
// raw-plus-expansion membership, effective-control scoping, nil-resolver
// fallback, and unfiltered fallback when the control filter errors.
func TestEffectiveHostGapAllowlist_Unit(t *testing.T) {
	framework := dynamicMatchFramework()
	policies := []reporthandling.Framework{*framework}

	newSession := func() *cautils.OPASessionObj {
		session := &cautils.OPASessionObj{
			Policies: policies,
			ResourceToControlsMap: map[string][]string{
				rawHostKubeletGVR: {framework.Controls[0].ControlID},
				rawHostProxyGVR:   {framework.Controls[1].ControlID},
			},
		}
		return session
	}

	t.Run("expansion bridges spellings", func(t *testing.T) {
		allowed := effectiveHostGapAllowlist(newSession(), discoveryBridgingResolver)
		assert.True(t, allowed[rawHostKubeletGVR])
		assert.True(t, allowed[discoveredHostKubeletGVR])
		assert.True(t, allowed[discoveredHostProxyGVR])
	})

	t.Run("skip narrows to selected", func(t *testing.T) {
		session := newSession()
		session.SkipControls = "C-0070"
		allowed := effectiveHostGapAllowlist(session, discoveryBridgingResolver)
		assert.True(t, allowed[discoveredHostKubeletGVR])
		assert.False(t, allowed[discoveredHostProxyGVR])
		assert.False(t, allowed[rawHostProxyGVR])
	})

	t.Run("nil resolver keeps raw keys", func(t *testing.T) {
		allowed := effectiveHostGapAllowlist(newSession(), nil)
		assert.True(t, allowed[rawHostKubeletGVR])
		assert.False(t, allowed[discoveredHostKubeletGVR])
	})

	t.Run("filter error falls back unfiltered", func(t *testing.T) {
		session := newSession()
		session.IncludeControls = "C-9999"
		allowed := effectiveHostGapAllowlist(session, discoveryBridgingResolver)
		assert.True(t, allowed[discoveredHostKubeletGVR])
		assert.True(t, allowed[discoveredHostProxyGVR])
	})

	t.Run("nil session is empty", func(t *testing.T) {
		assert.Empty(t, effectiveHostGapAllowlist(nil, discoveryBridgingResolver))
	})
}
