package resourcehandler

import (
	"context"
	"errors"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/version"
	k8stesting "k8s.io/client-go/testing"
)

const (
	apiServerInfoGVR    = "apiserverinfo.kubescape.cloud/v1beta0/APIServerInfo"
	eksPolicyVersionGVR = "eks.amazonaws.com/v1/PolicyVersion"
)

// No cluster serves these resources, so discovery never lists them. The live
// resolver used to drop them with "resource was not found in Kubernetes
// discovery", and the controls reading them got no input at all.
func TestDiscoveryResolverKeepsKubescapeServedIdentities(t *testing.T) {
	resolver, failures := newDiscoveryResourceResolver(coreGroupDiscovery())
	require.Empty(t, failures)

	for _, test := range []struct{ group, version, resource, want string }{
		{"apiserverinfo.kubescape.cloud", "v1beta0", "APIServerInfo", apiServerInfoGVR},
		{"eks.amazonaws.com", "v1", "PolicyVersion", eksPolicyVersionGVR},
		{"management.azure.com", "v1", "PolicyVersion", "management.azure.com/v1/PolicyVersion"},
	} {
		resolved := resolver(test.group, test.version, test.resource)
		require.Len(t, resolved, 1, test.want)
		assert.Equal(t, test.want, resolved[0].groupVersionResourceTriplet)
	}
}

// C-0161 matches APIServerInfo under the host-data group, an identity no
// cluster and no Kubescape collector serves. Registering the C-0089 identity
// must not turn that one into a live LIST: the fallback is for the registered
// group and version only, and the host-data one stays dropped as on master.
func TestDiscoveryResolverDropsUnregisteredAPIServerInfoIdentity(t *testing.T) {
	resolver, _ := newDiscoveryResourceResolver(coreGroupDiscovery())
	assert.Empty(t, resolver("hostdata.kubescape.cloud", "v1beta0", "APIServerInfo"))
	assert.Empty(t, resolver("eks.amazonaws.com", "v1", "APIServerInfo"))

	frameworks := []reporthandling.Framework{{Controls: []reporthandling.Control{
		{ControlID: "C-0161", Rules: []reporthandling.PolicyRule{{Match: []reporthandling.RuleMatchObjects{{
			APIGroups: []string{"hostdata.kubescape.cloud"}, APIVersions: []string{"v1beta0"}, Resources: []string{"APIServerInfo"},
		}}}}},
		{ControlID: "C-0089", Rules: []reporthandling.PolicyRule{{DynamicMatch: []reporthandling.RuleMatchObjects{{
			APIGroups: []string{"apiserverinfo.kubescape.cloud"}, APIVersions: []string{"v1beta0"}, Resources: []string{"APIServerInfo"},
		}}}}},
	}}}
	queryable, _ := getQueryableResourceMapFromPolicies(frameworks, nil, reporthandling.ScopeCluster, resolver)
	assert.Empty(t, queryable.ToK8sResourceMap(), "no live LIST for either APIServerInfo identity")

	external := setKSResourceMap(frameworks, map[string][]string{}, resolver)
	assert.Contains(t, external, apiServerInfoGVR)
	assert.NotContains(t, external, "hostdata.kubescape.cloud/v1beta0/APIServerInfo")
}

// A custom DynamicMatch may select a registered cloud identity with a "*"
// version, and the evaluator accepts it. When it is the only rule asking for
// ClusterDescribe, the resolver must still keep it, so the cloud collector is
// triggered, while the unregistered host-data APIServerInfo stays dropped.
func TestDiscoveryResolverKeepsWildcardVersionOfRegisteredIdentity(t *testing.T) {
	resolver, _ := newDiscoveryResourceResolver(coreGroupDiscovery())
	resolved := resolver("eks.amazonaws.com", "*", "ClusterDescribe")
	require.Len(t, resolved, 1)
	assert.Equal(t, "eks.amazonaws.com/v1/ClusterDescribe", resolved[0].groupVersionResourceTriplet, "a * version resolves to the registered version, not an empty one")
	assert.Empty(t, resolver("hostdata.kubescape.cloud", "*", "APIServerInfo"))

	frameworks := []reporthandling.Framework{{Controls: []reporthandling.Control{
		{ControlID: "C-CUSTOM", Rules: []reporthandling.PolicyRule{{DynamicMatch: []reporthandling.RuleMatchObjects{{
			APIGroups: []string{"eks.amazonaws.com"}, APIVersions: []string{"*"}, Resources: []string{"ClusterDescribe"},
		}}}}},
		{ControlID: "C-0161", Rules: []reporthandling.PolicyRule{{Match: []reporthandling.RuleMatchObjects{{
			APIGroups: []string{"hostdata.kubescape.cloud"}, APIVersions: []string{"v1beta0"}, Resources: []string{"APIServerInfo"},
		}}}}},
	}}}
	external := setKSResourceMap(frameworks, map[string][]string{}, resolver)
	cloud := cautils.MapCloudResources(external)
	require.Len(t, cloud, 1)
	assert.Contains(t, cloud[0], "ClusterDescribe")
	assert.NotContains(t, external, "hostdata.kubescape.cloud/v1beta0/APIServerInfo")
}

// C-0089 reads APIServerInfo through DynamicMatch. It must be selected for
// collection, routed with the cloud resources, and recorded as the control's
// dependency so a failed collection shows up in the scan coverage.
func TestSetKSResourceMap_SelectsAPIServerInfo(t *testing.T) {
	resolver, _ := newDiscoveryResourceResolver(coreGroupDiscovery())
	frameworks := []reporthandling.Framework{{Controls: []reporthandling.Control{
		{ControlID: "C-0089", Rules: []reporthandling.PolicyRule{{DynamicMatch: []reporthandling.RuleMatchObjects{{
			APIGroups: []string{"apiserverinfo.kubescape.cloud"}, APIVersions: []string{"v1beta0"}, Resources: []string{"APIServerInfo"},
		}}}}},
	}}}

	dependencies := map[string][]string{}
	external := setKSResourceMap(frameworks, dependencies, resolver)

	assert.Contains(t, external, apiServerInfoGVR)
	assert.Equal(t, []string{apiServerInfoGVR}, cautils.MapCloudResources(external))
	assert.Equal(t, []string{"C-0089"}, dependencies[apiServerInfoGVR])
}

func apiServerInfoHandler() (*K8sResourceHandler, *k8stesting.Fake) {
	discovery := coreGroupDiscovery()
	discovery.FakedServerVersion = &version.Info{Major: "1", Minor: "33", GitVersion: "v1.33.1"}
	// No cloud provider: kind, k3s, on-prem.
	return &K8sResourceHandler{k8s: &k8sinterface.KubernetesApi{DiscoveryClient: discovery}}, discovery.Fake
}

func TestCollectRequiredAPIServerInfo_WithoutCloudProvider(t *testing.T) {
	handler, _ := apiServerInfoHandler()
	sessionObj := &cautils.OPASessionObj{InfoMap: map[string]apis.StatusInfo{}}
	allResources := map[string]workloadinterface.IMetadata{}
	external := cautils.ExternalResources{apiServerInfoGVR: nil, "eks.amazonaws.com/v1/ClusterDescribe": nil}

	remaining := handler.collectRequiredAPIServerInfo(context.Background(), sessionObj, allResources, external,
		[]string{apiServerInfoGVR, "eks.amazonaws.com/v1/ClusterDescribe"})

	assert.Equal(t, []string{"eks.amazonaws.com/v1/ClusterDescribe"}, remaining)
	require.Len(t, external[apiServerInfoGVR], 1)
	resource, ok := allResources[external[apiServerInfoGVR][0]]
	require.True(t, ok)
	assert.Equal(t, "APIServerInfo", resource.GetKind())
	assert.Empty(t, sessionObj.InfoMap)
}

func TestCollectRequiredAPIServerInfo_FailureIsRecorded(t *testing.T) {
	handler, fake := apiServerInfoHandler()
	fake.PrependReactor("get", "version", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("version endpoint unavailable")
	})
	sessionObj := &cautils.OPASessionObj{InfoMap: map[string]apis.StatusInfo{}}

	remaining := handler.collectRequiredAPIServerInfo(context.Background(), sessionObj, map[string]workloadinterface.IMetadata{},
		cautils.ExternalResources{apiServerInfoGVR: nil}, []string{apiServerInfoGVR})

	assert.Empty(t, remaining)
	require.Contains(t, sessionObj.InfoMap, apiServerInfoGVR)
	assert.Equal(t, apis.StatusSkipped, sessionObj.InfoMap[apiServerInfoGVR].InnerStatus)
}

func TestCollectRequiredAPIServerInfo_NotRequired(t *testing.T) {
	handler, _ := apiServerInfoHandler()
	cloud := []string{"eks.amazonaws.com/v1/ClusterDescribe"}
	allResources := map[string]workloadinterface.IMetadata{}

	remaining := handler.collectRequiredAPIServerInfo(context.Background(), &cautils.OPASessionObj{InfoMap: map[string]apis.StatusInfo{}},
		allResources, cautils.ExternalResources{}, cloud)

	assert.Equal(t, cloud, remaining)
	assert.Empty(t, allResources)
}
