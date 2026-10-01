package resourcehandler

import (
	"context"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/hostsensorutils"
	"github.com/kubescape/opa-utils/objectsenvelopes/hostsensor"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery/fake"
	clienttesting "k8s.io/client-go/testing"
)

type hostIdentityDiscovery struct{ *fake.FakeDiscovery }

func (d hostIdentityDiscovery) ServerPreferredResources() ([]*metav1.APIResourceList, error) {
	return d.Resources, nil
}

type hostIdentitySensor struct {
	hostsensorutils.HostSensorHandlerMock
}

func (hostIdentitySensor) CollectResources(context.Context) ([]hostsensor.HostSensorDataEnvelope, map[string]apis.StatusInfo, []cautils.PartialGVRPull, error) {
	var resources []hostsensor.HostSensorDataEnvelope
	for _, name := range []string{"node-a", "node-b"} {
		var envelope hostsensor.HostSensorDataEnvelope
		envelope.SetApiVersion("hostdata.kubescape.cloud/v1beta0")
		envelope.SetKind("KubeletInfo")
		envelope.SetName(name)
		resources = append(resources, envelope)
	}
	return resources, nil, nil, nil
}

// This checks selection/indexing, not sensor decoding or Rego evaluation.
// The selector is the one used by the upstream C-0172 kubelet control.
func TestHostDataIdentityAcrossDiscovery(t *testing.T) {
	for _, tc := range []struct {
		name     string
		versions []string
	}{
		{name: "no CRDs"},
		{name: "v1beta0", versions: []string{"v1beta0"}},
		{name: "v1beta1", versions: []string{"v1beta1"}},
		{name: "both versions", versions: []string{"v1beta0", "v1beta1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			discovery := hostIdentityDiscovery{&fake.FakeDiscovery{Fake: &clienttesting.Fake{}}}
			for _, version := range tc.versions {
				discovery.Resources = append(discovery.Resources, &metav1.APIResourceList{
					GroupVersion: "hostdata.kubescape.cloud/" + version,
					APIResources: []metav1.APIResource{{
						Name: "kubeletinfos", Kind: "KubeletInfo",
						Verbs: metav1.Verbs{"get", "list"},
					}},
				})
			}
			// Initialize global discovery too: otherwise fallback resolution
			// can hide the collision and make this test pass incorrectly.
			k8sinterface.InitializeMapResources(discovery)
			t.Cleanup(k8sinterface.InitializeMapResourcesMock)
			resolver, _ := newDiscoveryResourceResolver(discovery)
			for _, resolve := range []resourceResolver{defaultResourceResolver, resolver} {
				for kind, apiVersion := range MapResourceToApiGroup {
					group, version := k8sinterface.SplitApiVersion(apiVersion)
					got := resolve(group, version, kind)
					if len(got) != 1 || got[0].groupVersionResourceTriplet != apiVersion+"/"+kind {
						t.Errorf("virtual host resource %s resolved to %v", kind, got)
					}
				}
			}
			frameworks := []reporthandling.Framework{{Controls: []reporthandling.Control{{
				ControlID: "C-0172",
				Rules: []reporthandling.PolicyRule{{DynamicMatch: []reporthandling.RuleMatchObjects{{
					APIGroups:   []string{"hostdata.kubescape.cloud"},
					APIVersions: []string{"v1beta0"}, Resources: []string{"KubeletInfo"},
				}}}},
			}}}}
			dependencies := map[string][]string{}
			external := setKSResourceMap(frameworks, dependencies, resolver)
			if hosts := cautils.MapHostResources(external); len(hosts) != 1 {
				t.Errorf("host collector selection lost: external=%v selected=%v", external, hosts)
			}
			// Invoke collection explicitly even if selection failed, to expose
			// the independent indexing mismatch rather than stopping early.
			all := map[string]workloadinterface.IMetadata{}
			handler := K8sResourceHandler{hostSensorHandler: &hostIdentitySensor{}}
			if _, _, err := handler.collectHostResources(context.Background(), all, external); err != nil {
				t.Fatal(err)
			}
			const key = "hostdata.kubescape.cloud/v1beta0/KubeletInfo"
			if len(external[key]) != 2 || len(all) != 2 {
				t.Errorf("host envelopes not indexed by virtual identity: external=%v collected=%d", external, len(all))
			}
			if ids := dependencies[key]; len(ids) != 1 || ids[0] != "C-0172" {
				t.Errorf("control dependency missing under virtual identity: %v", dependencies)
			}
		})
	}
}

func TestHostDataResolverPreservesCRDQueries(t *testing.T) {
	discovery := hostIdentityDiscovery{&fake.FakeDiscovery{Fake: &clienttesting.Fake{
		Resources: []*metav1.APIResourceList{
			{GroupVersion: "hostdata.kubescape.cloud/v1beta1", APIResources: []metav1.APIResource{
				{Name: "kubeletinfos", Kind: "KubeletInfo", Verbs: metav1.Verbs{"get", "list"}},
			}},
			{GroupVersion: "example.com/v1beta0", APIResources: []metav1.APIResource{
				{Name: "kubeletinfos", Kind: "KubeletInfo", Verbs: metav1.Verbs{"get", "list"}},
			}},
		},
	}}}
	k8sinterface.InitializeMapResources(discovery)
	t.Cleanup(k8sinterface.InitializeMapResourcesMock)
	resolver, _ := newDiscoveryResourceResolver(discovery)
	for _, tc := range []struct{ group, version, resource string }{
		{"hostdata.kubescape.cloud", "v1beta1", "KubeletInfo"},
		{"hostdata.kubescape.cloud", "v1beta1", "kubeletinfos"},
		{"hostdata.kubescape.cloud", "v1beta1", "*"},
		{"example.com", "v1beta0", "KubeletInfo"},
	} {
		got := resolver(tc.group, tc.version, tc.resource)
		want := tc.group + "/" + tc.version + "/kubeletinfos"
		if len(got) != 1 || got[0].groupVersionResourceTriplet != want || got[0].namespaced == nil {
			t.Errorf("CRD query %v resolved to %v, want %s with discovery scope", tc, got, want)
		}
	}
}
