package mcpserver

import (
	"context"
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	"github.com/kubescape/kubescape/v3/core/pkg/opaprocessor"
	"github.com/kubescape/kubescape/v3/core/pkg/policyhandler"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/resources"
)

// BenchmarkNetworkScan_Isolation measures the OPA engine evaluation overhead for the
// Network Policy control (C-0030) against a representative set of resources.
// Policy download is excluded from timing via b.StopTimer/b.StartTimer, so only the
// actual scan evaluation path — the dominant in-process cost — is benchmarked.
func BenchmarkNetworkScan_Isolation(b *testing.B) {
	ctx := context.Background()

	// Load policies once outside the loop (simulates server-startup policy caching).
	b.StopTimer()
	policyHandler := policyhandler.NewRequestScopedPolicyHandler("")
	defer policyHandler.Close()

	scanInfo := &cautils.ScanInfo{
		Getters: cautils.Getters{
			PolicyGetter:         getter.NewLoadPolicy([]string{"../../core/cautils/getter/testdata/policy.json"}),
			ExceptionsGetter:     getter.NewLoadPolicy([]string{"../../core/cautils/getter/testdata/exceptions.json"}),
			ControlsInputsGetter: getter.NewLoadPolicy([]string{"../../core/cautils/getter/testdata/controls-inputs.json"}),
			AttackTracksGetter:   getter.NewLoadPolicy([]string{"../../core/cautils/getter/testdata/attack-tracks.json"}),
		},
		ScanAll: false,
		PolicyIdentifier: []cautils.PolicyIdentifier{
			{Kind: apisv1.KindControl, Identifier: "C-0030"},
		},
		ScanTimeout: 10 * time.Second,
	}

	// A representative NetworkPolicy resource.
	networkResource := workloadinterface.NewWorkloadObj(map[string]interface{}{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "NetworkPolicy",
		"metadata":   map[string]interface{}{"name": "test-network-policy", "namespace": "default"},
		"spec": map[string]interface{}{
			"podSelector": map[string]interface{}{
				"matchLabels": map[string]interface{}{
					"role": "db",
				},
			},
			"policyTypes": []interface{}{"Ingress"},
			"ingress": []interface{}{
				map[string]interface{}{
					"from": []interface{}{
						map[string]interface{}{
							"ipBlock": map[string]interface{}{
								"cidr": "172.17.0.0/16",
								"except": []interface{}{
									"172.17.1.0/24",
								},
							},
						},
					},
				},
			},
		},
	})

	// A representative Pod resource that matches the NetworkPolicy podSelector
	podResource := workloadinterface.NewWorkloadObj(map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name":      "test-db-pod",
			"namespace": "default",
			"labels": map[string]interface{}{
				"role": "db",
			},
		},
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{
					"name":  "postgres",
					"image": "postgres:13",
				},
			},
		},
	})

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		b.StopTimer()

		// Collect a fresh OPASessionObj per iteration so mutations from the previous
		// run don't bleed into the next one.
		scanData, err := policyHandler.CollectPolicies(ctx, scanInfo.PolicyIdentifier, scanInfo)
		if err != nil {
			b.Fatalf("failed to collect policies: %v", err)
		}

		// Populate AllResources with the representative objects so the engine
		// evaluates the full rule path.
		scanData.AllResources = map[string]workloadinterface.IMetadata{
			networkResource.GetID(): networkResource,
			podResource.GetID():     podResource,
		}

		b.StartTimer()

		deps := resources.NewRegoDependenciesData(nil, "")
		opap := opaprocessor.NewOPAProcessor(scanData, deps, "", "", "", false, nil)

		err = opap.ProcessRulesListener(ctx, cautils.NewProgressHandler(""))
		if err != nil {
			b.Fatalf("ProcessRulesListener failed: %v", err)
		}
	}
}
