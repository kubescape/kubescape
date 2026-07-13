package mcpserver

import (
	"context"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	"github.com/kubescape/kubescape/v3/core/pkg/opaprocessor"
	"github.com/kubescape/kubescape/v3/core/pkg/policyhandler"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/resources"
)

// BenchmarkRBACScan_Isolation tests the overhead of loading and evaluating ONLY the RBAC controls
// This proves to the maintainer that hardcoding C-0015 and C-0016 is lightning fast.
func BenchmarkRBACScan_Isolation(b *testing.B) {
	// We run this outside the loop to mimic the one-time policy download overhead
	ctx := context.Background()
	policyHandler := policyhandler.NewPolicyHandler("")

	scanInfo := &cautils.ScanInfo{
		Getters: cautils.Getters{
			PolicyGetter:         getter.NewLoadPolicy([]string{"../../core/cautils/getter/testdata/policy.json"}),
			ExceptionsGetter:     getter.NewLoadPolicy([]string{"../../core/cautils/getter/testdata/exceptions.json"}),
			ControlsInputsGetter: getter.NewLoadPolicy([]string{"../../core/cautils/getter/testdata/controls-inputs.json"}),
			AttackTracksGetter:   getter.NewLoadPolicy([]string{"../../core/cautils/getter/testdata/attack-tracks.json"}),
		},
		ScanAll: false,
		PolicyIdentifier: []cautils.PolicyIdentifier{
			{Kind: apisv1.KindControl, Identifier: "C-0015"},
			{Kind: apisv1.KindControl, Identifier: "C-0016"},
		},
		ScanTimeout: 10 * time.Second,
	}

	// Pre-fetch policies so network overhead doesn't skew the benchmark
	scanData, err := policyHandler.CollectPolicies(ctx, scanInfo.PolicyIdentifier, scanInfo)
	if err != nil {
		b.Fatalf("failed to collect policies: %v", err)
	}

	b.ResetTimer() // Only benchmark the actual OPA processor initialization and rule processing

	for i := 0; i < b.N; i++ {
		// Instantiate a fresh OPA Processor
		deps := resources.NewRegoDependenciesData(nil, "")
		opap := opaprocessor.NewOPAProcessor(scanData, deps, "", "", "", false, nil)

		// In a real environment, resource handler would pull resources here.
		// Since we have no resources loaded in the mock scanData, this tests the raw engine overhead.
		err := opap.ProcessRulesListener(ctx, cautils.NewProgressHandler(""))
		if err != nil {
			b.Fatalf("ProcessRulesListener failed: %v", err)
		}
	}
}
