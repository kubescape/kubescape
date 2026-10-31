package core

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/kubescape/v4/core/pkg/policyhandler"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/reporthandling"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// releasedExceptionsSource stands in for the GitHub release a REST request
// without an exceptions body reads, so the test stays offline.
type releasedExceptionsSource struct{ name string }

func (r *releasedExceptionsSource) SetRegoObjectsWithFallback() (bool, error) { return false, nil }

func (r *releasedExceptionsSource) GetExceptions(context.Context, string) ([]armotypes.PostureExceptionPolicy, error) {
	return []armotypes.PostureExceptionPolicy{{PortalBase: armotypes.PortalBase{Name: r.name}}}, nil
}

// TestPolicyCacheSourceIsolation pins that scans which resolve the same
// cluster name, and so share one PolicyHandler, only reuse cached exceptions
// and control inputs read from the same source.
func TestPolicyCacheSourceIsolation(t *testing.T) {
	t.Setenv(policyhandler.PoliciesCacheTtlEnvVar, "5m")

	var crdReads atomic.Int64
	withGlobalClusterAPI(t, "global", &crdReads)
	const clusterException = "global-exception/C-0001"

	dir := t.TempDir()
	writeFile := func(name, content string) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		return path
	}
	exceptionFile := func(name, exceptionName string) string {
		b, err := json.Marshal([]armotypes.PostureExceptionPolicy{{PortalBase: armotypes.PortalBase{Name: exceptionName}}})
		require.NoError(t, err)
		return writeFile(name, string(b))
	}
	framework := reporthandling.Framework{Controls: []reporthandling.Control{{ControlID: "C-0001"}}}
	framework.Name = "cache-source-probe"
	frameworkBytes, err := json.Marshal(framework)
	require.NoError(t, err)
	frameworkPath := writeFile("framework.json", string(frameworkBytes))
	defaultInputs := writeFile("controls-inputs.json", `{"probe":["value"]}`)
	identifiers := []cautils.PolicyIdentifier{{Identifier: framework.Name, Kind: apisv1.KindFramework}}

	collect := func(t *testing.T, scanInfo *cautils.ScanInfo, exceptions getter.IExceptionsGetter, controlsInputs string) *cautils.OPASessionObj {
		t.Helper()
		session, err := collectPolicies(context.Background(), t.Name(), identifiers, scanInfo, &cautils.Getters{
			PolicyGetter:         getter.NewLoadPolicy([]string{frameworkPath}),
			ControlsInputsGetter: getter.NewLoadPolicy([]string{controlsInputs}),
			ExceptionsGetter:     exceptions,
		})
		require.NoError(t, err)
		require.Empty(t, session.PolicyDegradations)
		return session
	}
	fileExceptions := func(t *testing.T, path string, clusterScan bool) getter.IExceptionsGetter {
		t.Helper()
		g, _, err := getExceptionsGetterForTarget(context.Background(), path, "", nil, clusterScan, false, nil)
		require.NoError(t, err)
		return g
	}
	names := func(session *cautils.OPASessionObj) []string {
		out := []string{}
		for _, e := range session.Exceptions {
			out = append(out, e.Name)
		}
		return out
	}

	t.Run("different exception files", func(t *testing.T) {
		withException := exceptionFile("exceptions-a.json", "file-a-exception")
		empty := writeFile("exceptions-b.json", `[]`)

		assert.Equal(t, []string{"file-a-exception"}, names(collect(t, &cautils.ScanInfo{}, fileExceptions(t, withException, false), defaultInputs)))
		assert.Equal(t, []string{}, names(collect(t, &cautils.ScanInfo{}, fileExceptions(t, empty, false), defaultInputs)))
	})

	t.Run("request body exceptions then none", func(t *testing.T) {
		// A REST request body becomes scanInfo.UseExceptions; a request without
		// one reads the released exceptions. Both are cluster scans.
		body := exceptionFile("request-body.json", "request-body-exception")
		released, _, err := getReleasedExceptionsGetterForTarget(context.Background(), &releasedExceptionsSource{name: "released-exception"}, true, nil)
		require.NoError(t, err)

		assert.ElementsMatch(t, []string{"request-body-exception", clusterException}, names(collect(t, &cautils.ScanInfo{}, fileExceptions(t, body, true), defaultInputs)))
		assert.ElementsMatch(t, []string{"released-exception", clusterException}, names(collect(t, &cautils.ScanInfo{}, released, defaultInputs)))
	})

	t.Run("different controls-config files", func(t *testing.T) {
		exceptions := fileExceptions(t, writeFile("exceptions-none.json", `[]`), false)
		inputsA := writeFile("controls-inputs-a.json", `{"trustedCosignPublicKeys":["key-a"]}`)
		inputsB := writeFile("controls-inputs-b.json", `{"trustedCosignPublicKeys":["key-b"]}`)

		assert.Equal(t, map[string][]string{"trustedCosignPublicKeys": {"key-a"}}, collect(t, &cautils.ScanInfo{}, exceptions, inputsA).RegoInputData.PostureControlInputs)
		assert.Equal(t, map[string][]string{"trustedCosignPublicKeys": {"key-b"}}, collect(t, &cautils.ScanInfo{}, exceptions, inputsB).RegoInputData.PostureControlInputs)
	})

	t.Run("same source is reused with its provenance", func(t *testing.T) {
		exceptionsPath := exceptionFile("exceptions-same.json", "same-source-v1")
		inputsPath := writeFile("controls-inputs-same.json", `{"probe":["same-source-v1"]}`)
		newScanInfo := func() *cautils.ScanInfo {
			return &cautils.ScanInfo{ScanContract: &reporthandlingv2.ScanContractMetadata{
				APIVersion:     "config.kubescape.io/v1alpha1",
				Contract:       "ci",
				DigestSchema:   "kubescape-scan-contract:v1",
				ContractDigest: "sha256:contract",
			}}
		}

		first := collect(t, newScanInfo(), fileExceptions(t, exceptionsPath, true), inputsPath)
		crdReads.Store(0)
		// Within the TTL a source keeps serving what it returned first, even
		// if the file at that path changes.
		exceptionFile("exceptions-same.json", "same-source-v2")
		writeFile("controls-inputs-same.json", `{"probe":["same-source-v2"]}`)
		second := collect(t, newScanInfo(), fileExceptions(t, exceptionsPath, true), inputsPath)

		assert.ElementsMatch(t, []string{"same-source-v1", clusterException}, names(second))
		assert.Equal(t, map[string][]string{"probe": {"same-source-v1"}}, second.RegoInputData.PostureControlInputs)
		assert.Zero(t, crdReads.Load(), "the second scan should be served from the cache")
		require.NotNil(t, first.Metadata.ScanMetadata.ScanContract)
		require.Len(t, first.Metadata.ScanMetadata.ScanContract.RunnerInputs, 2)
		assert.Equal(t, first.Metadata.ScanMetadata.ScanContract.RunnerInputs, second.Metadata.ScanMetadata.ScanContract.RunnerInputs)
	})
}
