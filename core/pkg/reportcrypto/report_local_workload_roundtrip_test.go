package reportcrypto_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/anonymizer"
	"github.com/kubescape/kubescape/v4/core/pkg/reportcrypto"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	payrollManifest = "/home/alice/acme-payroll-repo/deploy/payroll.yaml"
	ledgerManifest  = "/home/alice/acme-payroll-repo/deploy/ledger.yaml"
)

type fileScanResource struct {
	name, namespace, sourcePath string
}

// fileScanResources are two documents of one manifest and one of another, as
// a directory scan loads them.
var fileScanResources = []fileScanResource{
	{name: "payroll-api", namespace: "acme-finance", sourcePath: payrollManifest},
	{name: "payroll-worker", namespace: "acme-finance", sourcePath: payrollManifest},
	{name: "ledger-api", namespace: "acme-ledger", sourcePath: ledgerManifest},
}

func encryptedFileScanReport(t *testing.T) []byte {
	t.Helper()
	catalog := make(map[string]workloadinterface.IMetadata)
	results := make(map[string]resourcesresults.Result)
	sources := make(map[string]reporthandling.Source)
	for _, resource := range fileScanResources {
		workload := localworkload.NewLocalWorkload(map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"sourcePath": resource.sourcePath,
			"metadata":   map[string]any{"name": resource.name, "namespace": resource.namespace},
		})
		id := workload.GetID()
		require.True(t, strings.HasPrefix(id, "path="), id)
		catalog[id] = workload
		results[id] = resourcesresults.Result{
			ResourceID: id,
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{{
				ControlID: "C-0012",
				Name:      "Applications credentials in configuration files",
				Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
			}},
		}
		sources[id] = reporthandling.Source{Path: "/home/alice/acme-payroll-repo", RelativePath: strings.TrimPrefix(resource.sourcePath, "/home/alice/acme-payroll-repo/")}
	}
	session := &cautils.OPASessionObj{
		ResourcesResult: results,
		ResourceSource:  sources,
		Metadata:        &reporthandlingv2.Metadata{},
		Report:          &reporthandlingv2.PostureReport{},
	}
	session.SetCatalog(cautils.NewMapResourceCatalog(catalog))

	handler := &resultshandling.ResultsHandler{ScanData: session}
	dek, err := reportcrypto.GenerateDEK()
	require.NoError(t, err)
	require.NoError(t, anonymizer.ApplyEncrypted(handler, dek, []byte(exceptionTestMasterKey)))
	encrypted, err := handler.ToJson()
	require.NoError(t, err)
	return encrypted
}

type reportResources struct {
	Results []struct {
		ResourceID string `json:"resourceID"`
	} `json:"results"`
	Resources []struct {
		ResourceID string         `json:"resourceID"`
		Object     map[string]any `json:"object"`
	} `json:"resources"`
}

// resolveResults returns each result's resource object, failing the test for
// a result that names no resource in the report.
func resolveResults(t *testing.T, raw []byte, where string) []map[string]any {
	t.Helper()
	var report reportResources
	require.NoError(t, json.Unmarshal(raw, &report))
	require.Len(t, report.Results, len(fileScanResources), where)
	require.Len(t, report.Resources, len(fileScanResources), where)
	byID := make(map[string]map[string]any, len(report.Resources))
	for _, resource := range report.Resources {
		byID[resource.ResourceID] = resource.Object
	}
	objects := make([]map[string]any, 0, len(report.Results))
	for _, result := range report.Results {
		object, ok := byID[result.ResourceID]
		require.True(t, ok, "%s: result %q names no resource", where, result.ResourceID)
		objects = append(objects, object)
	}
	return objects
}

func TestEncryptedFileScanReportRoundTripKeepsResources(t *testing.T) {
	encryptedJSON := encryptedFileScanReport(t)
	for _, secret := range []string{"alice", "acme-payroll-repo", "payroll-api", "payroll-worker", "ledger-api", "acme-finance", "acme-ledger"} {
		assert.NotContains(t, string(encryptedJSON), secret)
	}
	for _, object := range resolveResults(t, encryptedJSON, "encrypted report") {
		assert.Equal(t, "Deployment", object["kind"])
		assert.Contains(t, object["sourcePath"], "ENC[AES256_GCM,")
	}

	decryptedJSON, err := reportcrypto.DecryptReport(encryptedJSON, []byte(exceptionTestMasterKey))
	require.NoError(t, err)

	restored := make(map[string]fileScanResource)
	for _, object := range resolveResults(t, decryptedJSON, "decrypted report") {
		metadata := object["metadata"].(map[string]any)
		name := metadata["name"].(string)
		restored[name] = fileScanResource{name: name, namespace: metadata["namespace"].(string), sourcePath: object["sourcePath"].(string)}
	}
	want := make(map[string]fileScanResource, len(fileScanResources))
	for _, resource := range fileScanResources {
		want[resource.name] = resource
	}
	// Each manifest path is encrypted on its own, so two documents of one file
	// carry different ciphertext; both decrypt to the same path.
	assert.Equal(t, want, restored)
}

func TestDecryptReportRejectsTamperedFileScanResource(t *testing.T) {
	encryptedJSON := encryptedFileScanReport(t)
	var report map[string]any
	require.NoError(t, json.Unmarshal(encryptedJSON, &report))
	object := report["resources"].([]any)[0].(map[string]any)["object"].(map[string]any)
	name := object["metadata"].(map[string]any)["name"].(string)
	require.True(t, strings.HasPrefix(name, "ENC["), name)
	end := strings.LastIndex(name, "]")
	object["metadata"].(map[string]any)["name"] = name[:end-6] + "AAAA" + name[end:]
	tampered, err := json.Marshal(report)
	require.NoError(t, err)

	out, err := reportcrypto.DecryptReport(tampered, []byte(exceptionTestMasterKey))
	assert.Error(t, err)
	assert.Nil(t, out)
}
