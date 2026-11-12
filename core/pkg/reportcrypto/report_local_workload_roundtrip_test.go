package reportcrypto_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kubescape/k8s-interface/cloudsupport"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/anonymizer"
	"github.com/kubescape/kubescape/v4/core/pkg/reportcrypto"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/objectsenvelopes/hostsensor"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/version"
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

// envelopeCase is a catalog resource whose envelope keeps its name somewhere
// other than a plain Kubernetes object does, or builds its ID differently.
type envelopeCase struct {
	name     string
	resource func() workloadinterface.IMetadata
	// namePath is where the serialized object keeps the resource name.
	namePath []string
	// check inspects the decrypted object beyond its name.
	check func(t *testing.T, object map[string]any)
}

var envelopeCases = []envelopeCase{
	{
		// RBAC controls report a subject with its name at the top level,
		// beside the objects that grant it access.
		name: "rbac subject",
		resource: func() workloadinterface.IMetadata {
			return objectsenvelopes.NewRegoResponseVectorObject(map[string]any{
				"apiVersion": "",
				"kind":       "User",
				"name":       "mallory@acme.example",
				"namespace":  "",
				"relatedObjects": []any{map[string]any{
					"apiVersion": "rbac.authorization.k8s.io/v1",
					"kind":       "ClusterRoleBinding",
					"metadata":   map[string]any{"name": "admins"},
				}},
			})
		},
		namePath: []string{"name"},
		check: func(t *testing.T, object map[string]any) {
			assert.Equal(t, "User", object["kind"])
			assert.NotContains(t, object, "metadata", "the subject keeps its own layout")
			related := object["relatedObjects"].([]any)
			require.Len(t, related, 1)
			assert.Equal(t, "ClusterRoleBinding", related[0].(map[string]any)["kind"])
		},
	},
	{
		name: "api server info",
		resource: func() workloadinterface.IMetadata {
			return cloudsupport.NewApiServerVersionInfo(&version.Info{GitVersion: "v1.30.2", Platform: "linux/amd64"})
		},
		namePath: []string{"metadata", "name"},
		check: func(t *testing.T, object map[string]any) {
			assert.Equal(t, "APIServerInfo", object["kind"])
			data := object["data"].(map[string]any)
			assert.Equal(t, "v1.30.2", data["gitVersion"])
			assert.Equal(t, "linux/amd64", data["platform"])
			// The encrypted name was once also left, nested, at
			// data.metadata.name and data.data.metadata.name.
			assert.NotContains(t, data, "metadata")
			assert.NotContains(t, data, "data")
		},
	},
	{
		name: "host sensor data",
		resource: func() workloadinterface.IMetadata {
			return hostsensor.NewHostSensorDataEnvelope(map[string]any{
				"apiVersion": "hostdata.kubescape.cloud/v1beta0",
				"kind":       "KubeletInfo",
				"metadata":   map[string]any{"name": "node-acme-1"},
				"data":       map[string]any{"serviceFiles": []any{}},
			})
		},
		namePath: []string{"metadata", "name"},
		check: func(t *testing.T, object map[string]any) {
			assert.Equal(t, "KubeletInfo", object["kind"])
			assert.Equal(t, map[string]any{"serviceFiles": []any{}}, object["data"])
		},
	},
}

// encryptedReport runs the real producer: ApplyEncrypted, then ToJson, over a
// session in which each resource fails one control.
func encryptedReport(t *testing.T, resources ...workloadinterface.IMetadata) []byte {
	t.Helper()
	catalog := make(map[string]workloadinterface.IMetadata, len(resources))
	results := make(map[string]resourcesresults.Result, len(resources))
	for _, resource := range resources {
		id := resource.GetID()
		catalog[id] = resource
		results[id] = resourcesresults.Result{
			ResourceID: id,
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{{
				ControlID: "C-0035",
				Name:      "Administrative Roles",
				Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
			}},
		}
	}
	session := &cautils.OPASessionObj{
		ResourcesResult: results,
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

// soleResource returns the report's only resource object, after checking that
// its only result names it.
func soleResource(t *testing.T, raw []byte) (string, map[string]any, map[string]any) {
	t.Helper()
	var report map[string]any
	require.NoError(t, json.Unmarshal(raw, &report))
	resources, _ := report["resources"].([]any)
	results, _ := report["results"].([]any)
	require.Len(t, resources, 1, "the report keeps its resource")
	require.Len(t, results, 1)
	resource := resources[0].(map[string]any)
	id := resource["resourceID"].(string)
	assert.Equal(t, id, results[0].(map[string]any)["resourceID"], "the result names the resource")
	return id, resource["object"].(map[string]any), report
}

func stringAt(t *testing.T, object map[string]any, path []string) string {
	t.Helper()
	var current any = object
	for _, key := range path {
		parent, ok := current.(map[string]any)
		require.True(t, ok, "no object at %q of path %v", key, path)
		current = parent[key]
	}
	value, ok := current.(string)
	require.True(t, ok, "%v is %T, not a string", path, current)
	return value
}

// resourceSections returns the report's resources and results, the sections
// that carry resource names and IDs.
func resourceSections(t *testing.T, raw []byte) string {
	t.Helper()
	var report map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &report))
	return string(report["resources"]) + string(report["results"])
}

func TestEncryptedEnvelopeReportRoundTrip(t *testing.T) {
	for _, tc := range envelopeCases {
		t.Run(tc.name, func(t *testing.T) {
			original := tc.resource()
			name := original.GetName()

			encryptedJSON := encryptedReport(t, original)
			encryptedID, object, _ := soleResource(t, encryptedJSON)
			encryptedName := stringAt(t, object, tc.namePath)
			assert.True(t, strings.HasPrefix(encryptedName, "ENC[AES256_GCM,"), "the name at %v is %q", tc.namePath, encryptedName)
			assert.Contains(t, encryptedID, encryptedName, "the resource ID carries the encrypted name")
			assert.NotContains(t, encryptedID, name)
			assert.NotContains(t, resourceSections(t, encryptedJSON), `"`+name+`"`)

			decryptedJSON, err := reportcrypto.DecryptReport(encryptedJSON, []byte(exceptionTestMasterKey))
			require.NoError(t, err)
			require.NotNil(t, decryptedJSON)
			// Only the wrapped DEK in the encryption metadata stays encrypted.
			assert.NotContains(t, resourceSections(t, decryptedJSON), "ENC[")

			decryptedID, object, _ := soleResource(t, decryptedJSON)
			assert.Equal(t, name, stringAt(t, object, tc.namePath))
			assert.Equal(t, tc.resource().GetID(), decryptedID)
			tc.check(t, object)
		})
	}
}

// An RBAC subject's ID is built from its name and its related objects, so the
// decrypted report restores the exact ID the scan gave it.
func TestEncryptedRBACSubjectReportRestoresItsID(t *testing.T) {
	subject := envelopeCases[0].resource()
	decryptedJSON, err := reportcrypto.DecryptReport(encryptedReport(t, subject), []byte(exceptionTestMasterKey))
	require.NoError(t, err)
	id, _, _ := soleResource(t, decryptedJSON)
	assert.Equal(t, "//User/mallory@acme.example/rbac.authorization.k8s.io/v1//ClusterRoleBinding/admins", id)
}

func TestDecryptReportRejectsTamperedEnvelopeName(t *testing.T) {
	for _, tc := range envelopeCases {
		t.Run(tc.name, func(t *testing.T) {
			_, object, report := soleResource(t, encryptedReport(t, tc.resource()))
			parent := object
			for _, key := range tc.namePath[:len(tc.namePath)-1] {
				parent = parent[key].(map[string]any)
			}
			field := tc.namePath[len(tc.namePath)-1]
			name := parent[field].(string)
			end := strings.LastIndex(name, "]")
			parent[field] = name[:end-6] + "AAAA" + name[end:]
			report["resources"].([]any)[0].(map[string]any)["object"] = object
			tampered, err := json.Marshal(report)
			require.NoError(t, err)

			out, err := reportcrypto.DecryptReport(tampered, []byte(exceptionTestMasterKey))
			assert.Error(t, err)
			assert.Nil(t, out)
		})
	}
}

// One scan can hold every kind of resource at once: cluster workloads,
// file-scan manifests and the envelopes above. Each keeps its own resource
// through encryption and decryption.
func TestEncryptedMixedEnvelopeReportRoundTrip(t *testing.T) {
	// ApplyEncrypted writes into the resources it is given, so each stage
	// scans fresh ones.
	scan := func() []workloadinterface.IMetadata {
		resources := []workloadinterface.IMetadata{
			workloadinterface.NewWorkloadObj(map[string]any{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"metadata":   map[string]any{"name": "payroll-api", "namespace": "acme-finance"},
			}),
			localworkload.NewLocalWorkload(map[string]any{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"sourcePath": payrollManifest,
				"metadata":   map[string]any{"name": "payroll-worker", "namespace": "acme-finance"},
			}),
		}
		for _, tc := range envelopeCases {
			resources = append(resources, tc.resource())
		}
		return resources
	}
	wantKinds := map[string]int{"Deployment": 2, "User": 1, "APIServerInfo": 1, "KubeletInfo": 1}

	for _, stage := range []string{"encrypted", "decrypted"} {
		resources := scan()
		raw := encryptedReport(t, resources...)
		if stage == "decrypted" {
			var err error
			raw, err = reportcrypto.DecryptReport(raw, []byte(exceptionTestMasterKey))
			require.NoError(t, err)
		}
		var report reportResources
		require.NoError(t, json.Unmarshal(raw, &report))
		require.Len(t, report.Resources, len(resources), stage)
		require.Len(t, report.Results, len(resources), stage)
		byID := make(map[string]map[string]any, len(report.Resources))
		for _, resource := range report.Resources {
			byID[resource.ResourceID] = resource.Object
		}
		kinds := make(map[string]int)
		for _, result := range report.Results {
			object, ok := byID[result.ResourceID]
			if assert.True(t, ok, "%s: result %q names no resource", stage, result.ResourceID) {
				kinds[object["kind"].(string)]++
			}
		}
		assert.Equal(t, wantKinds, kinds, stage)
	}
}
