package anonymizer

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubescape/k8s-interface/cloudsupport"
	cloudsupportv1 "github.com/kubescape/k8s-interface/cloudsupport/v1"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	printerv2 "github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/objectsenvelopes/hostsensor"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/version"
)

const (
	identityControlID   = "C-0012"
	identityControlName = "Applications credentials in configuration files"
	identityDescription = "Attackers who can read the manifest can read the credentials in it."
	identityRemediation = "Use Kubernetes secrets or Key Management Systems to store credentials."
	identityManifest    = "/home/alice/acme-payroll-repo/deploy/payroll.yaml"
	identityOtherFile   = "/home/alice/acme-payroll-repo/deploy/ledger.yaml"
)

// The resource names, namespaces and manifest paths these tests anonymize,
// which a hidden or encrypted report must not contain in any form.
var identitySecrets = []string{"alice", "acme-payroll-repo", "payroll-api", "payroll-worker", "ledger-api", "acme-finance", "gke-acme-prod", "node-acme-1", "eks-acme-prod", "mallory@acme.example", "admins", "viewers", "acme-sec", "privileged-role", "viewer-role"}

func localDeployment(name, path string) *localworkload.LocalWorkload {
	return localworkload.NewLocalWorkload(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"sourcePath": path,
		"metadata":   map[string]any{"name": name, "namespace": "acme-finance"},
		"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
			"containers": []any{map[string]any{"name": "app", "image": "nginx:1.27"}},
		}}},
	})
}

func clusterDeployment() workloadinterface.IMetadata {
	return workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "payroll-api", "namespace": "acme-finance"},
	})
}

func hostSensorData() workloadinterface.IMetadata {
	return hostsensor.NewHostSensorDataEnvelope(map[string]any{
		"apiVersion": "hostdata.kubescape.cloud/v1beta0",
		"kind":       "KubeletInfo",
		"metadata":   map[string]any{"name": "node-acme-1"},
		"data":       map[string]any{"serviceFiles": []any{}},
	})
}

func cloudProviderData() workloadinterface.IMetadata {
	return cloudsupportv1.NewDescriptiveInfoFromCloudProvider(map[string]any{
		"apiVersion": "container.googleapis.com/v1",
		"kind":       "ClusterDescribe",
		"metadata":   map[string]any{"name": "gke-acme-prod", "provider": "gke"},
		"data":       map[string]any{"status": "RUNNING"},
	})
}

func cloudMetadata(name string) cloudsupportv1.CloudProviderMetadata {
	var metadata cloudsupportv1.CloudProviderMetadata
	metadata.Name = name
	metadata.Provider = "eks"
	return metadata
}

func apiServerInfo() *cloudsupport.ApiServerInfo {
	return cloudsupport.NewApiServerVersionInfo(&version.Info{GitVersion: "v1.30.2", Platform: "linux/amd64"})
}

// rbacSubject is the shape RBAC controls report a subject in: the name sits at
// the top level, beside the objects that grant it access.
func rbacSubject() workloadinterface.IMetadata {
	return objectsenvelopes.NewRegoResponseVectorObject(map[string]any{
		"apiVersion": "",
		"kind":       "User",
		"name":       "mallory@acme.example",
		"namespace":  "",
		"relatedObjects": []any{
			map[string]any{
				"apiVersion": "rbac.authorization.k8s.io/v1",
				"kind":       "ClusterRoleBinding",
				"metadata":   map[string]any{"name": "admins"},
				"subjects": []any{
					map[string]any{"kind": "User", "name": "alice"},
				},
				"roleRef": map[string]any{
					"kind": "ClusterRole",
					"name": "privileged-role",
				},
			},
			map[string]any{
				"apiVersion": "rbac.authorization.k8s.io/v1",
				"kind":       "RoleBinding",
				"metadata":   map[string]any{"name": "viewers", "namespace": "acme-sec"},
				"subjects": []any{
					map[string]any{"kind": "ServiceAccount", "name": "payroll-worker", "namespace": "acme-sec"},
				},
				"roleRef": map[string]any{
					"kind": "Role",
					"name": "viewer-role",
				},
			},
			map[string]any{
				"apiVersion": "rbac.authorization.k8s.io/v1",
				"kind":       "RoleBinding",
				"sourcePath": identityManifest + ":4",
				"metadata":   map[string]any{"name": "viewers", "namespace": "acme-sec"},
				"subjects": []any{
					map[string]any{"kind": "User", "name": "alice"},
				},
				"roleRef": map[string]any{
					"kind": "Role",
					"name": "viewer-role",
				},
			},
		},
	})
}

// everyCatalogEnvelope has one resource of each envelope type a scan puts in
// the catalog: Kubernetes objects, file-scan manifests, host-sensor data,
// cloud-provider data, API server info and RBAC subjects.
func everyCatalogEnvelope() map[string]workloadinterface.IMetadata {
	return map[string]workloadinterface.IMetadata{
		"cluster workload":   clusterDeployment(),
		"base object":        workloadinterface.NewBaseObject(map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "cm", "namespace": "acme-finance"}}),
		"file-scan workload": localDeployment("ledger-api", identityOtherFile),
		"host sensor data":   hostSensorData(),
		"cloud describe":     cloudProviderData(),
		"cloud repositories": &cloudsupportv1.CloudProviderDescribeRepositories{ApiVersion: "eks.amazonaws.com/v1", Kind: "DescribeRepositories", Metadata: cloudMetadata("eks-acme-prod"), Data: map[string]any{}},
		"cloud entities":     &cloudsupportv1.CloudProviderListEntitiesForPolicies{ApiVersion: "eks.amazonaws.com/v1", Kind: "ListEntitiesForPolicies", Metadata: cloudMetadata("eks-acme-prod"), Data: map[string]any{}},
		"cloud policy":       &cloudsupportv1.CloudProviderPolicyVersion{ApiVersion: "eks.amazonaws.com/v1", Kind: "PolicyVersion", Metadata: cloudMetadata("eks-acme-prod"), Data: map[string]any{}},
		"api server info":    apiServerInfo(),
		"rbac subject":       rbacSubject(),
	}
}

// customIDResource is an envelope the anonymizer does not know, with an ID of
// its own.
type customIDResource struct {
	*workloadinterface.Workload
}

func (r *customIDResource) GetID() string { return "custom/" + r.GetName() }

// identitySession is a scan of the given resources in which each one fails
// identityControlID, laid out the way the processor leaves a session: results,
// sources and the control summary all keyed by the resource's own ID.
func identitySession(resources ...workloadinterface.IMetadata) *cautils.OPASessionObj {
	catalog := make(map[string]workloadinterface.IMetadata, len(resources))
	results := make(map[string]resourcesresults.Result, len(resources))
	sources := make(map[string]reporthandling.Source)
	control := reportsummary.ControlSummary{
		ControlID:   identityControlID,
		Name:        identityControlName,
		Description: identityDescription,
		Remediation: identityRemediation,
		ScoreFactor: 8,
		StatusInfo:  apis.StatusInfo{InnerStatus: apis.StatusFailed},
	}
	control.ResourceIDs.Initialize(len(resources))
	for _, resource := range resources {
		id := resource.GetID()
		catalog[id] = resource
		results[id] = resourcesresults.Result{
			ResourceID: id,
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{{
				ControlID: identityControlID,
				Name:      identityControlName,
				Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
			}},
		}
		if local, ok := resource.(*localworkload.LocalWorkload); ok {
			sources[id] = reporthandling.Source{Path: filepath.Dir(local.GetPath()), RelativePath: filepath.Base(local.GetPath()), FileType: "yaml"}
		}
		control.ResourceIDs.Append(apis.StatusFailed, id)
	}

	session := &cautils.OPASessionObj{
		ResourcesResult: results,
		ResourceSource:  sources,
		Metadata:        &reporthandlingv2.Metadata{},
		Report: &reporthandlingv2.PostureReport{
			SummaryDetails: reportsummary.SummaryDetails{
				Controls: reportsummary.ControlSummaries{identityControlID: control},
				Frameworks: []reportsummary.FrameworkSummary{{
					Name:     "acme-framework",
					Controls: reportsummary.ControlSummaries{identityControlID: control},
				}},
			},
		},
	}
	session.SetCatalog(cautils.NewMapResourceCatalog(catalog))
	return session
}

type anonymizationMode struct {
	name  string
	apply func(t *testing.T, session *cautils.OPASessionObj)
}

var anonymizationModes = []anonymizationMode{
	{name: "hide", apply: func(t *testing.T, session *cautils.OPASessionObj) {
		require.NoError(t, Apply(&resultshandling.ResultsHandler{ScanData: session}))
	}},
	{name: "encrypt", apply: func(t *testing.T, session *cautils.OPASessionObj) {
		dek := make([]byte, 32)
		for i := range dek {
			dek[i] = byte(i + 1)
		}
		require.NoError(t, ApplyEncrypted(&resultshandling.ResultsHandler{ScanData: session}, dek, []byte("01234567890123456789012345678901")))
	}},
}

// assertResultsResolve checks the association every printer depends on: each
// result is keyed by the ID of a catalog resource, and that resource reports
// the same ID itself.
func assertResultsResolve(t *testing.T, session *cautils.OPASessionObj) {
	t.Helper()
	require.Equal(t, len(session.ResourcesResult), session.GetCatalog().Len(), "every result keeps its resource")
	for id, result := range session.ResourcesResult {
		assert.Equal(t, id, result.ResourceID)
		resource, ok := session.GetResource(id)
		if assert.True(t, ok, "result %q has no resource in the catalog", id) {
			assert.Equal(t, id, resource.GetID(), "the resource stored under %q reports another ID", id)
		}
	}
}

func TestCloneCatalogKeepsResourceEnvelopeAndID(t *testing.T) {
	for name, original := range everyCatalogEnvelope() {
		t.Run(name, func(t *testing.T) {
			id := original.GetID()
			resources, originalByClone, err := cloneCatalog(cautils.NewMapResourceCatalog(map[string]workloadinterface.IMetadata{id: original}))
			require.NoError(t, err)

			cloned := resources[id]
			require.NotNil(t, cloned)
			assert.Same(t, original, originalByClone[cloned])
			assert.Equal(t, id, cloned.GetID(), "the clone must have the original's ID")
			if _, isBase := original.(*workloadinterface.BaseObject); !isBase {
				envelope := cloned
				if working, ok := cloned.(*apiServerInfoClone); ok {
					envelope = working.ApiServerInfo
				}
				assert.IsType(t, original, envelope, "the clone must keep the original's envelope")
			}

			cloned.SetName("changed")
			assert.Equal(t, id, original.GetID(), "changing the clone must not change the original")
		})
	}
}

func TestTransformSessionRefusesEnvelopeItCannotCopy(t *testing.T) {
	// A generic copy of an unknown envelope has another ID. Committing it
	// would leave a result that resolves to no resource, so the transaction
	// fails and leaves the session as it was.
	custom := &customIDResource{Workload: workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "payroll-api", "namespace": "acme-finance"},
	})}
	session := identitySession(localDeployment("ledger-api", identityOtherFile), custom)
	before := snapshotTransformState(t, session)

	err := transformSession(session, NewMapping(), NewMappingTransformer())

	require.ErrorContains(t, err, "cannot copy its *anonymizer.customIDResource envelope without changing its ID")
	assert.JSONEq(t, string(before), string(snapshotTransformState(t, session)))
	assertResultsResolve(t, session)
}

func TestAnonymizationKeepsResultsResolvable(t *testing.T) {
	for _, mode := range anonymizationModes {
		t.Run(mode.name, func(t *testing.T) {
			originals := []workloadinterface.IMetadata{
				localDeployment("payroll-api", identityManifest),
				localDeployment("payroll-worker", identityManifest),
			}
			for _, resource := range everyCatalogEnvelope() {
				originals = append(originals, resource)
			}
			originalTypes := make(map[string]int)
			for _, resource := range originals {
				originalTypes[fmt.Sprintf("%T", resource)]++
			}
			session := identitySession(originals...)

			mode.apply(t, session)

			assertResultsResolve(t, session)
			transformedTypes := make(map[string]int)
			for _, resource := range session.GetCatalog().All() {
				transformedTypes[fmt.Sprintf("%T", resource)]++
			}
			assert.Equal(t, originalTypes, transformedTypes, "resources keep their envelopes")

			for id := range session.ResourcesResult {
				for _, secret := range identitySecrets {
					assert.NotContains(t, id, secret)
				}
			}
			for _, resource := range session.GetCatalog().All() {
				encoded, err := json.Marshal(resource.GetObject())
				require.NoError(t, err)
				for _, secret := range identitySecrets {
					assert.NotContains(t, string(encoded), secret, "%s still names %q", resource.GetKind(), secret)
				}
				if rego, ok := resource.(*objectsenvelopes.RegoResponseVectorObject); ok {
					related := rego.GetRelatedObjects()
					require.Len(t, related, 3, "related objects remain present")
					for _, rel := range related {
						assert.NotEmpty(t, rel.GetName(), "related object has transformed name")
						relObj := rel.GetObject()
						rawSubjects := relObj["subjects"].([]any)
						require.NotEmpty(t, rawSubjects, "related binding subjects remain present")
						subjectMap := rawSubjects[0].(map[string]any)
						roleRefMap := relObj["roleRef"].(map[string]any)

						if mode.name == "hide" {
							assert.True(t, strings.HasPrefix(rel.GetName(), "res-"), "related object name is transformed")
							assert.True(t, strings.HasPrefix(subjectMap["name"].(string), "res-"), "related subject name is transformed")
							assert.True(t, strings.HasPrefix(roleRefMap["name"].(string), "res-"), "related roleRef name is transformed")
							if rel.GetKind() == "RoleBinding" {
								assert.True(t, strings.HasPrefix(rel.GetNamespace(), "ns-"), "related object namespace is transformed")
							}
							if ns, ok := subjectMap["namespace"].(string); ok && ns != "" {
								assert.True(t, strings.HasPrefix(ns, "ns-"), "related subject namespace is transformed")
							}
							if lw, isLW := rel.(*localworkload.LocalWorkload); isLW {
								assert.True(t, strings.HasPrefix(lw.GetPath(), "src-"), "related local workload sourcePath is transformed")
								assert.True(t, strings.HasSuffix(lw.GetPath(), ":4"), "related local workload line suffix is preserved")
							}
						} else {
							assert.True(t, strings.HasPrefix(rel.GetName(), "ENC["), "related object name is encrypted")
							assert.True(t, strings.HasPrefix(subjectMap["name"].(string), "ENC["), "related subject name is encrypted")
							assert.True(t, strings.HasPrefix(roleRefMap["name"].(string), "ENC["), "related roleRef name is encrypted")
							if rel.GetKind() == "RoleBinding" {
								assert.True(t, strings.HasPrefix(rel.GetNamespace(), "ENC["), "related object namespace is encrypted")
							}
							if ns, ok := subjectMap["namespace"].(string); ok && ns != "" {
								assert.True(t, strings.HasPrefix(ns, "ENC["), "related subject namespace is encrypted")
							}
							if lw, isLW := rel.(*localworkload.LocalWorkload); isLW {
								assert.True(t, strings.HasPrefix(lw.GetPath(), "ENC["), "related local workload sourcePath is encrypted")
								assert.True(t, strings.HasSuffix(lw.GetPath(), ":4"), "related local workload line suffix is preserved")
							}
						}
					}
				}
			}
		})
	}
}

func TestAnonymizationKeepsSharedManifestPathConsistent(t *testing.T) {
	for _, mode := range anonymizationModes {
		t.Run(mode.name, func(t *testing.T) {
			// --hide maps one value to one pseudonym. --encrypt encrypts each
			// occurrence with its own nonce, so only --hide keeps the files
			// grouped; both must keep three distinct, resolvable resources.
			session := identitySession(
				localDeployment("payroll-api", identityManifest),
				localDeployment("payroll-worker", identityManifest),
				localDeployment("ledger-api", identityOtherFile),
			)

			mode.apply(t, session)

			assertResultsResolve(t, session)
			pathOf := make(map[string]string)
			for _, resource := range session.GetCatalog().All() {
				local, ok := resource.(*localworkload.LocalWorkload)
				require.True(t, ok)
				assert.True(t, strings.HasPrefix(local.GetID(), "path="), local.GetID())
				pathOf[local.GetID()] = local.GetPath()
			}
			require.Len(t, pathOf, 3, "three resources stay three distinct resources")

			// Two resources from one manifest still share one (transformed)
			// path, and the third keeps a different one.
			distinct := make(map[string]int)
			for _, path := range pathOf {
				assert.NotEqual(t, identityManifest, path)
				assert.NotEqual(t, identityOtherFile, path)
				distinct[path]++
			}
			counts := make([]int, 0, len(distinct))
			for _, count := range distinct {
				counts = append(counts, count)
			}
			if mode.name == "hide" {
				assert.ElementsMatch(t, []int{2, 1}, counts)
			}
		})
	}
}

func TestAnonymizationKeepsClusterResourceIdentity(t *testing.T) {
	for _, mode := range anonymizationModes {
		t.Run(mode.name, func(t *testing.T) {
			session := identitySession(clusterDeployment())

			mode.apply(t, session)

			assertResultsResolve(t, session)
			for id, resource := range session.GetCatalog().All() {
				assert.IsType(t, &workloadinterface.Workload{}, resource)
				assert.False(t, strings.HasPrefix(id, "path="), id)
				assert.True(t, strings.HasPrefix(id, "apps/v1/"), id)
				assert.Equal(t, "Deployment", resource.GetKind())
			}
		})
	}
}

func TestAnonymizationKeepsControlDescriptionAndRemediation(t *testing.T) {
	for _, mode := range anonymizationModes {
		t.Run(mode.name, func(t *testing.T) {
			session := identitySession(localDeployment("payroll-api", identityManifest))

			mode.apply(t, session)

			summaries := map[string]reportsummary.ControlSummaries{
				"controls":           session.Report.SummaryDetails.Controls,
				"framework controls": session.Report.SummaryDetails.Frameworks[0].Controls,
			}
			for name, controls := range summaries {
				control := controls[identityControlID]
				assert.Equal(t, identityDescription, control.Description, name)
				assert.Equal(t, identityRemediation, control.Remediation, name)
				assert.Len(t, control.ResourceIDs.All(), 1, name)
				for id := range control.ResourceIDs.All() {
					_, ok := session.GetResource(id)
					assert.True(t, ok, "%s: resource ID %q does not resolve", name, id)
				}
			}
		})
	}
}

func TestTransformSessionRollsBackFileScanSession(t *testing.T) {
	for name, failure := range map[string]struct{ prefix, value string }{
		"second resource name": {prefix: "res", value: "ledger-api"},
		"manifest path":        {prefix: "src", value: identityOtherFile},
	} {
		t.Run(name, func(t *testing.T) {
			originals := []workloadinterface.IMetadata{
				localDeployment("payroll-api", identityManifest),
				localDeployment("ledger-api", identityOtherFile),
				hostSensorData(),
			}
			session := identitySession(originals...)
			before := snapshotTransformState(t, session)
			catalogBefore := session.GetCatalog().All()

			err := transformSession(session, NewMapping(), &selectiveFailTransformer{
				delegate: NewMappingTransformer(), failPrefix: failure.prefix, failValue: failure.value,
			})

			require.ErrorIs(t, err, errInjectedTransform)
			assert.JSONEq(t, string(before), string(snapshotTransformState(t, session)))
			catalogAfter := session.GetCatalog().All()
			require.Len(t, catalogAfter, len(catalogBefore))
			for id, original := range catalogBefore {
				assert.Same(t, original, catalogAfter[id], "the catalog entry for %q was replaced", id)
				assert.Equal(t, id, original.GetID(), "the original resource behind %q was changed", id)
			}
			assertResultsResolve(t, session)
		})
	}
}

// API server info keeps its fields in a typed envelope whose ID has no
// namespace segment, so a generic copy changed its ID and its result no longer
// resolved. Its SetObject stores what it is given as its data, so the
// transform helpers' GetObject/SetObject round trips must not nest the object
// inside its own data: the report keeps the name at metadata.name only, where
// DecryptReport restores it.
func TestAnonymizationKeepsAPIServerInfoResolvable(t *testing.T) {
	for _, mode := range anonymizationModes {
		t.Run(mode.name, func(t *testing.T) {
			info := apiServerInfo()
			session := identitySession(info)

			mode.apply(t, session)

			assertResultsResolve(t, session)
			resource, ok := session.GetResource(info.GetID())
			require.True(t, ok)
			assert.Same(t, info, resource)
			assert.Equal(t, cloudsupport.ApiServerInfoApiVersion, info.GetApiVersion())
			assert.Equal(t, "APIServerInfo", info.GetKind())
			assert.NotEqual(t, "version", info.GetName(), "the name is anonymized")
			object := info.GetObject()
			assert.Equal(t, map[string]any{"name": info.GetName()}, object["metadata"])
			data, ok := object["data"].(map[string]any)
			require.True(t, ok, "data is %T", object["data"])
			assert.Equal(t, "v1.30.2", data["gitVersion"])
			assert.NotContains(t, data, "metadata", "the object is not nested inside its own data")
			assert.NotContains(t, data, "data", "the object is not nested inside its own data")
		})
	}
}

// SetObject cannot return an error, so an object the API server info working
// copy cannot decode is kept and fails the commit before anything is written.
func TestCommitRefusesAPIServerInfoItCouldNotDecode(t *testing.T) {
	original := apiServerInfo()
	cloned, err := cloneResourceEnvelope(original, original.GetObject())
	require.NoError(t, err)
	working, ok := cloned.(*apiServerInfoClone)
	require.True(t, ok, "the working copy is a %T", cloned)

	working.SetObject(map[string]any{"metadata": "not an object"})
	working.SetName("changed")

	write, err := commitResourceEnvelope(original, working)
	require.Error(t, err)
	assert.Nil(t, write)
	assert.Equal(t, "version", original.GetName(), "the original is not changed")
}

// The printers below read resources through the catalog, keyed by result ID.
// When those keys stopped agreeing, a hidden report kept its results but lost
// what they are about.
func TestHiddenFileScanReportsKeepResources(t *testing.T) {
	for _, hide := range []bool{false, true} {
		t.Run(fmt.Sprintf("hide=%v", hide), func(t *testing.T) {
			session := identitySession(
				localDeployment("payroll-api", identityManifest),
				localDeployment("ledger-api", identityOtherFile),
			)
			if hide {
				anonymizationModes[0].apply(t, session)
			}
			reports := printIdentityReports(t, session)

			for _, format := range []string{"json", "yaml"} {
				var report struct {
					Results []struct {
						ResourceID string `json:"resourceID" yaml:"resourceID"`
					} `json:"results" yaml:"results"`
					Resources []struct {
						ResourceID string         `json:"resourceID" yaml:"resourceID"`
						Object     map[string]any `json:"object" yaml:"object"`
					} `json:"resources" yaml:"resources"`
				}
				if format == "json" {
					require.NoError(t, json.Unmarshal([]byte(reports[format]), &report))
				} else {
					require.NoError(t, yaml.Unmarshal([]byte(reports[format]), &report))
				}
				require.Len(t, report.Results, 2, format)
				require.Len(t, report.Resources, 2, format)
				resourceIDs := make(map[string]map[string]any)
				for _, resource := range report.Resources {
					resourceIDs[resource.ResourceID] = resource.Object
				}
				for _, result := range report.Results {
					object, ok := resourceIDs[result.ResourceID]
					if assert.True(t, ok, "%s result %q has no resource", format, result.ResourceID) {
						assert.Equal(t, "Deployment", object["kind"], format)
					}
				}
			}

			policyReport := reports["policyreport"]
			assert.Equal(t, 2, strings.Count(policyReport, "result: fail"), policyReport)
			assert.Equal(t, 2, strings.Count(policyReport, "kind: Deployment"), policyReport)
			assert.Contains(t, policyReport, "message: "+identityDescription)

			rows, err := csv.NewReader(strings.NewReader(reports["csv"])).ReadAll()
			require.NoError(t, err)
			require.Len(t, rows, 3, "a header and one row per failing resource")
			column := make(map[string]int)
			for i, name := range rows[0] {
				column[name] = i
			}
			names := make([]string, 0, 2)
			for _, row := range rows[1:] {
				assert.Equal(t, "Deployment", row[column["Resource Kind"]])
				assert.Equal(t, "apps/v1", row[column["API Version"]])
				assert.Equal(t, identityRemediation, row[column["Remediation"]])
				assert.NotEmpty(t, row[column["Resource Namespace"]])
				names = append(names, row[column["Resource Name"]])
			}

			if hide {
				for format, output := range reports {
					for _, secret := range identitySecrets {
						assert.NotContains(t, output, secret, "hidden %s report names %q", format, secret)
					}
				}
				for _, name := range names {
					assert.True(t, strings.HasPrefix(name, "res-"), name)
				}
			} else {
				assert.ElementsMatch(t, []string{"payroll-api", "ledger-api"}, names)
				assert.Contains(t, reports["json"], "acme-finance")
			}
		})
	}
}

func printIdentityReports(t *testing.T, session *cautils.OPASessionObj) map[string]string {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	printers := map[string]interface {
		SetWriter(context.Context, string) error
		ActionPrint(context.Context, *cautils.OPASessionObj, []cautils.ImageScanData) error
		CloseWriter() error
	}{
		"json":         printerv2.NewJsonPrinter(),
		"yaml":         printerv2.NewYamlPrinter(),
		"policyreport": printerv2.NewPolicyReportPrinter(),
		"csv":          printerv2.NewCsvPrinter(false),
	}
	outputs := make(map[string]string, len(printers))
	for format, printer := range printers {
		path := filepath.Join(dir, format+"-report"+map[string]string{"json": ".json", "yaml": ".yaml", "policyreport": ".yaml", "csv": ".csv"}[format])
		require.NoError(t, printer.SetWriter(ctx, path), format)
		require.NoError(t, printer.ActionPrint(ctx, session, nil), format)
		require.NoError(t, printer.CloseWriter(), format)
		data, err := os.ReadFile(path)
		require.NoError(t, err, format)
		outputs[format] = string(data)
	}
	return outputs
}

func TestAnonymizationHidesRBACBindingReferencesConsistently(t *testing.T) {
	subject := objectsenvelopes.NewRegoResponseVectorObject(map[string]any{
		"apiVersion": "",
		"kind":       "User",
		"name":       "alice",
		"namespace":  "",
		"relatedObjects": []any{
			map[string]any{
				"apiVersion": "rbac.authorization.k8s.io/v1",
				"kind":       "Role",
				"metadata":   map[string]any{"name": "viewer-role", "namespace": "acme-sec"},
			},
			map[string]any{
				"apiVersion": "rbac.authorization.k8s.io/v1",
				"kind":       "RoleBinding",
				"metadata":   map[string]any{"name": "viewers", "namespace": "acme-sec"},
				"subjects": []any{
					map[string]any{"kind": "User", "name": "alice"},
					map[string]any{"kind": "ServiceAccount", "name": "payroll-worker", "namespace": "acme-sec"},
				},
				"roleRef": map[string]any{
					"apiGroup": "rbac.authorization.k8s.io",
					"kind":     "Role",
					"name":     "viewer-role",
				},
			},
		},
	})

	topLevelBinding := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRoleBinding",
		"metadata":   map[string]any{"name": "admins"},
		"subjects": []any{
			map[string]any{"kind": "User", "name": "alice"},
		},
		"roleRef": map[string]any{
			"apiGroup": "rbac.authorization.k8s.io",
			"kind":     "ClusterRole",
			"name":     "privileged-role",
		},
	})

	serviceAccount := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "ServiceAccount",
		"metadata":   map[string]any{"name": "payroll-worker", "namespace": "acme-sec"},
	})

	clusterRole := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRole",
		"metadata":   map[string]any{"name": "privileged-role"},
	})

	session := identitySession(subject, topLevelBinding, serviceAccount, clusterRole)
	require.NoError(t, Apply(&resultshandling.ResultsHandler{ScanData: session}))

	jsonOut := printIdentityReports(t, session)["json"]
	for _, secret := range []string{"alice", "viewer-role", "viewers", "acme-sec", "payroll-worker", "admins", "privileged-role"} {
		assert.NotContains(t, jsonOut, secret)
	}

	var anonSubject *objectsenvelopes.RegoResponseVectorObject
	var anonTopBinding workloadinterface.IMetadata
	var anonServiceAccount workloadinterface.IMetadata
	var anonClusterRole workloadinterface.IMetadata

	for _, res := range session.GetCatalog().All() {
		switch res.GetKind() {
		case "User":
			anonSubject = res.(*objectsenvelopes.RegoResponseVectorObject)
		case "ClusterRoleBinding":
			anonTopBinding = res
		case "ServiceAccount":
			anonServiceAccount = res
		case "ClusterRole":
			anonClusterRole = res
		}
	}

	require.NotNil(t, anonSubject)
	require.NotNil(t, anonTopBinding)
	require.NotNil(t, anonServiceAccount)
	require.NotNil(t, anonClusterRole)

	related := anonSubject.GetRelatedObjects()
	require.Len(t, related, 2)
	anonRole := related[0]
	anonBinding := related[1]

	bindingObj := anonBinding.GetObject()
	subjects := bindingObj["subjects"].([]any)
	require.Len(t, subjects, 2)

	assert.Equal(t, anonSubject.GetName(), subjects[0].(map[string]any)["name"])
	assert.Equal(t, anonServiceAccount.GetName(), subjects[1].(map[string]any)["name"])
	assert.Equal(t, anonServiceAccount.GetNamespace(), subjects[1].(map[string]any)["namespace"])
	assert.Equal(t, anonRole.GetName(), bindingObj["roleRef"].(map[string]any)["name"])

	topObj := anonTopBinding.GetObject()
	topSubjects := topObj["subjects"].([]any)
	require.Len(t, topSubjects, 1)

	assert.Equal(t, anonSubject.GetName(), topSubjects[0].(map[string]any)["name"])
	assert.Equal(t, anonClusterRole.GetName(), topObj["roleRef"].(map[string]any)["name"])
}
