package printer

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
	"github.com/kubescape/opa-utils/exceptions"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func exceptionsWorkload(t *testing.T, kind, namespace, name string) workloadinterface.IMetadata {
	t.Helper()
	return exceptionsWorkloadFromFile(t, kind, namespace, name, "")
}

// exceptionsWorkloadFromFile mirrors a locally scanned resource, which carries
// the manifest it was read from in sourcePath.
func exceptionsWorkloadFromFile(t *testing.T, kind, namespace, name, path string) workloadinterface.IMetadata {
	t.Helper()

	metadata := map[string]any{"name": name}
	if namespace != "" {
		metadata["namespace"] = namespace
	}
	object := map[string]any{
		"apiVersion": "v1",
		"kind":       kind,
		"metadata":   metadata,
	}
	if path != "" {
		object["sourcePath"] = path
	}
	workload := workloadinterface.NewWorkloadObj(object)
	require.NotNil(t, workload)
	return workload
}

func failedControl(controlID string) resourcesresults.ResourceAssociatedControl {
	return resourcesresults.ResourceAssociatedControl{
		ControlID: controlID,
		Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
	}
}

func passedControl(controlID string) resourcesresults.ResourceAssociatedControl {
	return resourcesresults.ResourceAssociatedControl{
		ControlID: controlID,
		Status:    apis.StatusInfo{InnerStatus: apis.StatusPassed},
	}
}

func exceptionsSession(t *testing.T) *cautils.OPASessionObj {
	t.Helper()

	session := &cautils.OPASessionObj{
		Report: &reporthandlingv2.PostureReport{
			ReportGenerationTime: time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC),
		},
		AllResources: map[string]workloadinterface.IMetadata{
			"api":  exceptionsWorkload(t, "Deployment", "prod", "api"),
			"web":  exceptionsWorkload(t, "Deployment", "staging", "web"),
			"role": exceptionsWorkload(t, "ClusterRole", "", "admin"),
		},
		ResourcesResult: map[string]resourcesresults.Result{
			"api": {AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				failedControl("C-0002"), passedControl("C-0009"),
			}},
			"web": {AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				failedControl("C-0002"),
			}},
			"role": {AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				failedControl("C-0001"),
			}},
		},
	}
	return session
}

func TestBuildExceptionPoliciesGroupsResourcesByControl(t *testing.T) {
	policies := buildExceptionPolicies(context.Background(), exceptionsSession(t))

	require.Len(t, policies, 2)
	assert.Equal(t, "exclude-C-0001", policies[0].Name)
	assert.Equal(t, "exclude-C-0002", policies[1].Name)

	for _, policy := range policies {
		assert.Equal(t, exceptionPolicyType, policy.PolicyType)
		assert.Equal(t, []armotypes.PostureExceptionPolicyActions{armotypes.AlertOnly}, policy.Actions)
		assert.Equal(t, "2026-03-04T05:06:07Z", policy.CreationTime)
		require.Len(t, policy.PosturePolicies, 1)
	}

	assert.Equal(t, "C-0001", policies[0].PosturePolicies[0].ControlID)
	assert.Equal(t, "C-0002", policies[1].PosturePolicies[0].ControlID)

	// Both deployments failed C-0002 and are listed under the one policy.
	require.Len(t, policies[1].Resources, 2)
	assert.Equal(t, map[string]string{"kind": "Deployment", "namespace": "prod", "name": "api"}, policies[1].Resources[0].Attributes)
	assert.Equal(t, map[string]string{"kind": "Deployment", "namespace": "staging", "name": "web"}, policies[1].Resources[1].Attributes)
	assert.Equal(t, identifiers.DesignatorAttributes, policies[1].Resources[1].DesignatorType)
	assert.Equal(t, identifiers.DesignatorAttributes, policies[1].Resources[0].DesignatorType)
}

func TestBuildExceptionPoliciesPinsResourcesThatReportNoNamespace(t *testing.T) {
	policies := buildExceptionPolicies(context.Background(), exceptionsSession(t))

	require.Len(t, policies[0].Resources, 1)
	assert.Equal(t,
		map[string]string{"kind": "ClusterRole", "name": "admin", "namespace": emptyNamespacePattern},
		policies[0].Resources[0].Attributes)
}

func TestBuildExceptionPoliciesSkipsPassedControls(t *testing.T) {
	policies := buildExceptionPolicies(context.Background(), exceptionsSession(t))

	for _, policy := range policies {
		assert.NotEqual(t, "C-0009", policy.PosturePolicies[0].ControlID)
	}
}

func TestBuildExceptionPoliciesWithoutFailuresIsEmpty(t *testing.T) {
	session := &cautils.OPASessionObj{
		Report: &reporthandlingv2.PostureReport{},
		AllResources: map[string]workloadinterface.IMetadata{
			"api": exceptionsWorkload(t, "Deployment", "prod", "api"),
		},
		ResourcesResult: map[string]resourcesresults.Result{
			"api": {AssociatedControls: []resourcesresults.ResourceAssociatedControl{passedControl("C-0009")}},
		},
	}

	assert.Empty(t, buildExceptionPolicies(context.Background(), session))
}

func TestBuildExceptionPoliciesIgnoresResultsWithoutAResource(t *testing.T) {
	session := &cautils.OPASessionObj{
		Report:       &reporthandlingv2.PostureReport{},
		AllResources: map[string]workloadinterface.IMetadata{"api": nil},
		ResourcesResult: map[string]resourcesresults.Result{
			"api":     {AssociatedControls: []resourcesresults.ResourceAssociatedControl{failedControl("C-0002")}},
			"missing": {AssociatedControls: []resourcesresults.ResourceAssociatedControl{failedControl("C-0002")}},
		},
	}

	assert.Empty(t, buildExceptionPolicies(context.Background(), session))
}

func TestBuildExceptionPoliciesDeduplicatesResources(t *testing.T) {
	session := exceptionsSession(t)
	result := session.ResourcesResult["api"]
	result.AssociatedControls = append(result.AssociatedControls, failedControl("C-0002"))
	session.ResourcesResult["api"] = result

	policies := buildExceptionPolicies(context.Background(), session)

	require.Len(t, policies, 2)
	assert.Len(t, policies[1].Resources, 2)
}

func TestBuildExceptionPoliciesFallsBackToNowWithoutAReportTime(t *testing.T) {
	session := exceptionsSession(t)
	session.Report.ReportGenerationTime = time.Time{}

	policies := buildExceptionPolicies(context.Background(), session)

	require.NotEmpty(t, policies)
	parsed, err := time.Parse(time.RFC3339, policies[0].CreationTime)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().UTC(), parsed, time.Minute)
}

// TestExceptionDocumentsMatchDocumentedShape pins the serialised form against
// the files under examples/exceptions, which is what users edit and feed back
// through --exceptions.
func TestExceptionDocumentsMatchDocumentedShape(t *testing.T) {
	policies := buildExceptionPolicies(context.Background(), exceptionsSession(t))

	encoded, err := json.Marshal(exceptionDocuments(policies))
	require.NoError(t, err)

	var decoded []map[string]any
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.NotEmpty(t, decoded)

	assert.ElementsMatch(t,
		[]string{"name", "policyType", "creationTime", "actions", "resources", "posturePolicies"},
		keysOf(decoded[0]),
	)

	posturePolicies, ok := decoded[0]["posturePolicies"].([]any)
	require.True(t, ok)
	require.NotEmpty(t, posturePolicies)
	assert.Equal(t, []string{"controlID"}, keysOf(posturePolicies[0].(map[string]any)))
}

// TestExceptionDocumentsRoundTripIntoTheConsumedType is the contract that
// matters: whatever is written has to parse back as an exception policy.
func TestExceptionDocumentsRoundTripIntoTheConsumedType(t *testing.T) {
	policies := buildExceptionPolicies(context.Background(), exceptionsSession(t))

	encoded, err := json.Marshal(exceptionDocuments(policies))
	require.NoError(t, err)

	var parsed []armotypes.PostureExceptionPolicy
	require.NoError(t, json.Unmarshal(encoded, &parsed))

	require.Len(t, parsed, len(policies))
	for i := range parsed {
		assert.Equal(t, policies[i].Name, parsed[i].Name)
		assert.Equal(t, policies[i].PolicyType, parsed[i].PolicyType)
		assert.Equal(t, policies[i].Actions, parsed[i].Actions)
		assert.Equal(t, policies[i].Resources, parsed[i].Resources)
		require.Len(t, parsed[i].PosturePolicies, 1)
		assert.Equal(t, policies[i].PosturePolicies[0].ControlID, parsed[i].PosturePolicies[0].ControlID)
		assert.True(t, parsed[i].IsAlertOnly())
	}
}

func keysOf(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}

// TestExceptionsOutputExtDoesNotCollideWithJSON pins the distinct extension.
// Both formats emit JSON, and --format json,exceptions with one --output would
// resolve to the same path and be rejected as a collision if they shared ".json".
func TestExceptionsOutputExtDoesNotCollideWithJSON(t *testing.T) {
	assert.NotEqual(t, printer.JsonOutputExt, printer.ExceptionsOutputExt)

	jsonPath, _ := printer.ResolveOutputFile(printer.JsonFormat, "scan-result", "results")
	exceptionsPath, _ := printer.ResolveOutputFile(printer.ExceptionsFormat, "scan-result", exceptionsOutputFile)
	assert.NotEqual(t, jsonPath, exceptionsPath)
}

// TestDesignatorsDoNotMatchUnrelatedResources drives the real exception
// processor. Attributes are compared as anchored regular expressions, so a
// resource whose name contains a dot — every CRD is <plural>.<group> — would
// otherwise generate a designator that also silences unrelated resources.
func TestDesignatorsDoNotMatchUnrelatedResources(t *testing.T) {
	session := &cautils.OPASessionObj{
		Report: &reporthandlingv2.PostureReport{},
		AllResources: map[string]workloadinterface.IMetadata{
			"crd": exceptionsWorkload(t, "Pod", "default", "web-1.2.3"),
		},
		ResourcesResult: map[string]resourcesresults.Result{
			"crd": {AssociatedControls: []resourcesresults.ResourceAssociatedControl{failedControl("C-0001")}},
		},
	}

	policies := buildExceptionPolicies(context.Background(), session)
	require.Len(t, policies, 1)

	processor := exceptions.NewProcessor()
	intended := exceptionsWorkload(t, "Pod", "default", "web-1.2.3")
	unrelated := exceptionsWorkload(t, "Pod", "default", "web-1x2y3")

	assert.NotEmpty(t, processor.GetResourceExceptions(policies, intended, ""),
		"the resource the exception was generated for must match")
	assert.Empty(t, processor.GetResourceExceptions(policies, unrelated, ""),
		"a resource the baseline never described must not be silenced")
}

func TestActionPrintWritesAFileThatParsesBack(t *testing.T) {
	output := filepath.Join(t.TempDir(), "baseline.exceptions.json")

	p := NewExceptionsPrinter()
	require.NoError(t, p.SetWriter(context.Background(), output))

	require.NoError(t, p.ActionPrint(context.Background(), exceptionsSession(t), nil))
	require.NoError(t, p.CloseWriter())

	contents, err := os.ReadFile(output)
	require.NoError(t, err)

	var parsed []armotypes.PostureExceptionPolicy
	require.NoError(t, json.Unmarshal(contents, &parsed))
	require.Len(t, parsed, 2)
	assert.Equal(t, "exclude-C-0001", parsed[0].Name)
	assert.True(t, parsed[0].IsAlertOnly())
	assert.Equal(t, byte('\n'), contents[len(contents)-1], "file should end with a newline")
}

func TestActionPrintWithoutASessionErrors(t *testing.T) {
	p := NewExceptionsPrinter()
	require.NoError(t, p.SetWriter(context.Background(), filepath.Join(t.TempDir(), "out.exceptions.json")))
	t.Cleanup(func() { _ = p.CloseWriter() })

	assert.Error(t, p.ActionPrint(context.Background(), nil, nil))
}

func TestActionPrintWritesAnEmptyArrayWhenNothingFailed(t *testing.T) {
	output := filepath.Join(t.TempDir(), "empty.exceptions.json")

	session := &cautils.OPASessionObj{
		Report:          &reporthandlingv2.PostureReport{},
		AllResources:    map[string]workloadinterface.IMetadata{"api": exceptionsWorkload(t, "Deployment", "prod", "api")},
		ResourcesResult: map[string]resourcesresults.Result{"api": {AssociatedControls: []resourcesresults.ResourceAssociatedControl{passedControl("C-0009")}}},
	}

	p := NewExceptionsPrinter()
	require.NoError(t, p.SetWriter(context.Background(), output))
	require.NoError(t, p.ActionPrint(context.Background(), session, nil))
	require.NoError(t, p.CloseWriter())

	contents, err := os.ReadFile(output)
	require.NoError(t, err)

	// A clean scan still writes a usable file rather than nothing at all.
	var parsed []armotypes.PostureExceptionPolicy
	require.NoError(t, json.Unmarshal(contents, &parsed))
	assert.Empty(t, parsed)
}

// TestControlIDsDoNotMatchUnrelatedControls covers the second regex axis. A
// custom rule's control ID is custom-<rule>, and the rule is named after a file
// or directory, so it can carry dots that would otherwise widen the policy to
// controls the baseline never described.
func TestControlIDsDoNotMatchUnrelatedControls(t *testing.T) {
	session := &cautils.OPASessionObj{
		Report:       &reporthandlingv2.PostureReport{},
		AllResources: map[string]workloadinterface.IMetadata{"api": exceptionsWorkload(t, "Pod", "default", "api")},
		ResourcesResult: map[string]resourcesresults.Result{
			"api": {AssociatedControls: []resourcesresults.ResourceAssociatedControl{failedControl("custom-net.policy.v1")}},
		},
	}

	policies := buildExceptionPolicies(context.Background(), session)
	require.Len(t, policies, 1)

	processor := exceptions.NewProcessor()
	controlID := policies[0].PosturePolicies[0].ControlID

	assert.True(t, processor.RegexCompareControlID(controlID, "custom-net.policy.v1"),
		"the control the exception was generated for must match")
	assert.False(t, processor.RegexCompareControlID(controlID, "custom-netXpolicyYv1"),
		"a control the baseline never described must not be silenced")
}

// TestStandardControlIDsAreUnchangedByEscaping keeps the common output readable:
// regolibrary IDs carry no regex metacharacters, so escaping must be invisible.
func TestStandardControlIDsAreUnchangedByEscaping(t *testing.T) {
	policies := buildExceptionPolicies(context.Background(), exceptionsSession(t))

	require.Len(t, policies, 2)
	assert.Equal(t, "C-0001", policies[0].PosturePolicies[0].ControlID)
	assert.Equal(t, "C-0002", policies[1].PosturePolicies[0].ControlID)
	assert.Equal(t, map[string]string{"kind": "Deployment", "namespace": "prod", "name": "api"},
		policies[1].Resources[0].Attributes)
}

// TestNamespacelessWorkloadDoesNotMatchOtherNamespaces covers manifests that
// omit metadata.namespace, which is the common case in a repository. Leaving
// the namespace axis unconstrained would let a baseline built from those
// manifests silence an unrelated object of the same kind and name in a real
// namespace.
func TestNamespacelessWorkloadDoesNotMatchOtherNamespaces(t *testing.T) {
	session := &cautils.OPASessionObj{
		Report:       &reporthandlingv2.PostureReport{},
		AllResources: map[string]workloadinterface.IMetadata{"api": exceptionsWorkload(t, "Deployment", "", "api")},
		ResourcesResult: map[string]resourcesresults.Result{
			"api": {AssociatedControls: []resourcesresults.ResourceAssociatedControl{failedControl("C-0001")}},
		},
	}

	policies := buildExceptionPolicies(context.Background(), session)
	require.Len(t, policies, 1)
	assert.Equal(t, emptyNamespacePattern, policies[0].Resources[0].Attributes[identifiers.AttributeNamespace])

	processor := exceptions.NewProcessor()
	assert.NotEmpty(t, processor.GetResourceExceptions(policies, exceptionsWorkload(t, "Deployment", "", "api"), ""),
		"the workload the exception was generated for must match")
	assert.Empty(t, processor.GetResourceExceptions(policies, exceptionsWorkload(t, "Deployment", "prod", "api"), ""),
		"an identical Deployment in another namespace must not be silenced")
}

// TestClusterScopedWorkloadStillMatches keeps the round trip working for kinds
// that genuinely have no namespace: the same pattern describes them, so pinning
// the axis must not stop the exception applying.
func TestClusterScopedWorkloadStillMatches(t *testing.T) {
	session := &cautils.OPASessionObj{
		Report:       &reporthandlingv2.PostureReport{},
		AllResources: map[string]workloadinterface.IMetadata{"cr": exceptionsWorkload(t, "ClusterRole", "", "admin")},
		ResourcesResult: map[string]resourcesresults.Result{
			"cr": {AssociatedControls: []resourcesresults.ResourceAssociatedControl{failedControl("C-0001")}},
		},
	}

	policies := buildExceptionPolicies(context.Background(), session)
	require.Len(t, policies, 1)
	assert.Equal(t, emptyNamespacePattern, policies[0].Resources[0].Attributes[identifiers.AttributeNamespace])

	processor := exceptions.NewProcessor()
	assert.NotEmpty(t, processor.GetResourceExceptions(policies, exceptionsWorkload(t, "ClusterRole", "", "admin"), ""))
}

// TestNamespaceKindRoundTripsThroughTheProcessor covers the kind the processor
// special-cases: it compares the namespace axis against a Namespace object's own
// name, so pinning that axis to "no namespace" would leave every finding on the
// 18+ shipped controls that evaluate raw Namespace objects unsuppressed.
func TestNamespaceKindRoundTripsThroughTheProcessor(t *testing.T) {
	session := &cautils.OPASessionObj{
		Report:       &reporthandlingv2.PostureReport{},
		AllResources: map[string]workloadinterface.IMetadata{"ns": exceptionsWorkload(t, "Namespace", "", "kube-system")},
		ResourcesResult: map[string]resourcesresults.Result{
			"ns": {AssociatedControls: []resourcesresults.ResourceAssociatedControl{failedControl("C-0186")}},
		},
	}

	policies := buildExceptionPolicies(context.Background(), session)
	require.Len(t, policies, 1)
	assert.Equal(t, "kube-system", policies[0].Resources[0].Attributes[identifiers.AttributeNamespace])

	processor := exceptions.NewProcessor()
	assert.NotEmpty(t, processor.GetResourceExceptions(policies, exceptionsWorkload(t, "Namespace", "", "kube-system"), ""),
		"the namespace the exception was generated for must match")
	assert.Empty(t, processor.GetResourceExceptions(policies, exceptionsWorkload(t, "Namespace", "", "kube-public"), ""),
		"another namespace must not be silenced")
}

// TestSameObjectInTwoFilesStaysDistinct is the kustomize base-and-overlay case:
// both files declare the same kind, namespace and name, so without the source
// path a baseline built from one would suppress a later finding in the other.
func TestSameObjectInTwoFilesStaysDistinct(t *testing.T) {
	base := exceptionsWorkloadFromFile(t, "Deployment", "default", "api", "base/deploy.yaml:1")
	overlay := exceptionsWorkloadFromFile(t, "Deployment", "default", "api", "overlays/prod/deploy.yaml:1")

	session := &cautils.OPASessionObj{
		Report:       &reporthandlingv2.PostureReport{},
		AllResources: map[string]workloadinterface.IMetadata{"base": base},
		ResourcesResult: map[string]resourcesresults.Result{
			"base": {AssociatedControls: []resourcesresults.ResourceAssociatedControl{failedControl("C-0016")}},
		},
	}

	policies := buildExceptionPolicies(context.Background(), session)
	require.Len(t, policies, 1)
	assert.Equal(t, `base/deploy\.yaml:1`, policies[0].Resources[0].Attributes[identifiers.AttributePath])

	processor := exceptions.NewProcessor()
	assert.NotEmpty(t, processor.GetResourceExceptions(policies, base, ""),
		"the file the exception was generated from must match")
	assert.Empty(t, processor.GetResourceExceptions(policies, overlay, ""),
		"the same object declared in another file must not be silenced")
}

// TestClusterResourcesOmitThePathAxis keeps cluster scans working: they carry no
// sourcePath, and an unmatchable path attribute would kill every policy.
func TestClusterResourcesOmitThePathAxis(t *testing.T) {
	policies := buildExceptionPolicies(context.Background(), exceptionsSession(t))

	require.NotEmpty(t, policies)
	for _, policy := range policies {
		for _, resource := range policy.Resources {
			assert.NotContains(t, resource.Attributes, identifiers.AttributePath)
		}
	}
}
