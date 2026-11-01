package printer

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sarifExceptionControlID = "C-0057"

const sarifExceptionManifest = `apiVersion: apps/v1
kind: Deployment
metadata: {name: demo, namespace: default}
spec:
  replicas: 1
  selector: {matchLabels: {app: demo}}
  template:
    metadata: {labels: {app: demo}}
    spec:
      containers:
      - name: app
        image: nginx:1.23
        securityContext:
          privileged: true
          allowPrivilegeEscalation: true
`

func disableException(name string, reason *string) armotypes.PostureExceptionPolicy {
	return armotypes.PostureExceptionPolicy{
		PortalBase: armotypes.PortalBase{Name: name},
		PolicyType: string(armotypes.PostureExceptionPolicyType),
		Actions:    []armotypes.PostureExceptionPolicyActions{armotypes.Disable},
		Reason:     reason,
	}
}

func alertOnlyException(name string, expires *time.Time) armotypes.PostureExceptionPolicy {
	return armotypes.PostureExceptionPolicy{
		PortalBase:     armotypes.PortalBase{Name: name},
		PolicyType:     string(armotypes.PostureExceptionPolicyType),
		Actions:        []armotypes.PostureExceptionPolicyActions{armotypes.AlertOnly},
		ExpirationDate: expires,
	}
}

func strPtr(s string) *string { return &s }

// failingRule is a rule that failed on the privileged flag; exceptions are what
// the processor attached to it.
func failingRule(name, fixPath string, attached ...armotypes.PostureExceptionPolicy) resourcesresults.ResourceAssociatedRule {
	return resourcesresults.ResourceAssociatedRule{
		Name:   name,
		Status: apis.StatusFailed,
		Paths: []armotypes.PosturePaths{{
			FixPath: armotypes.FixPath{Path: fixPath, Value: "false"},
		}},
		Exception: attached,
	}
}

const (
	privilegedPath = "spec.template.spec.containers[0].securityContext.privileged"
	escalationPath = "spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation"
)

// sarifExceptionControl derives the control's status from its rules the way the
// processor does after it has attached exceptions.
func sarifExceptionControl(rules ...resourcesresults.ResourceAssociatedRule) resourcesresults.ResourceAssociatedControl {
	ac := resourcesresults.ResourceAssociatedControl{
		ControlID:               sarifExceptionControlID,
		ResourceAssociatedRules: rules,
	}
	ac.SetStatus(reporthandling.Control{})
	return ac
}

func sarifExceptionSession(t *testing.T, controls ...resourcesresults.ResourceAssociatedControl) *cautils.OPASessionObj {
	t.Helper()
	manifestDir := t.TempDir()
	manifestPath := filepath.Join(manifestDir, "deploy.yaml")
	require.NoError(t, os.WriteFile(manifestPath, []byte(sarifExceptionManifest), 0o600))

	resourceID := "apps/v1/Deployment/default/demo"
	lw := localworkload.NewLocalWorkload(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "demo", "namespace": "default"},
		"spec":       map[string]any{},
	})
	lw.SetPath("deploy.yaml:0")

	session := cautils.NewOPASessionObjMock()
	session.Metadata = &reporthandlingv2.Metadata{
		ScanMetadata: reporthandlingv2.ScanMetadata{ScanningTarget: reporthandlingv2.File},
		ContextMetadata: reporthandlingv2.ContextMetadata{
			FileContextMetadata: &reporthandlingv2.FileContextMetadata{FilePath: manifestPath},
		},
	}
	session.ResourcesResult[resourceID] = resourcesresults.Result{ResourceID: resourceID, AssociatedControls: controls}
	session.ResourceSource = map[string]reporthandling.Source{
		resourceID: {Path: manifestDir, RelativePath: "deploy.yaml", FileType: reporthandling.SourceTypeYaml},
	}
	session.AllResources[resourceID] = lw
	session.Report = &reporthandlingv2.PostureReport{
		SummaryDetails: reportsummary.SummaryDetails{
			Controls: reportsummary.ControlSummaries{
				sarifExceptionControlID: reportsummary.ControlSummary{
					ControlID:   sarifExceptionControlID,
					Name:        "Privileged container",
					Description: "Do not run privileged containers",
					Remediation: "Set privileged to false",
					ScoreFactor: 8.0,
				},
			},
		},
	}
	return session
}

func renderSARIF(t *testing.T, sp *SARIFPrinter, session *cautils.OPASessionObj) []byte {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, sp.writeConfigurationSARIF(context.Background(), &buf, session))
	return buf.Bytes()
}

// validateSARIF checks a report against the SARIF 2.1.0 schema published by
// OASIS (testdata/sarif-schema-2.1.0.json).
func validateSARIF(t *testing.T, raw []byte) error {
	t.Helper()
	schemaFile, err := os.Open(filepath.Join("testdata", "sarif-schema-2.1.0.json"))
	require.NoError(t, err)
	defer func() { _ = schemaFile.Close() }()
	schemaDoc, err := jsonschema.UnmarshalJSON(schemaFile)
	require.NoError(t, err)

	compiler := jsonschema.NewCompiler()
	require.NoError(t, compiler.AddResource("sarif-schema-2.1.0.json", schemaDoc))
	schema, err := compiler.Compile("sarif-schema-2.1.0.json")
	require.NoError(t, err)

	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	require.NoError(t, err)
	return schema.Validate(instance)
}

func requireValidSARIF(t *testing.T, raw []byte) {
	t.Helper()
	require.NoError(t, validateSARIF(t, raw), "report is not valid SARIF 2.1.0:\n%s", raw)
}

func parseSARIFResults(t *testing.T, raw []byte) []*sarif.Result {
	t.Helper()
	var report sarif.Report
	require.NoError(t, json.Unmarshal(raw, &report))
	require.Len(t, report.Runs, 1)
	return report.Runs[0].Results
}

func fingerprintOf(t *testing.T, result *sarif.Result) string {
	t.Helper()
	value, ok := result.PartialFingerprints["kubescapeFindingFingerprint"].(string)
	require.True(t, ok, "result has no kubescapeFindingFingerprint")
	return value
}

func TestSARIFExceptions_DisableProducesSuppressedResult(t *testing.T) {
	reason := "approved by the platform team until the migration ends"
	ex := disableException("allow-privileged", &reason)

	ordinary := parseSARIFResults(t, renderSARIF(t, NewSARIFPrinter(false),
		sarifExceptionSession(t, sarifExceptionControl(failingRule("privileged", privilegedPath)))))
	require.Len(t, ordinary, 1)

	raw := renderSARIF(t, NewSARIFPrinter(false),
		sarifExceptionSession(t, sarifExceptionControl(failingRule("privileged", privilegedPath, ex))))
	requireValidSARIF(t, raw)
	results := parseSARIFResults(t, raw)

	require.Len(t, results, 1, "the finding stays in the report")
	suppressed := results[0]
	require.Len(t, suppressed.Suppressions, 1)
	assert.Equal(t, "external", suppressed.Suppressions[0].Kind)
	require.NotNil(t, suppressed.Suppressions[0].Status)
	assert.Equal(t, "accepted", *suppressed.Suppressions[0].Status)
	require.NotNil(t, suppressed.Suppressions[0].Justification)
	assert.Equal(t, reason, *suppressed.Suppressions[0].Justification)

	// Same finding as without the exception: only the suppression differs.
	assert.Equal(t, ordinary[0].RuleID, suppressed.RuleID)
	assert.Equal(t, sarifExceptionControlID, *suppressed.RuleID)
	assert.Equal(t, ordinary[0].Message.Text, suppressed.Message.Text)
	assert.Equal(t, ordinary[0].Locations[0].PhysicalLocation.Region, suppressed.Locations[0].PhysicalLocation.Region)
	assert.Equal(t, fingerprintOf(t, ordinary[0]), fingerprintOf(t, suppressed),
		"the fingerprint must not change when an exception is added, or the code-scanning alert is lost")
	assert.Nil(t, ordinary[0].Suppressions)
}

func TestSARIFExceptions_JustificationFallsBackToExceptionName(t *testing.T) {
	tests := []struct {
		name string
		ex   armotypes.PostureExceptionPolicy
		want string
	}{
		{name: "no reason", ex: disableException("allow-privileged", nil), want: `Accepted by exception "allow-privileged"`},
		{name: "blank reason", ex: disableException("allow-privileged", strPtr("  ")), want: `Accepted by exception "allow-privileged"`},
		{name: "no reason and no name", ex: disableException("", nil), want: "Accepted by a scan exception"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := renderSARIF(t, NewSARIFPrinter(false),
				sarifExceptionSession(t, sarifExceptionControl(failingRule("privileged", privilegedPath, tt.ex))))
			requireValidSARIF(t, raw)
			results := parseSARIFResults(t, raw)
			require.Len(t, results, 1)
			require.Len(t, results[0].Suppressions, 1)
			assert.Equal(t, tt.want, *results[0].Suppressions[0].Justification)
		})
	}
}

func TestSARIFExceptions_SuppressionRecordsNameAndExpiration(t *testing.T) {
	expires := time.Date(2030, 1, 2, 3, 4, 5, 0, time.FixedZone("x", 3600))
	ex := disableException("allow-privileged", nil)
	ex.ExpirationDate = &expires

	raw := renderSARIF(t, NewSARIFPrinter(false),
		sarifExceptionSession(t, sarifExceptionControl(failingRule("privileged", privilegedPath, ex))))
	requireValidSARIF(t, raw)

	var decoded struct {
		Runs []struct {
			Results []struct {
				Suppressions []struct {
					Properties map[string]any `json:"properties"`
				} `json:"suppressions"`
			} `json:"results"`
		} `json:"runs"`
	}
	require.NoError(t, json.Unmarshal(raw, &decoded))
	properties := decoded.Runs[0].Results[0].Suppressions[0].Properties
	assert.Equal(t, "allow-privileged", properties["exception-name"])
	assert.Equal(t, "2030-01-02T02:04:05Z", properties["exception-expiration"])
}

func TestSARIFExceptions_AlertOnlyStaysVisibleAndUnsuppressed(t *testing.T) {
	expires := time.Date(2030, 6, 1, 0, 0, 0, 0, time.UTC)
	ordinary := parseSARIFResults(t, renderSARIF(t, NewSARIFPrinter(false),
		sarifExceptionSession(t, sarifExceptionControl(failingRule("privileged", privilegedPath)))))

	raw := renderSARIF(t, NewSARIFPrinter(false), sarifExceptionSession(t,
		sarifExceptionControl(failingRule("privileged", privilegedPath, alertOnlyException("known-issue", &expires)))))
	requireValidSARIF(t, raw)
	results := parseSARIFResults(t, raw)

	require.Len(t, results, 1)
	assert.Empty(t, results[0].Suppressions, "alertOnly acknowledges a finding, it does not suppress it")
	assert.Equal(t, "alertOnly", results[0].Properties["exception-action"])
	assert.Equal(t, "known-issue", results[0].Properties["exception-names"])
	assert.Equal(t, "2030-06-01T00:00:00Z", results[0].Properties["exception-expiration"])
	assert.Equal(t, fingerprintOf(t, ordinary[0]), fingerprintOf(t, results[0]))
}

func TestSARIFExceptions_AlertOnlyUsesEarliestExpirationAndSortedNames(t *testing.T) {
	late := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	early := time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC)
	rule := failingRule("privileged", privilegedPath,
		alertOnlyException("zeta", &late), alertOnlyException("alpha", &early), alertOnlyException("alpha", &early))

	results := parseSARIFResults(t, renderSARIF(t, NewSARIFPrinter(false),
		sarifExceptionSession(t, sarifExceptionControl(rule))))

	require.Len(t, results, 1)
	assert.Equal(t, "alpha, zeta", results[0].Properties["exception-names"])
	assert.Equal(t, "2029-01-01T00:00:00Z", results[0].Properties["exception-expiration"])
}

func TestSARIFExceptions_FindingWithoutExceptionIsUnchanged(t *testing.T) {
	raw := renderSARIF(t, NewSARIFPrinter(false),
		sarifExceptionSession(t, sarifExceptionControl(failingRule("privileged", privilegedPath))))
	requireValidSARIF(t, raw)

	assert.NotContains(t, string(raw), "suppressions")
	assert.NotContains(t, string(raw), "exception-")
	assert.Len(t, parseSARIFResults(t, raw), 1)
}

// TestSARIFExceptions_ProcessorDecidesWhichExceptionsApply covers exceptions the
// processor did not honour. It drops expired exceptions before it attaches any,
// and a framework-scoped exception that does not match the scan leaves the rule
// failing. In both cases the printer must report an ordinary finding and must
// not look at the exception's dates or scope itself.
func TestSARIFExceptions_ProcessorDecidesWhichExceptionsApply(t *testing.T) {
	t.Run("expired exception was dropped by the processor", func(t *testing.T) {
		expired := time.Now().Add(-24 * time.Hour)
		ex := disableException("expired", nil)
		ex.ExpirationDate = &expired
		// Nothing is attached: filterExpiredExceptions removed it up front.
		raw := renderSARIF(t, NewSARIFPrinter(false),
			sarifExceptionSession(t, sarifExceptionControl(failingRule("privileged", privilegedPath))))
		requireValidSARIF(t, raw)

		results := parseSARIFResults(t, raw)
		require.Len(t, results, 1)
		assert.Empty(t, results[0].Suppressions)
		assert.NotContains(t, string(raw), "exception-")
	})

	t.Run("framework-scoped exception that does not match the scan", func(t *testing.T) {
		ex := disableException("other-framework", nil)
		ex.PosturePolicies = []armotypes.PosturePolicy{{FrameworkName: "cis"}}
		raw := renderSARIF(t, NewSARIFPrinter(false),
			sarifExceptionSession(t, sarifExceptionControl(failingRule("privileged", privilegedPath, ex))))
		requireValidSARIF(t, raw)

		results := parseSARIFResults(t, raw)
		require.Len(t, results, 1)
		assert.Empty(t, results[0].Suppressions)
		assert.NotContains(t, string(raw), "exception-")
	})
}

// TestSARIFExceptions_MixedControlReportsBothStates covers a control with one
// rule removed by an exception and another still failing: the ordinary result
// describes only the rule that still fails.
func TestSARIFExceptions_MixedControlReportsBothStates(t *testing.T) {
	reason := "privileged is needed by the CNI"
	ac := sarifExceptionControl(
		failingRule("privileged", privilegedPath, disableException("cni", &reason)),
		failingRule("escalation", escalationPath),
	)
	require.True(t, ac.GetStatus(nil).IsFailed())

	raw := renderSARIF(t, NewSARIFPrinter(false), sarifExceptionSession(t, ac))
	requireValidSARIF(t, raw)
	results := parseSARIFResults(t, raw)

	require.Len(t, results, 2)
	assert.Empty(t, results[0].Suppressions, "the ordinary result comes first")
	assert.Contains(t, *results[0].Message.Text, escalationPath)
	assert.NotContains(t, *results[0].Message.Text, privilegedPath, "a rule an exception removed is not part of the ordinary finding")

	require.Len(t, results[1].Suppressions, 1)
	assert.Equal(t, reason, *results[1].Suppressions[0].Justification)
	assert.Contains(t, *results[1].Message.Text, privilegedPath)
	assert.NotEqual(t, fingerprintOf(t, results[0]), fingerprintOf(t, results[1]),
		"two results at one rule id need distinct fingerprints")
}

func TestSARIFExceptions_MixedRulesDisableAndAlertOnly(t *testing.T) {
	reason := "privileged is needed by the CNI"
	expires := time.Date(2030, 6, 1, 0, 0, 0, 0, time.UTC)
	ac := sarifExceptionControl(
		failingRule("privileged", privilegedPath, disableException("cni", &reason)),
		failingRule("escalation", escalationPath, alertOnlyException("known-escalation", &expires)),
	)
	require.True(t, ac.GetStatus(nil).IsFailed())

	raw := renderSARIF(t, NewSARIFPrinter(false), sarifExceptionSession(t, ac))
	requireValidSARIF(t, raw)
	results := parseSARIFResults(t, raw)

	require.Len(t, results, 2)
	visible, suppressed := results[0], results[1]

	// Visible finding describes the alertOnly rule.
	assert.Empty(t, visible.Suppressions, "alertOnly finding remains unsuppressed")
	assert.Contains(t, *visible.Message.Text, escalationPath)
	assert.NotContains(t, *visible.Message.Text, privilegedPath)
	assert.Equal(t, "alertOnly", visible.Properties["exception-action"])
	assert.Equal(t, "known-escalation", visible.Properties["exception-names"])

	// Suppressed finding describes the disabled rule.
	require.Len(t, suppressed.Suppressions, 1)
	assert.Equal(t, reason, *suppressed.Suppressions[0].Justification)
	assert.Contains(t, *suppressed.Message.Text, privilegedPath)
	assert.NotEqual(t, fingerprintOf(t, visible), fingerprintOf(t, suppressed))
}

func TestSARIFExceptions_SeveralExceptionsGiveOneResult(t *testing.T) {
	zeroReason := "second"
	first := disableException("a-first", nil)
	second := disableException("b-second", &zeroReason)
	// Two rules matched by the same two exceptions, listed in opposite orders.
	ac := sarifExceptionControl(
		failingRule("privileged", privilegedPath, second, first),
		failingRule("escalation", escalationPath, first, second),
	)

	raw := renderSARIF(t, NewSARIFPrinter(false), sarifExceptionSession(t, ac))
	requireValidSARIF(t, raw)
	results := parseSARIFResults(t, raw)

	require.Len(t, results, 1, "one finding, however many exceptions explain it")
	require.Len(t, results[0].Suppressions, 2)
	assert.Equal(t, `Accepted by exception "a-first"`, *results[0].Suppressions[0].Justification)
	assert.Equal(t, "second", *results[0].Suppressions[1].Justification)
}

func TestSARIFExceptions_OutputIsDeterministic(t *testing.T) {
	build := func(order int) []byte {
		first, second := disableException("a", nil), disableException("b", strPtr("why"))
		attached := []armotypes.PostureExceptionPolicy{first, second}
		if order == 1 {
			attached = []armotypes.PostureExceptionPolicy{second, first}
		}
		return renderSARIF(t, NewSARIFPrinter(false), sarifExceptionSession(t, sarifExceptionControl(
			failingRule("privileged", privilegedPath, attached...),
			failingRule("escalation", escalationPath))))
	}
	// The temp directory differs per session, so compare the parts that matter.
	normalize := func(raw []byte) string {
		var report sarif.Report
		require.NoError(t, json.Unmarshal(raw, &report))
		encoded, err := json.Marshal(report.Runs[0].Results)
		require.NoError(t, err)
		return string(encoded)
	}
	assert.Equal(t, normalize(build(0)), normalize(build(1)))
}

func TestSARIFExceptions_SuppressedResultKeepsRuleAndLocation(t *testing.T) {
	raw := renderSARIF(t, NewSARIFPrinter(false), sarifExceptionSession(t,
		sarifExceptionControl(failingRule("privileged", privilegedPath, disableException("allow", nil)))))
	requireValidSARIF(t, raw)

	var report sarif.Report
	require.NoError(t, json.Unmarshal(raw, &report))
	run := report.Runs[0]
	require.Len(t, run.Results, 1)
	require.Len(t, run.Tool.Driver.Rules, 1, "a control whose only findings are suppressed still declares its rule")
	assert.Equal(t, sarifExceptionControlID, run.Tool.Driver.Rules[0].ID)
	require.NotNil(t, run.Results[0].RuleIndex)
	assert.Equal(t, uint(0), *run.Results[0].RuleIndex)

	region := run.Results[0].Locations[0].PhysicalLocation.Region
	assert.Equal(t, 14, *region.StartLine, "the location points at the field the exception covers")
	assert.Equal(t, "deploy.yaml", *run.Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI)
}

func TestSARIFExceptions_SuppressedResultRedactsSecrets(t *testing.T) {
	const secret = "s3cr3t-plaintext-password"
	rule := resourcesresults.ResourceAssociatedRule{
		Name:   "credentials",
		Status: apis.StatusFailed,
		Paths: []armotypes.PosturePaths{{
			FixPath: armotypes.FixPath{Path: "data.password", Value: secret},
		}},
		Exception: []armotypes.PostureExceptionPolicy{disableException("allow", nil)},
	}
	build := func(t *testing.T) *cautils.OPASessionObj {
		session := sarifExceptionSession(t, sarifExceptionControl(rule))
		for id := range session.AllResources {
			lw := localworkload.NewLocalWorkload(map[string]any{
				"apiVersion": "v1", "kind": "Secret",
				"metadata": map[string]any{"name": "demo", "namespace": "default"},
				"data":     map[string]any{},
			})
			lw.SetPath("deploy.yaml:0")
			session.AllResources[id] = lw
		}
		manifest := "apiVersion: v1\nkind: Secret\nmetadata: {name: demo, namespace: default}\ndata:\n  password: \"0000000000000000\"\n"
		for id, source := range session.ResourceSource {
			require.NoError(t, os.WriteFile(filepath.Join(source.Path, "deploy.yaml"), []byte(manifest), 0o600))
			_ = id
		}
		return session
	}

	hidden := renderSARIF(t, NewSARIFPrinter(false), build(t))
	requireValidSARIF(t, hidden)
	require.Len(t, parseSARIFResults(t, hidden), 1)
	assert.NotContains(t, string(hidden), secret, "a suppressed result is redacted like an ordinary one")
	assert.Contains(t, string(hidden), redactedValue)

	revealed := renderSARIF(t, NewSARIFPrinter(true), build(t))
	assert.Contains(t, string(revealed), secret)
}

func TestSARIFExceptions_SkippedControlIsNotReportedAsSuppressed(t *testing.T) {
	ac := sarifExceptionControl(failingRule("privileged", privilegedPath, disableException("allow", nil)))
	ac.Status = apis.StatusInfo{InnerStatus: apis.StatusSkipped, SubStatus: apis.SubStatusManualReview}

	raw := renderSARIF(t, NewSARIFPrinter(false), sarifExceptionSession(t, ac))
	requireValidSARIF(t, raw)
	assert.Empty(t, parseSARIFResults(t, raw))
}

func TestSARIFExceptions_SplitLeavesUnexceptedControlsAlone(t *testing.T) {
	ac := sarifExceptionControl(failingRule("privileged", privilegedPath))
	split := splitSARIFExceptions(nil, ac)

	assert.False(t, split.hasSuppressed)
	assert.Empty(t, split.alertOnlyExceptions)
	assert.Equal(t, ac.ResourceAssociatedRules, split.visible.ResourceAssociatedRules)
	assert.False(t, isSARIFSuppressedControl(nil, ac))
	assert.False(t, strings.Contains(string(renderSARIF(t, NewSARIFPrinter(false), sarifExceptionSession(t, ac))), "suppressions"))
}

// TestSARIFExceptions_SchemaRejectsLibrarySuppressionNulls documents why
// suppressions are written through sarifSuppression: sarif.Suppression
// marshals every field it was not given as null, which the schema rejects.
func TestSARIFExceptions_SchemaRejectsLibrarySuppressionNulls(t *testing.T) {
	report, err := sarif.New(sarif.Version210)
	require.NoError(t, err)
	run := sarif.NewRunWithInformationURI("kubescape", "https://kubescape.io")
	result := run.CreateResultForRule("C-0057").WithMessage(sarif.NewTextMessage("m"))
	result.AddSuppression(sarif.NewSuppression("external").WithStatus("accepted"))
	report.AddRun(run)
	raw, err := json.Marshal(report)
	require.NoError(t, err)

	assert.Error(t, validateSARIF(t, raw))
}

// TestSARIFExceptions_SuppressedOnlyResourceIsReported covers a resource whose
// every finding was removed by an exception, so the resource itself passes: it
// is still listed next to a resource that fails.
func TestSARIFExceptions_SuppressedOnlyResourceIsReported(t *testing.T) {
	session := sarifExceptionSession(t, sarifExceptionControl(
		failingRule("privileged", privilegedPath, disableException("allow", nil))))
	demo := session.ResourcesResult["apps/v1/Deployment/default/demo"]
	require.False(t, demo.GetStatus(nil).IsFailed(), "the resource passes once the exception removes its only finding")

	otherID := "apps/v1/Deployment/default/other"
	other := sarifExceptionControl(failingRule("privileged", privilegedPath))
	session.ResourcesResult[otherID] = resourcesresults.Result{ResourceID: otherID, AssociatedControls: []resourcesresults.ResourceAssociatedControl{other}}
	session.ResourceSource[otherID] = session.ResourceSource["apps/v1/Deployment/default/demo"]
	lw := localworkload.NewLocalWorkload(map[string]any{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"name": "other", "namespace": "default"},
		"spec":     map[string]any{},
	})
	lw.SetPath("deploy.yaml:0")
	session.AllResources[otherID] = lw

	raw := renderSARIF(t, NewSARIFPrinter(false), session)
	requireValidSARIF(t, raw)
	results := parseSARIFResults(t, raw)

	require.Len(t, results, 2)
	suppressed := 0
	for _, r := range results {
		if len(r.Suppressions) > 0 {
			suppressed++
		}
	}
	assert.Equal(t, 1, suppressed)
}

// A rule matched by a disable and an alertOnly exception passes, because only an
// all-alertOnly match keeps it failing. The disable exception is the one that
// suppressed it; the alertOnly exception stays acknowledgment metadata.
func TestSARIFExceptions_AlertOnlyAlongsideDisableIsNotASuppression(t *testing.T) {
	expires := time.Date(2030, 6, 1, 0, 0, 0, 0, time.UTC)
	disable := disableException("allow-privileged", strPtr("approved"))
	alert := alertOnlyException("known-issue", &expires)

	for name, attached := range map[string][]armotypes.PostureExceptionPolicy{
		"disable first":   {disable, alert},
		"alertOnly first": {alert, disable},
	} {
		t.Run(name, func(t *testing.T) {
			raw := renderSARIF(t, NewSARIFPrinter(false),
				sarifExceptionSession(t, sarifExceptionControl(failingRule("privileged", privilegedPath, attached...))))
			requireValidSARIF(t, raw)
			results := parseSARIFResults(t, raw)

			require.Len(t, results, 1, "the finding is reported once, as suppressed")
			require.Len(t, results[0].Suppressions, 1, "only the disable exception suppressed the finding")
			assert.Equal(t, "approved", *results[0].Suppressions[0].Justification)

			encoded, err := json.Marshal(results[0].Suppressions)
			require.NoError(t, err)
			assert.Contains(t, string(encoded), "allow-privileged")
			assert.NotContains(t, string(encoded), "known-issue", "alertOnly must not be recorded as an accepted suppression")

			assert.Equal(t, "alertOnly", results[0].Properties["exception-action"])
			assert.Equal(t, "known-issue", results[0].Properties["exception-names"])
			assert.Equal(t, "2030-06-01T00:00:00Z", results[0].Properties["exception-expiration"])
		})
	}
}

// Exceptions the printer cannot tell apart by name, reason or expiration are told
// apart by GUID, and the report still satisfies the schema's uniqueItems rule.
func TestSARIFExceptions_DistinctGUIDsStayDistinguishable(t *testing.T) {
	expires := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	build := func(guid string) armotypes.PostureExceptionPolicy {
		ex := disableException("shared-name", strPtr("same reason"))
		ex.GUID = guid
		ex.ExpirationDate = &expires
		return ex
	}
	first, second := build("11111111-aaaa"), build("22222222-bbbb")

	render := func(attached ...armotypes.PostureExceptionPolicy) []byte {
		return renderSARIF(t, NewSARIFPrinter(false),
			sarifExceptionSession(t, sarifExceptionControl(failingRule("privileged", privilegedPath, attached...))))
	}
	raw := render(second, first)
	requireValidSARIF(t, raw)
	results := parseSARIFResults(t, raw)

	require.Len(t, results, 1)
	require.Len(t, results[0].Suppressions, 2, "both distinct exception records are kept")
	guids := []any{
		results[0].Suppressions[0].Properties["exception-guid"],
		results[0].Suppressions[1].Properties["exception-guid"],
	}
	assert.Equal(t, []any{"11111111-aaaa", "22222222-bbbb"}, guids, "ordered by GUID")
	assert.NotEqual(t, results[0].Suppressions[0].Properties, results[0].Suppressions[1].Properties)

	// Same bytes on every run and whatever order the exceptions were attached in.
	// The report embeds a per-session temp path, so compare the results.
	results1 := parseSARIFResults(t, render(first, second))
	encode := func(r []*sarif.Result) string {
		b, err := json.Marshal(r[0].Suppressions)
		require.NoError(t, err)
		return string(b)
	}
	for i := 0; i < 5; i++ {
		assert.Equal(t, encode(results), encode(parseSARIFResults(t, render(second, first))))
	}
	assert.Equal(t, encode(results), encode(results1))
}

// A suppression with no name, GUID or expiration has nothing to put in
// properties, and must not serialize a null one.
func TestSARIFExceptions_SuppressionWithoutOptionalFieldsIsSchemaValid(t *testing.T) {
	raw := renderSARIF(t, NewSARIFPrinter(false),
		sarifExceptionSession(t, sarifExceptionControl(failingRule("privileged", privilegedPath, disableException("", nil)))))
	requireValidSARIF(t, raw)
	assert.NotContains(t, string(raw), `"properties": null`)
	assert.NotContains(t, string(raw), `"properties":null`)
	results := parseSARIFResults(t, raw)
	require.Len(t, results, 1)
	require.Len(t, results[0].Suppressions, 1)
}

// Identical GUID-less exceptions would serialize to identical suppressions, which
// the schema forbids; they are written once.
func TestSARIFExceptions_IndistinguishableSuppressionsAreWrittenOnce(t *testing.T) {
	a, b := disableException("same", strPtr("why")), disableException("same", strPtr(" why "))
	raw := renderSARIF(t, NewSARIFPrinter(false),
		sarifExceptionSession(t, sarifExceptionControl(failingRule("privileged", privilegedPath, a, b))))
	requireValidSARIF(t, raw)
	results := parseSARIFResults(t, raw)
	require.Len(t, results, 1)
	assert.Len(t, results[0].Suppressions, 1)
}
