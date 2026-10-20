package opaprocessor

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/anonymizer"
	"github.com/kubescape/kubescape/v4/core/pkg/reportcrypto"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	printerv2 "github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	sarifPrivacyControlID = "C-0057"
	// Distinctive values that must never reach an anonymized report.
	sarifPrivacyNamespace = "payroll-ns-7731"
	sarifPrivacyName      = "salary-batch-4471"
	sarifPrivacyReason    = "waiver-for-incident-INC9482-owner-jdoe"
)

// sarifPrivacySession is a scan result for one Deployment that failed a rule and
// carries the kubescape.io/skip-* annotations. Exceptions are attached to it by
// the processor, not by the test.
func sarifPrivacySession(t *testing.T) (*cautils.OPASessionObj, string) {
	t.Helper()
	manifestDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(manifestDir, "deploy.yaml"), []byte("apiVersion: apps/v1\nkind: Deployment\n"), 0o600))

	deployment := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]any{
			"name":      sarifPrivacyName,
			"namespace": sarifPrivacyNamespace,
			"annotations": map[string]any{
				skipControlsAnnotation: sarifPrivacyControlID,
				skipReasonAnnotation:   sarifPrivacyReason,
			},
		},
		"spec": map[string]any{},
	})
	id := deployment.GetID()

	session := cautils.NewOPASessionObjMock()
	session.AllResources[id] = deployment
	session.ResourceSource = map[string]reporthandling.Source{
		id: {Path: manifestDir, RelativePath: "deploy.yaml", FileType: reporthandling.SourceTypeYaml},
	}
	session.Metadata = &reporthandlingv2.Metadata{
		ScanMetadata: reporthandlingv2.ScanMetadata{ScanningTarget: reporthandlingv2.File},
		ContextMetadata: reporthandlingv2.ContextMetadata{
			FileContextMetadata: &reporthandlingv2.FileContextMetadata{FilePath: filepath.Join(manifestDir, "deploy.yaml")},
		},
	}
	session.Report.SummaryDetails.Controls = reportsummary.ControlSummaries{
		sarifPrivacyControlID: {ControlID: sarifPrivacyControlID, Name: "Privileged container", ScoreFactor: 8},
	}
	session.ResourcesResult[id] = resourcesresults.Result{
		ResourceID: id,
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{{
			ControlID: sarifPrivacyControlID,
			Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
			ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{
				Name:   "privileged",
				Status: apis.StatusFailed,
				Paths: []armotypes.PosturePaths{{
					FailedPath: "spec.template.spec.containers[0].securityContext.privileged",
					FixPath:    armotypes.FixPath{Path: "spec.template.spec.containers[0].securityContext.privileged", Value: "false"},
				}},
			}},
		}},
	}
	session.AllPolicies = &cautils.Policies{Controls: map[string]reporthandling.Control{
		sarifPrivacyControlID: {ControlID: sarifPrivacyControlID},
	}}
	return session, id
}

// renderPipelineSARIF runs the production steps in their production order, the
// processor's exception handling, then the anonymization apply returns, then the
// SARIF printer, and returns the serialized report.
func renderPipelineSARIF(t *testing.T, anonymize func(*resultshandling.ResultsHandler) error) string {
	t.Helper()
	session, _ := sarifPrivacySession(t)

	opap := &OPAProcessor{OPASessionObj: session}
	opap.HonorInlineExceptions = true
	opap.updateResults(context.Background())

	handler := &resultshandling.ResultsHandler{ScanData: session}
	if anonymize != nil {
		require.NoError(t, anonymize(handler))
	}

	out := filepath.Join(t.TempDir(), "report.sarif")
	sp := printerv2.NewSARIFPrinter(false)
	require.NoError(t, sp.SetWriter(context.Background(), out))
	require.NoError(t, sp.ActionPrint(context.Background(), handler.ScanData, nil))
	raw, err := os.ReadFile(out)
	require.NoError(t, err)
	return string(raw)
}

func TestSARIFExceptionAuditTrail_PreservedWithoutAnonymization(t *testing.T) {
	report := renderPipelineSARIF(t, nil)

	assert.Contains(t, report, `"suppressions"`)
	assert.Contains(t, report, sarifPrivacyReason, "the skip reason is the suppression justification")
	assert.Contains(t, report, "inline-", "the inline exception name is recorded")
	assert.Contains(t, report, sarifPrivacyName)
}

func TestSARIFExceptionAuditTrail_HideKeepsOriginalIdentifiersOut(t *testing.T) {
	report := renderPipelineSARIF(t, func(h *resultshandling.ResultsHandler) error { return anonymizer.Apply(h) })

	assertSARIFExceptionTrailAnonymized(t, report)
}

func TestSARIFExceptionAuditTrail_EncryptKeepsOriginalIdentifiersOut(t *testing.T) {
	dek, err := reportcrypto.GenerateDEK()
	require.NoError(t, err)
	masterKey, err := reportcrypto.GenerateDEK()
	require.NoError(t, err)

	report := renderPipelineSARIF(t, func(h *resultshandling.ResultsHandler) error {
		return anonymizer.ApplyEncrypted(h, dek, masterKey)
	})

	assertSARIFExceptionTrailAnonymized(t, report)
}

// assertSARIFExceptionTrailAnonymized checks the serialized report, where a
// reader would find a leak: none of the original identifiers or the reason may
// appear anywhere, yet the finding must still be reported as suppressed with a
// justification and an exception name.
func assertSARIFExceptionTrailAnonymized(t *testing.T, report string) {
	t.Helper()
	for _, secret := range []string{sarifPrivacyNamespace, sarifPrivacyName, sarifPrivacyReason, "INC9482", "jdoe", "payroll", "salary"} {
		assert.NotContains(t, report, secret, "%q leaked into the serialized SARIF report", secret)
	}
	assert.Contains(t, report, `"suppressions"`, "the audit trail survives anonymization")
	assert.Contains(t, report, `"justification"`)
	assert.Contains(t, report, `"exception-name"`)
}
