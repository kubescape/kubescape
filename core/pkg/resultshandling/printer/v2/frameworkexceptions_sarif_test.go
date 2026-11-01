package printer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nsaException is scoped to the NSA framework, the shape opa-utils v0.0.315
// records on a rule: the control and rule keep their raw failed status.
func frameworkException(frameworkName string, action armotypes.PostureExceptionPolicyActions) armotypes.PostureExceptionPolicy {
	name := "nsa-only-hostnetwork"
	if frameworkName != "NSA" {
		name = frameworkName + "-only-hostnetwork"
	}
	return armotypes.PostureExceptionPolicy{
		PortalBase:      armotypes.PortalBase{Name: name},
		PolicyType:      string(armotypes.PostureExceptionPolicyType),
		Actions:         []armotypes.PostureExceptionPolicyActions{action},
		PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: frameworkName, ControlID: testHostNetworkControl}},
	}
}

// nsaException is scoped to the NSA framework, the shape opa-utils v0.0.315
// records on a rule: the control and rule keep their raw failed status.
func nsaException(action armotypes.PostureExceptionPolicyActions) armotypes.PostureExceptionPolicy {
	return frameworkException("NSA", action)
}

func agnosticException(action armotypes.PostureExceptionPolicyActions) armotypes.PostureExceptionPolicy {
	return armotypes.PostureExceptionPolicy{
		PortalBase:      armotypes.PortalBase{Name: "agnostic-hostnetwork"},
		PolicyType:      string(armotypes.PostureExceptionPolicyType),
		Actions:         []armotypes.PostureExceptionPolicyActions{action},
		PosturePolicies: []armotypes.PosturePolicy{{ControlID: testHostNetworkControl}},
	}
}

func sarifFrameworkSessionWithExceptions(t *testing.T, withActiveRule bool, frameworks []string, ruleExceptions ...armotypes.PostureExceptionPolicy) *cautils.OPASessionObj {
	t.Helper()
	rules := []resourcesresults.ResourceAssociatedRule{{
		Name:      "host-network-access",
		Status:    apis.StatusFailed,
		Paths:     []armotypes.PosturePaths{{FixPath: armotypes.FixPath{Path: hostNetworkFixPath, Value: "false"}}},
		Exception: ruleExceptions,
	}}
	if withActiveRule {
		rules = append(rules, resourcesresults.ResourceAssociatedRule{
			Name:   "host-pid-access",
			Status: apis.StatusFailed,
			Paths:  []armotypes.PosturePaths{{FixPath: armotypes.FixPath{Path: hostPIDFixPath, Value: "false"}}},
		})
	}
	ac := resourcesresults.ResourceAssociatedControl{
		ControlID:               testHostNetworkControl,
		Name:                    "HostNetwork access",
		Status:                  apis.StatusInfo{InnerStatus: apis.StatusFailed},
		ResourceAssociatedRules: rules,
	}

	session := sarifExceptionSession(t, ac)
	for _, source := range session.ResourceSource {
		require.NoError(t, os.WriteFile(filepath.Join(source.Path, source.RelativePath), []byte(locationManifest), 0o600))
	}
	controls := reportsummary.ControlSummaries{
		testHostNetworkControl: {ControlID: testHostNetworkControl, Name: "HostNetwork access", ScoreFactor: 8.0},
	}
	session.Report.SummaryDetails.Controls = controls
	for _, name := range frameworks {
		session.Report.SummaryDetails.Frameworks = append(session.Report.SummaryDetails.Frameworks, reportsummary.FrameworkSummary{Name: name, Controls: controls})
	}
	return session
}

func sarifFrameworkSession(t *testing.T, action armotypes.PostureExceptionPolicyActions, withActiveRule bool, frameworks ...string) *cautils.OPASessionObj {
	return sarifFrameworkSessionWithExceptions(t, withActiveRule, frameworks, nsaException(action))
}

func sarifStartLine(t *testing.T, result *sarif.Result) int {
	t.Helper()
	require.NotEmpty(t, result.Locations)
	require.NotNil(t, result.Locations[0].PhysicalLocation)
	require.NotNil(t, result.Locations[0].PhysicalLocation.Region)
	require.NotNil(t, result.Locations[0].PhysicalLocation.Region.StartLine)
	return *result.Locations[0].PhysicalLocation.Region.StartLine
}

// splitVisibleAndSuppressed separates the results of a report by whether they
// carry a suppression.
func splitVisibleAndSuppressed(results []*sarif.Result) (visible, suppressed []*sarif.Result) {
	for _, r := range results {
		if len(r.Suppressions) > 0 {
			suppressed = append(suppressed, r)
		} else {
			visible = append(visible, r)
		}
	}
	return visible, suppressed
}

func TestSARIFFrameworkExceptions_PartlyExceptedControl(t *testing.T) {
	session := sarifFrameworkSession(t, armotypes.Disable, true, "NSA")
	raw := renderSARIF(t, NewSARIFPrinter(false), session)
	requireValidSARIF(t, raw)

	visible, suppressed := splitVisibleAndSuppressed(parseSARIFResults(t, raw))
	require.Len(t, visible, 1)
	require.Len(t, suppressed, 1)

	assert.Equal(t, hostPIDLine, sarifStartLine(t, visible[0]), "the visible finding points at the rule that still fails")
	assert.Equal(t, hostNetworkLine, sarifStartLine(t, suppressed[0]), "the audit result keeps the excepted rule's finding")
	require.Len(t, suppressed[0].Suppressions, 1)
	assert.Equal(t, "external", suppressed[0].Suppressions[0].Kind)
	assert.Equal(t, "nsa-only-hostnetwork", suppressed[0].Suppressions[0].Properties["exception-name"])
	assert.NotEqual(t, fingerprintOf(t, visible[0]), fingerprintOf(t, suppressed[0]))
}

func TestSARIFFrameworkExceptions_FullyExceptedControlOnlyKeepsAuditResult(t *testing.T) {
	session := sarifFrameworkSession(t, armotypes.Disable, false, "NSA")
	raw := renderSARIF(t, NewSARIFPrinter(false), session)
	requireValidSARIF(t, raw)

	visible, suppressed := splitVisibleAndSuppressed(parseSARIFResults(t, raw))
	assert.Empty(t, visible, "nothing actionable is reported")
	require.Len(t, suppressed, 1, "the exception leaves an audit trail")
	assert.Equal(t, hostNetworkLine, sarifStartLine(t, suppressed[0]))

	// the scan's own evaluation is not rewritten to produce the report
	for _, result := range session.ResourcesResult {
		rule := result.AssociatedControls[0].ResourceAssociatedRules[0]
		assert.Equal(t, apis.StatusFailed, rule.Status)
		assert.Len(t, rule.Exception, 1)
	}
}

func TestSARIFFrameworkExceptions_OtherFrameworkIsNotSuppressed(t *testing.T) {
	for _, tc := range []struct {
		name       string
		frameworks []string
	}{
		{"framework without the exception", []string{"MITRE"}},
		{"excepted and unexcepted frameworks together", []string{"NSA", "MITRE"}},
		{"no framework context", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session := sarifFrameworkSession(t, armotypes.Disable, true, tc.frameworks...)
			raw := renderSARIF(t, NewSARIFPrinter(false), session)
			requireValidSARIF(t, raw)

			visible, suppressed := splitVisibleAndSuppressed(parseSARIFResults(t, raw))
			assert.Empty(t, suppressed)
			require.Len(t, visible, 1)
			assert.Equal(t, hostNetworkLine, sarifStartLine(t, visible[0]), "the rule is still actionable, so it is the first fix")
			assert.NotContains(t, visible[0].Properties, "exception-action", "a disable exception scoped to another framework is not an acknowledgement")
			assert.NotContains(t, visible[0].Properties, "exception-names")
		})
	}
}

func TestSARIFFrameworkExceptions_AlertOnlyIsNotASuppression(t *testing.T) {
	session := sarifFrameworkSession(t, armotypes.AlertOnly, true, "NSA")
	raw := renderSARIF(t, NewSARIFPrinter(false), session)
	requireValidSARIF(t, raw)

	visible, suppressed := splitVisibleAndSuppressed(parseSARIFResults(t, raw))
	assert.Empty(t, suppressed)
	require.Len(t, visible, 1)
	assert.Equal(t, hostNetworkLine, sarifStartLine(t, visible[0]))
	assert.Equal(t, "alertOnly", visible[0].Properties["exception-action"])
}

func TestSARIFFrameworkExceptions_ReportIsStable(t *testing.T) {
	first := renderSARIF(t, NewSARIFPrinter(false), sarifFrameworkSession(t, armotypes.Disable, true, "NSA"))
	second := renderSARIF(t, NewSARIFPrinter(false), sarifFrameworkSession(t, armotypes.Disable, true, "NSA"))

	firstVisible, firstSuppressed := splitVisibleAndSuppressed(parseSARIFResults(t, first))
	secondVisible, secondSuppressed := splitVisibleAndSuppressed(parseSARIFResults(t, second))
	require.Len(t, firstVisible, 1)
	require.Len(t, secondVisible, 1)
	require.Len(t, firstSuppressed, 1)
	require.Len(t, secondSuppressed, 1)
	assert.Equal(t, fingerprintOf(t, firstVisible[0]), fingerprintOf(t, secondVisible[0]))
	assert.Equal(t, fingerprintOf(t, firstSuppressed[0]), fingerprintOf(t, secondSuppressed[0]))
}

func TestSARIFFrameworkExceptions_AgnosticExceptionAcrossFrameworks(t *testing.T) {
	t.Run("disable suppresses across multiple frameworks without duplicating suppressions", func(t *testing.T) {
		session := sarifFrameworkSessionWithExceptions(t, true, []string{"NSA", "MITRE"}, agnosticException(armotypes.Disable))
		raw := renderSARIF(t, NewSARIFPrinter(false), session)
		requireValidSARIF(t, raw)

		visible, suppressed := splitVisibleAndSuppressed(parseSARIFResults(t, raw))
		require.Len(t, visible, 1, "the unexcepted rule remains visible")
		assert.Equal(t, hostPIDLine, sarifStartLine(t, visible[0]))

		require.Len(t, suppressed, 1, "excepted rule is suppressed")
		assert.Equal(t, hostNetworkLine, sarifStartLine(t, suppressed[0]))
		require.Len(t, suppressed[0].Suppressions, 1, "framework-agnostic exception matching multiple frameworks must not duplicate suppressions")
		assert.Equal(t, "external", suppressed[0].Suppressions[0].Kind)
		assert.Equal(t, "agnostic-hostnetwork", suppressed[0].Suppressions[0].Properties["exception-name"])
	})

	t.Run("fully excepted control with policy-less exception across 3 frameworks", func(t *testing.T) {
		ex := disableException("policy-less-agnostic", nil)
		session := sarifFrameworkSessionWithExceptions(t, false, []string{"NSA", "MITRE", "CIS"}, ex)
		raw := renderSARIF(t, NewSARIFPrinter(false), session)
		requireValidSARIF(t, raw)

		visible, suppressed := splitVisibleAndSuppressed(parseSARIFResults(t, raw))
		assert.Empty(t, visible, "nothing actionable is reported")
		require.Len(t, suppressed, 1, "audit result is reported")
		require.Len(t, suppressed[0].Suppressions, 1, "suppression is recorded exactly once")
		assert.Equal(t, "policy-less-agnostic", suppressed[0].Suppressions[0].Properties["exception-name"])
	})

	t.Run("alertOnly acknowledges across multiple frameworks without duplicating names", func(t *testing.T) {
		session := sarifFrameworkSessionWithExceptions(t, false, []string{"NSA", "MITRE"}, agnosticException(armotypes.AlertOnly))
		raw := renderSARIF(t, NewSARIFPrinter(false), session)
		requireValidSARIF(t, raw)

		visible, suppressed := splitVisibleAndSuppressed(parseSARIFResults(t, raw))
		assert.Empty(t, suppressed, "alertOnly does not suppress")
		require.Len(t, visible, 1)
		assert.Equal(t, hostNetworkLine, sarifStartLine(t, visible[0]))
		assert.Equal(t, "alertOnly", visible[0].Properties["exception-action"])
		assert.Equal(t, "agnostic-hostnetwork", visible[0].Properties["exception-names"])
	})
}

func TestSARIFFrameworkExceptions_MixedAlertOnlyAndDisable(t *testing.T) {
	t.Run("rule with disable in one framework and alertOnly in another stays visible in combined scan", func(t *testing.T) {
		nsaDisable := frameworkException("NSA", armotypes.Disable)
		mitreAlert := frameworkException("MITRE", armotypes.AlertOnly)

		// When both frameworks are scanned, MITRE keeps the rule failing.
		// The disable exception does not suppress it, and only the alertOnly exception acknowledges it.
		session := sarifFrameworkSessionWithExceptions(t, false, []string{"NSA", "MITRE"}, nsaDisable, mitreAlert)
		raw := renderSARIF(t, NewSARIFPrinter(false), session)
		requireValidSARIF(t, raw)

		visible, suppressed := splitVisibleAndSuppressed(parseSARIFResults(t, raw))
		assert.Empty(t, suppressed, "the finding is not suppressed because MITRE still failed the rule")
		require.Len(t, visible, 1, "the finding stays visible")
		assert.Equal(t, hostNetworkLine, sarifStartLine(t, visible[0]))
		assert.Equal(t, "alertOnly", visible[0].Properties["exception-action"])
		assert.Equal(t, "MITRE-only-hostnetwork", visible[0].Properties["exception-names"])
		assert.NotContains(t, visible[0].Properties["exception-names"], "nsa-only-hostnetwork")
	})

	t.Run("rule with disable in NSA and alertOnly in MITRE suppresses when scanning NSA alone", func(t *testing.T) {
		nsaDisable := frameworkException("NSA", armotypes.Disable)
		mitreAlert := frameworkException("MITRE", armotypes.AlertOnly)

		session := sarifFrameworkSessionWithExceptions(t, false, []string{"NSA"}, nsaDisable, mitreAlert)
		raw := renderSARIF(t, NewSARIFPrinter(false), session)
		requireValidSARIF(t, raw)

		visible, suppressed := splitVisibleAndSuppressed(parseSARIFResults(t, raw))
		assert.Empty(t, visible)
		require.Len(t, suppressed, 1)
		require.Len(t, suppressed[0].Suppressions, 1)
		assert.Equal(t, "nsa-only-hostnetwork", suppressed[0].Suppressions[0].Properties["exception-name"])
	})

	t.Run("rule with disable in NSA and alertOnly in MITRE is visible alertOnly when scanning MITRE alone", func(t *testing.T) {
		nsaDisable := frameworkException("NSA", armotypes.Disable)
		mitreAlert := frameworkException("MITRE", armotypes.AlertOnly)

		session := sarifFrameworkSessionWithExceptions(t, false, []string{"MITRE"}, nsaDisable, mitreAlert)
		raw := renderSARIF(t, NewSARIFPrinter(false), session)
		requireValidSARIF(t, raw)

		visible, suppressed := splitVisibleAndSuppressed(parseSARIFResults(t, raw))
		assert.Empty(t, suppressed)
		require.Len(t, visible, 1)
		assert.Equal(t, "alertOnly", visible[0].Properties["exception-action"])
		assert.Equal(t, "MITRE-only-hostnetwork", visible[0].Properties["exception-names"])
	})

	t.Run("control with one disabled rule and one alertOnly rule splits cleanly", func(t *testing.T) {
		disableEx := armotypes.PostureExceptionPolicy{
			PortalBase:      armotypes.PortalBase{Name: "nsa-disable-hostnetwork"},
			PolicyType:      string(armotypes.PostureExceptionPolicyType),
			Actions:         []armotypes.PostureExceptionPolicyActions{armotypes.Disable},
			PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: "NSA", ControlID: testHostNetworkControl}},
		}
		alertEx := armotypes.PostureExceptionPolicy{
			PortalBase:      armotypes.PortalBase{Name: "nsa-alert-hostpid"},
			PolicyType:      string(armotypes.PostureExceptionPolicyType),
			Actions:         []armotypes.PostureExceptionPolicyActions{armotypes.AlertOnly},
			PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: "NSA", ControlID: testHostNetworkControl}},
		}
		rules := []resourcesresults.ResourceAssociatedRule{
			{
				Name:      "host-network-access",
				Status:    apis.StatusFailed,
				Paths:     []armotypes.PosturePaths{{FixPath: armotypes.FixPath{Path: hostNetworkFixPath, Value: "false"}}},
				Exception: []armotypes.PostureExceptionPolicy{disableEx},
			},
			{
				Name:      "host-pid-access",
				Status:    apis.StatusFailed,
				Paths:     []armotypes.PosturePaths{{FixPath: armotypes.FixPath{Path: hostPIDFixPath, Value: "false"}}},
				Exception: []armotypes.PostureExceptionPolicy{alertEx},
			},
		}
		ac := resourcesresults.ResourceAssociatedControl{
			ControlID:               testHostNetworkControl,
			Name:                    "HostNetwork access",
			Status:                  apis.StatusInfo{InnerStatus: apis.StatusFailed},
			ResourceAssociatedRules: rules,
		}

		session := sarifExceptionSession(t, ac)
		for _, source := range session.ResourceSource {
			require.NoError(t, os.WriteFile(filepath.Join(source.Path, source.RelativePath), []byte(locationManifest), 0o600))
		}
		controls := reportsummary.ControlSummaries{
			testHostNetworkControl: {ControlID: testHostNetworkControl, Name: "HostNetwork access", ScoreFactor: 8.0},
		}
		session.Report.SummaryDetails.Controls = controls
		session.Report.SummaryDetails.Frameworks = []reportsummary.FrameworkSummary{
			{Name: "NSA", Controls: controls},
		}

		raw := renderSARIF(t, NewSARIFPrinter(false), session)
		requireValidSARIF(t, raw)

		visible, suppressed := splitVisibleAndSuppressed(parseSARIFResults(t, raw))
		require.Len(t, visible, 1, "alertOnly rule stays visible")
		assert.Equal(t, hostPIDLine, sarifStartLine(t, visible[0]))
		assert.Empty(t, visible[0].Suppressions)
		assert.Equal(t, "alertOnly", visible[0].Properties["exception-action"])
		assert.Equal(t, "nsa-alert-hostpid", visible[0].Properties["exception-names"])

		require.Len(t, suppressed, 1, "disabled rule is suppressed")
		assert.Equal(t, hostNetworkLine, sarifStartLine(t, suppressed[0]))
		require.Len(t, suppressed[0].Suppressions, 1)
		assert.Equal(t, "external", suppressed[0].Suppressions[0].Kind)
		assert.Equal(t, "nsa-disable-hostnetwork", suppressed[0].Suppressions[0].Properties["exception-name"])

		assert.NotEqual(t, fingerprintOf(t, visible[0]), fingerprintOf(t, suppressed[0]))
	})

	t.Run("rule with both disable and alertOnly in scanned framework suppresses and keeps alertOnly metadata", func(t *testing.T) {
		disable := frameworkException("NSA", armotypes.Disable)
		alert := armotypes.PostureExceptionPolicy{
			PortalBase:      armotypes.PortalBase{Name: "nsa-audit-ack"},
			PolicyType:      string(armotypes.PostureExceptionPolicyType),
			Actions:         []armotypes.PostureExceptionPolicyActions{armotypes.AlertOnly},
			PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: "NSA", ControlID: testHostNetworkControl}},
		}

		session := sarifFrameworkSessionWithExceptions(t, false, []string{"NSA"}, disable, alert)
		raw := renderSARIF(t, NewSARIFPrinter(false), session)
		requireValidSARIF(t, raw)

		visible, suppressed := splitVisibleAndSuppressed(parseSARIFResults(t, raw))
		assert.Empty(t, visible)
		require.Len(t, suppressed, 1)
		require.Len(t, suppressed[0].Suppressions, 1)
		assert.Equal(t, "nsa-only-hostnetwork", suppressed[0].Suppressions[0].Properties["exception-name"])
		assert.Equal(t, "alertOnly", suppressed[0].Properties["exception-action"])
		assert.Equal(t, "nsa-audit-ack", suppressed[0].Properties["exception-names"])
	})
}
