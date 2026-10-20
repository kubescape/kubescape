package printer

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/exceptions"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

// SARIF 2.1.0 suppression vocabulary (sections 3.35.3 and 3.35.4). An exception is
// kept outside the scanned manifest, in an exceptions file or a SecurityException
// CRD, so it is an "external" suppression, and the scan accepted the finding.
const (
	sarifSuppressionKindExternal   = "external"
	sarifSuppressionStatusAccepted = "accepted"
)

// sarifExceptionSplit is a control's failing rules sorted by what the exception
// processor decided about them. The decision is read from the rule's effective
// status, not recomputed here, so an exception that was expired, scoped to
// another framework or otherwise inapplicable never reaches the report: the
// processor already left the rule failing.
type sarifExceptionSplit struct {
	// visible is the control without the rules a disable exception removed. It
	// is what an ordinary result is built from.
	visible resourcesresults.ResourceAssociatedControl
	// suppressed is the control reduced to the rules a disable exception removed,
	// reported as failing so the finding is built exactly as it would have been
	// without the exception.
	suppressed resourcesresults.ResourceAssociatedControl
	// hasSuppressed reports whether any rule was removed by a disable exception.
	hasSuppressed bool
	// suppressingExceptions are the exceptions behind the suppressed rules that
	// actually removed the finding. An alertOnly exception that matched the same
	// rule is not among them: it never suppresses.
	suppressingExceptions []armotypes.PostureExceptionPolicy
	// suppressedAlertOnlyExceptions are the alertOnly exceptions that matched a
	// suppressed rule alongside a disable exception. They acknowledge the finding
	// but did not decide its status.
	suppressedAlertOnlyExceptions []armotypes.PostureExceptionPolicy
	// alertOnlyExceptions are the exceptions that acknowledged a rule that is
	// still failing.
	alertOnlyExceptions []armotypes.PostureExceptionPolicy
}

// splitSARIFExceptions classifies the rules of ac. A rule whose raw status is
// failed and whose effective status carries the exception sub-status was
// affected by an exception: passed means a disable action removed the finding,
// failed means alertOnly acknowledged it.
func splitSARIFExceptions(ac resourcesresults.ResourceAssociatedControl) sarifExceptionSplit {
	split := sarifExceptionSplit{visible: ac, suppressed: ac}
	var visibleRules, suppressedRules []resourcesresults.ResourceAssociatedRule

	for _, rule := range ac.ResourceAssociatedRules {
		effective := rule.GetStatus(nil)
		if rule.Status != apis.StatusFailed || effective.GetSubStatus() != apis.SubStatusException {
			visibleRules = append(visibleRules, rule)
			continue
		}
		// These are the same exceptions the processor matched, selected with the
		// same filter it used to decide the rule's status.
		matched := exceptions.FilterExceptionsByFrameworks(rule.Exception, nil, ac.ControlID, rule.GetName())
		if effective.IsPassed() {
			// The rule passes when any matched exception is not alertOnly, so the
			// matches may mix actions. Only a non-alertOnly exception removed the
			// finding, which is the processor's own test (allExceptionsAlertOnly).
			for _, e := range matched {
				if e.IsAlertOnly() {
					split.suppressedAlertOnlyExceptions = append(split.suppressedAlertOnlyExceptions, e)
				} else {
					split.suppressingExceptions = append(split.suppressingExceptions, e)
				}
			}
			// The copy reports the rule as failing, as it did before the exception.
			rule.Exception = nil
			suppressedRules = append(suppressedRules, rule)
			continue
		}
		split.alertOnlyExceptions = append(split.alertOnlyExceptions, matched...)
		visibleRules = append(visibleRules, rule)
	}

	if len(suppressedRules) > 0 {
		split.hasSuppressed = true
		split.visible.ResourceAssociatedRules = visibleRules
		split.suppressed.ResourceAssociatedRules = suppressedRules
	}
	split.suppressingExceptions = uniqueSortedExceptions(split.suppressingExceptions)
	split.suppressedAlertOnlyExceptions = uniqueSortedExceptions(split.suppressedAlertOnlyExceptions)
	split.alertOnlyExceptions = uniqueSortedExceptions(split.alertOnlyExceptions)
	return split
}

// isSARIFSuppressedControl reports whether a disable exception removed at least
// one failing rule of ac and the control was otherwise evaluated.
func isSARIFSuppressedControl(ac resourcesresults.ResourceAssociatedControl) bool {
	return !ac.GetStatus(nil).IsSkipped() && splitSARIFExceptions(ac).hasSuppressed
}

// hasSARIFSuppressedFinding reports whether any control of result carries a
// finding a disable exception removed. Such a resource is not failing, but it
// still has something to report.
func hasSARIFSuppressedFinding(result resourcesresults.Result) bool {
	for _, ac := range result.AssociatedControls {
		if isSARIFSuppressedControl(ac) {
			return true
		}
	}
	return false
}

// uniqueSortedExceptions drops repeats of one exception, which several rules of
// a control commonly share, and orders the rest so the report does not depend on
// the order rules or exceptions were evaluated in. Two exceptions are the same
// only when everything the report shows of them is the same, so distinct records
// that share a name stay distinct.
func uniqueSortedExceptions(list []armotypes.PostureExceptionPolicy) []armotypes.PostureExceptionPolicy {
	if len(list) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(list))
	unique := make([]armotypes.PostureExceptionPolicy, 0, len(list))
	for _, e := range list {
		key := strings.Join([]string{e.GUID, e.Name, sarifExceptionReason(e), sarifExceptionExpiration(e)}, "\x00")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, e)
	}
	sort.SliceStable(unique, func(i, j int) bool {
		a, b := unique[i], unique[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.GUID != b.GUID {
			return a.GUID < b.GUID
		}
		if ra, rb := sarifExceptionReason(a), sarifExceptionReason(b); ra != rb {
			return ra < rb
		}
		return sarifExceptionExpiration(a) < sarifExceptionExpiration(b)
	})
	return unique
}

// sarifExceptionReason is the exception's reason without surrounding space, or
// "" when it gave none.
func sarifExceptionReason(e armotypes.PostureExceptionPolicy) string {
	if e.Reason == nil {
		return ""
	}
	return strings.TrimSpace(*e.Reason)
}

// sarifExceptionExpiration is the exception's expiration as it is written to the
// report, or "" when it never expires.
func sarifExceptionExpiration(e armotypes.PostureExceptionPolicy) string {
	if e.ExpirationDate == nil {
		return ""
	}
	return e.ExpirationDate.UTC().Format(time.RFC3339)
}

// sarifSuppression is a SARIF suppression object. sarif.Suppression is not used
// because it marshals every unset pointer field as null, and a null location,
// guid or justification is not valid in the schema.
type sarifSuppression struct {
	Kind          string         `json:"kind"`
	Status        string         `json:"status"`
	Justification string         `json:"justification,omitempty"`
	Properties    map[string]any `json:"properties,omitempty"`
}

// sarifSuppressedResult is a result carrying schema-valid suppressions. The outer
// Suppressions field shadows sarif.Result's, so only this field is written.
type sarifSuppressedResult struct {
	*sarif.Result
	Suppressions []sarifSuppression `json:"suppressions"`
}

// newSARIFSuppressedResult attaches one suppression per exception to result.
//
// The schema requires the suppressions of a result to be unique, and the
// exception's identity is not a standard suppression field, so it is written to
// the suppression's property bag: exception-guid is what tells two exceptions
// apart that share a name, reason and expiration. Suppressions that are still
// identical once serialized, which are exceptions without a GUID that the report
// cannot tell apart either, are written once.
func newSARIFSuppressedResult(result *sarif.Result, list []armotypes.PostureExceptionPolicy) sarifSuppressedResult {
	suppressions := make([]sarifSuppression, 0, len(list))
	seen := make(map[string]struct{}, len(list))
	for _, e := range list {
		suppression := sarifSuppression{
			Kind:          sarifSuppressionKindExternal,
			Status:        sarifSuppressionStatusAccepted,
			Justification: sarifExceptionJustification(e),
			Properties:    make(map[string]any),
		}
		if e.Name != "" {
			suppression.Properties["exception-name"] = e.Name
		}
		if e.GUID != "" {
			suppression.Properties["exception-guid"] = e.GUID
		}
		if expiration := sarifExceptionExpiration(e); expiration != "" {
			suppression.Properties["exception-expiration"] = expiration
		}
		if len(suppression.Properties) == 0 {
			suppression.Properties = nil
		}
		// Properties is a map, which encoding/json writes with sorted keys, so the
		// encoding is a canonical identity.
		identity, err := json.Marshal(suppression)
		if err == nil {
			if _, ok := seen[string(identity)]; ok {
				continue
			}
			seen[string(identity)] = struct{}{}
		}
		suppressions = append(suppressions, suppression)
	}
	return sarifSuppressedResult{Result: result, Suppressions: suppressions}
}

// sarifExceptionJustification explains a suppression: the exception's own reason
// when it gave one, otherwise the exception's name.
func sarifExceptionJustification(e armotypes.PostureExceptionPolicy) string {
	if reason := sarifExceptionReason(e); reason != "" {
		return reason
	}
	if e.Name != "" {
		return fmt.Sprintf("Accepted by exception %q", e.Name)
	}
	return "Accepted by a scan exception"
}

// addSARIFAlertOnlyProperties records the exceptions that acknowledged a finding
// that stays visible. The finding is not suppressed: alertOnly exists to keep it
// counting while saying why it is known.
func addSARIFAlertOnlyProperties(result *sarif.Result, list []armotypes.PostureExceptionPolicy) {
	if len(list) == 0 {
		return
	}
	if result.Properties == nil {
		result.Properties = make(sarif.Properties)
	}
	names := make([]string, 0, len(list))
	var earliest *time.Time
	for _, e := range list {
		if e.Name != "" {
			names = append(names, e.Name)
		}
		if e.ExpirationDate != nil && (earliest == nil || e.ExpirationDate.Before(*earliest)) {
			earliest = e.ExpirationDate
		}
	}
	result.Properties["exception-action"] = "alertOnly"
	if len(names) > 0 {
		result.Properties["exception-names"] = strings.Join(names, ", ")
	}
	if earliest != nil {
		result.Properties["exception-expiration"] = earliest.UTC().Format(time.RFC3339)
	}
}
