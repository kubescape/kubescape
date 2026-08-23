package printer

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/yaml"
)

const (
	policyReportOutputFile = "report"

	policyReportAPIVersion  = "wgpolicyk8s.io/v1alpha2"
	policyReportKind        = "PolicyReport"
	clusterPolicyReportKind = "ClusterPolicyReport"

	policyReportSource = "kubescape"

	policyReportResultPass = "pass"
	policyReportResultFail = "fail"
	policyReportResultSkip = "skip"

	// Limits the apiserver enforces on the two fields these reports derive from a cluster name.
	maxPolicyReportNameLength       = validation.DNS1123SubdomainMaxLength
	maxPolicyReportLabelValueLength = validation.LabelValueMaxLength
)

var _ printer.IPrinter = &PolicyReportPrinter{}

type PolicyReportPrinter struct {
	writer *os.File
}

type policyReport struct {
	APIVersion string               `json:"apiVersion"`
	Kind       string               `json:"kind"`
	Metadata   policyReportMeta     `json:"metadata"`
	Scope      *policyReportScope   `json:"scope,omitempty"`
	Results    []policyReportResult `json:"results"`
	Summary    policyReportSummary  `json:"summary"`
}

type policyReportMeta struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

type policyReportScope struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
}

type policyReportResult struct {
	Source     string                    `json:"source"`
	Policy     string                    `json:"policy"`
	Rule       string                    `json:"rule,omitempty"`
	Category   string                    `json:"category,omitempty"`
	Severity   string                    `json:"severity,omitempty"`
	Result     string                    `json:"result"`
	Message    string                    `json:"message,omitempty"`
	Timestamp  metav1.Time               `json:"timestamp,omitempty"`
	Resources  []policyReportResourceRef `json:"resources,omitempty"`
	Properties map[string]string         `json:"properties,omitempty"`
}

type policyReportResourceRef struct {
	APIVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind,omitempty"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name,omitempty"`
}

type policyReportSummary struct {
	Pass  int `json:"pass"`
	Fail  int `json:"fail"`
	Warn  int `json:"warn"`
	Error int `json:"error"`
	Skip  int `json:"skip"`
}

func NewPolicyReportPrinter() *PolicyReportPrinter {
	return &PolicyReportPrinter{}
}

func (pp *PolicyReportPrinter) SetWriter(ctx context.Context, outputFile string) error {
	outputFile, explicitOutput := printer.ResolveOutputFile(printer.PolicyReportFormat, outputFile, policyReportOutputFile)
	if explicitOutput {
		var err error
		pp.writer, err = printer.GetWriterNoFallback(outputFile)
		return err
	}
	pp.writer = printer.GetWriter(ctx, outputFile)
	return nil
}

func (pp *PolicyReportPrinter) Score(score float32) {
}

func (pp *PolicyReportPrinter) PrintNextSteps() {
}

func (pp *PolicyReportPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) error {
	if opaSessionObj == nil {
		return fmt.Errorf("failed to write results in PolicyReport format: no data provided")
	}

	reports := buildPolicyReports(opaSessionObj)
	if len(reports) == 0 {
		logger.L().Ctx(ctx).Warning("no results to report in PolicyReport format")
	}

	var out []byte
	for i, report := range reports {
		encoded, err := yaml.Marshal(report)
		if err != nil {
			logger.L().Ctx(ctx).Error("failed to encode PolicyReport", helpers.Error(err))
			return fmt.Errorf("failed to encode PolicyReport: %w", err)
		}
		if i > 0 {
			out = append(out, []byte("---\n")...)
		}
		out = append(out, encoded...)
	}

	if _, err := pp.writer.Write(out); err != nil {
		logger.L().Ctx(ctx).Error("failed to write results in PolicyReport format", helpers.Error(err))
		return fmt.Errorf("failed to write results in PolicyReport format: %w", err)
	}

	printer.LogOutputFile(pp.writer.Name())
	return nil
}

func buildPolicyReports(opaSessionObj *cautils.OPASessionObj) []policyReport {
	timestamp := opaSessionObj.Report.ReportGenerationTime
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}
	metaTime := metav1.NewTime(timestamp)

	summaryControls := opaSessionObj.Report.SummaryDetails.Controls

	byNamespace := map[string][]policyReportResult{}
	summaries := map[string]policyReportSummary{}

	resourceIDs := make([]string, 0, len(opaSessionObj.ResourcesResult))
	for resourceID := range opaSessionObj.ResourcesResult {
		resourceIDs = append(resourceIDs, resourceID)
	}
	sort.Strings(resourceIDs)

	for _, resourceID := range resourceIDs {
		result := opaSessionObj.ResourcesResult[resourceID]
		resourceData, ok := opaSessionObj.AllResources[resourceID]
		if !ok {
			continue
		}

		ref := policyReportResourceRef{
			APIVersion: resourceData.GetApiVersion(),
			Kind:       resourceData.GetKind(),
			Namespace:  resourceData.GetNamespace(),
			Name:       resourceData.GetName(),
		}
		namespace := resourceData.GetNamespace()

		for _, assocCtrl := range result.AssociatedControls {
			ac := assocCtrl
			status := ac.GetStatus(nil)

			if status.Status() == "" {
				continue
			}

			policyResult := policyReportResultFail
			if status.IsPassed() {
				policyResult = policyReportResultPass
			} else if status.IsSkipped() {
				policyResult = policyReportResultSkip
			}
			severity := "Unknown"
			message := ac.GetName()
			if ctl := summaryControls.GetControl(reportsummary.EControlCriteriaID, ac.GetID()); ctl != nil {
				severity = apis.ControlSeverityToString(ctl.GetScoreFactor())
				if desc := ctl.GetDescription(); desc != "" {
					message = desc
				}
			}

			byNamespace[namespace] = append(byNamespace[namespace], policyReportResult{
				Source:    policyReportSource,
				Policy:    ac.GetID(),
				Rule:      ac.GetName(),
				Severity:  mapPolicyReportSeverity(severity),
				Result:    policyResult,
				Message:   message,
				Timestamp: metaTime,
				Resources: []policyReportResourceRef{ref},
				Properties: map[string]string{
					"controlURL": cautils.GetControlLink(ac.GetID()),
				},
			})

			s := summaries[namespace]
			switch policyResult {
			case policyReportResultPass:
				s.Pass++
			case policyReportResultSkip:
				s.Skip++
			default:
				s.Fail++
			}
			summaries[namespace] = s
		}
	}

	clusterName := scanContextName(opaSessionObj)

	namespaces := make([]string, 0, len(byNamespace))
	for namespace := range byNamespace {
		namespaces = append(namespaces, namespace)
	}
	sort.Strings(namespaces)

	reports := make([]policyReport, 0, len(byNamespace))
	for _, namespace := range namespaces {
		results := byNamespace[namespace]
		if namespace == "" {
			reports = append(reports, policyReport{
				APIVersion: policyReportAPIVersion,
				Kind:       clusterPolicyReportKind,
				Metadata: policyReportMeta{
					Name:   policyReportName(clusterName, ""),
					Labels: policyReportLabels(clusterName),
				},
				Scope:   policyReportClusterScope(clusterName),
				Results: results,
				Summary: summaries[namespace],
			})
			continue
		}
		reports = append(reports, policyReport{
			APIVersion: policyReportAPIVersion,
			Kind:       policyReportKind,
			Metadata: policyReportMeta{
				Name:      policyReportName(clusterName, namespace),
				Namespace: namespace,
				Labels:    policyReportLabels(clusterName),
			},
			Results: results,
			Summary: summaries[namespace],
		})
	}

	return reports
}

// policyReportName builds the metadata.name for a report. A cluster name reaches us from a
// kubeconfig context, a cloud provider ARN or an API server URL (see scanContextName), so it
// routinely carries uppercase letters, colons and slashes that the apiserver rejects in a name.
func policyReportName(clusterName, namespace string) string {
	name := policyReportSource

	// A namespace is already a DNS-1123 label upstream, so this can only ever shrink it.
	ns := sanitizeDNS1123Subdomain(namespace, validation.DNS1123LabelMaxLength)

	// Whatever the fixed parts leave over is the cluster component's budget. Spending it in this
	// order keeps a very long cluster name from crowding the namespace out of the name, which
	// would collapse two namespaces onto one metadata.name.
	clusterBudget := maxPolicyReportNameLength - len(name) - 1
	if ns != "" {
		clusterBudget -= len(ns) + 1
	}

	if cluster := sanitizeDNS1123Subdomain(clusterName, clusterBudget); cluster != "" {
		name += "-" + cluster
	}
	if ns != "" {
		name += "-" + ns
	}
	return name
}

// policyReportLabels builds the metadata.labels map for a PolicyReport or ClusterPolicyReport,
// sanitizing the cluster name to satisfy Kubernetes label value constraints.
func policyReportLabels(clusterName string) map[string]string {
	labels := map[string]string{
		"app.kubernetes.io/managed-by": policyReportSource,
	}
	// A cluster name that sanitizes down to nothing is treated as an absent one: dropping the
	// label is valid, whereas emitting it empty would not survive `kubectl apply`.
	if cluster := sanitizeLabelValue(clusterName); cluster != "" {
		labels["kubescape.io/cluster"] = cluster
	}
	return labels
}

// sanitizeDNS1123Subdomain reduces an arbitrary identifier to a value the apiserver accepts as a
// metadata.name: lowercase alphanumerics joined by single hyphens, no leading or trailing hyphen,
// and no longer than maxLength.
//
// Dots are folded into hyphens along with every other illegal character. The result is embedded
// as one component of a compound name ("kubescape-<cluster>-<namespace>"), where a dot would
// imply a DNS label boundary that means nothing here and would need validating in its own right.
//
// Returns "" when no usable character survives, which callers treat as an absent value.
func sanitizeDNS1123Subdomain(value string, maxLength int) string {
	if maxLength <= 0 {
		return ""
	}

	var b strings.Builder
	b.Grow(len(value))

	// Separators are written lazily, only once a legal character follows one, so a run of
	// illegal characters collapses to a single hyphen and neither end can carry one.
	pendingSeparator := false
	for _, r := range strings.ToLower(value) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			if pendingSeparator {
				b.WriteByte('-')
				pendingSeparator = false
			}
			b.WriteRune(r)
			continue
		}
		pendingSeparator = b.Len() > 0
	}

	out := b.String()
	if len(out) > maxLength {
		out = strings.TrimRight(out[:maxLength], "-")
	}
	return out
}

// sanitizeLabelValue reduces an arbitrary identifier to a legal label value: at most
// maxPolicyReportLabelValueLength characters, opening and closing on an alphanumeric, and
// otherwise limited to alphanumerics, '-', '_' and '.'.
//
// Case is preserved here, unlike in a name: a label value may legally contain uppercase letters,
// so folding it would discard part of the identity the user configured for no gain.
//
// Returns "" when no usable character survives.
func sanitizeLabelValue(value string) string {
	var b strings.Builder
	b.Grow(len(value))

	pendingSeparator := false
	separator := byte('-')
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			if pendingSeparator {
				b.WriteByte(separator)
				pendingSeparator = false
			}
			b.WriteRune(r)
			continue
		}
		if !pendingSeparator && b.Len() > 0 {
			// A separator that is already legal survives as itself; anything else becomes a hyphen.
			if r == '-' || r == '_' || r == '.' {
				separator = byte(r)
			} else {
				separator = '-'
			}
			pendingSeparator = true
		}
	}

	out := b.String()
	if len(out) > maxPolicyReportLabelValueLength {
		out = strings.TrimRight(out[:maxPolicyReportLabelValueLength], "-_.")
	}
	return out
}

func policyReportClusterScope(clusterName string) *policyReportScope {
	if clusterName == "" {
		return nil
	}
	return &policyReportScope{
		APIVersion: "v1",
		Kind:       "Cluster",
		// Left unsanitized on purpose: scope.name identifies the cluster the report describes
		// rather than naming a Kubernetes object, so RFC 1123 does not apply and the full
		// context name — ARN, URL or otherwise — is the useful value to carry here.
		Name: clusterName,
	}
}

func mapPolicyReportSeverity(severity string) string {
	switch severity {
	case apis.SeverityCriticalString:
		return "critical"
	case apis.SeverityHighString:
		return "high"
	case apis.SeverityMediumString:
		return "medium"
	case apis.SeverityLowString:
		return "low"
	default:
		return "info"
	}
}

// CloseWriter closes the PolicyReport output writer, returning any error from flushing or closing.
func (pp *PolicyReportPrinter) CloseWriter() error {
	if pp.writer != nil && pp.writer != os.Stdout {
		return pp.writer.Close()
	}
	return nil
}
