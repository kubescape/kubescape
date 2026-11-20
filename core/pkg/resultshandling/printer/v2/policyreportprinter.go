package printer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings" // required for sanitizeDNS1123Subdomain / sanitizeLabelValue (Builder, ToLower, TrimRight)
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
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

	policyReportTypeLabel          = "kubescape.io/report-type"
	policyReportTypeImage          = "image-vulnerabilities"
	policyReportImageAnnotation    = "kubescape.io/image"
	policyReportPlatformAnnotation = "kubescape.io/platform"
	policyReportImageCategory      = "Image Vulnerability"

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
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
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
	Timestamp  metav1.Timestamp          `json:"timestamp,omitempty"`
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
		pp.writer, err = printer.GetPrinterWriterNoFallback(outputFile)
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
	hasPosture := opaSessionObj != nil && opaSessionObj.Report != nil
	if !hasPosture && len(imageScanData) == 0 {
		return fmt.Errorf("failed to write results in PolicyReport format: no data provided")
	}
	if pp.writer == nil {
		return fmt.Errorf("failed to write PolicyReport results: output writer is nil")
	}
	if err := printer.PrepareOutput(pp.writer); err != nil {
		return err
	}

	var reports []policyReport
	var clusterName string
	timestamp := time.Now().UTC()
	if hasPosture {
		reports = buildPolicyReports(opaSessionObj)
		clusterName = scanContextName(opaSessionObj)
		if generated := opaSessionObj.Report.ReportGenerationTime; !generated.IsZero() {
			timestamp = generated
		}
	}
	reports = append(reports, buildImagePolicyReports(imageScanData, clusterName, timestamp)...)
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

// buildPolicyReports constructs PolicyReport and ClusterPolicyReport objects from an OPA session,
// including cluster-wide skipped controls and diagnostics (#3989).
func buildPolicyReports(opaSessionObj *cautils.OPASessionObj) []policyReport {
	if opaSessionObj == nil {
		return nil
	}
	var timestamp time.Time
	if opaSessionObj.Report != nil {
		timestamp = opaSessionObj.Report.ReportGenerationTime
	}
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}
	reportTime := metav1.NewTime(timestamp)
	resultTimestamp := *reportTime.ProtoTime()

	var summaryControls reportsummary.ControlSummaries
	if opaSessionObj.Report != nil {
		summaryControls = opaSessionObj.Report.SummaryDetails.Controls
	}

	byNamespace := map[string][]policyReportResult{}
	summaries := map[string]policyReportSummary{}
	emittedClusterControls := make(map[string]struct{})

	resourceIDs := make([]string, 0, len(opaSessionObj.ResourcesResult))
	for resourceID := range opaSessionObj.ResourcesResult {
		resourceIDs = append(resourceIDs, resourceID)
	}
	sort.Strings(resourceIDs)

	for _, resourceID := range resourceIDs {
		result := opaSessionObj.ResourcesResult[resourceID]
		resourceData, ok := opaSessionObj.GetResource(resourceID)
		if !ok || resourceData == nil {
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
			status := cautils.ControlStatus(&opaSessionObj.Report.SummaryDetails, &ac)

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
			if summaryControls != nil {
				if ctl := summaryControls.GetControl(reportsummary.EControlCriteriaID, ac.GetID()); ctl != nil {
					severity = apis.ControlSeverityToString(ctl.GetScoreFactor())
					if desc := ctl.GetDescription(); desc != "" {
						message = desc
					}
				}
			}

			byNamespace[namespace] = append(byNamespace[namespace], policyReportResult{
				Source:    policyReportSource,
				Policy:    ac.GetID(),
				Rule:      ac.GetName(),
				Severity:  mapPolicyReportSeverity(severity),
				Result:    policyResult,
				Message:   message,
				Timestamp: resultTimestamp,
				Resources: []policyReportResourceRef{ref},
				Properties: map[string]string{
					"controlURL": cautils.GetControlLink(ac.GetID()),
				},
			})

			if namespace == "" {
				emittedClusterControls[ac.GetID()] = struct{}{}
			}

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

	// Surface cluster-wide skipped and unevaluated controls in ClusterPolicyReport (#3884 parity)
	skippedControls := collectSkippedControls(opaSessionObj)
	for _, sc := range skippedControls {
		reason := sc.reason
		if reason == "" {
			reason = "reason unavailable"
		}

		message := reason
		if sc.name != "" && reason != "" {
			message = fmt.Sprintf("%s: %s", sc.name, reason)
		}

		enrichedExistingSkip := false
		if _, alreadyEmitted := emittedClusterControls[sc.controlID]; alreadyEmitted {
			for i := range byNamespace[""] {
				result := &byNamespace[""][i]
				if result.Policy != sc.controlID || result.Result != policyReportResultSkip {
					continue
				}
				result.Message = message
				if result.Properties == nil {
					result.Properties = map[string]string{}
				}
				result.Properties["skipReason"] = reason
				enrichedExistingSkip = true
			}
			if enrichedExistingSkip {
				continue
			}
		}

		severity := apis.ControlSeverityToString(sc.scoreFactor)
		if severity == "" || severity == "Unknown" {
			if summaryControls != nil {
				if ctrl := summaryControls.GetControl(reportsummary.EControlCriteriaID, sc.controlID); ctrl != nil && ctrl.GetScoreFactor() > 0 {
					severity = apis.ControlSeverityToString(ctrl.GetScoreFactor())
				}
			}
		}
		if severity == "" {
			severity = "Unknown"
		}

		byNamespace[""] = append(byNamespace[""], policyReportResult{
			Source:    policyReportSource,
			Policy:    sc.controlID,
			Rule:      sc.name,
			Severity:  mapPolicyReportSeverity(severity),
			Result:    policyReportResultSkip,
			Message:   message,
			Timestamp: resultTimestamp,
			Properties: map[string]string{
				"controlURL": cautils.GetControlLink(sc.controlID),
				"skipReason": reason,
			},
		})

		emittedClusterControls[sc.controlID] = struct{}{}

		s := summaries[""]
		s.Skip++
		summaries[""] = s
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

func buildImagePolicyReports(imageScanData []cautils.ImageScanData, clusterName string, timestamp time.Time) []policyReport {
	if len(imageScanData) == 0 {
		return nil
	}
	reportTime := metav1.NewTime(timestamp)
	resultTimestamp := *reportTime.ProtoTime()

	reports := make([]policyReport, 0, len(imageScanData))
	for i := range imageScanData {
		scan := &imageScanData[i]
		cves := extractCVEs(scan.Matches, scan.Image, scan.VexStatuses)

		var summary policyReportSummary
		results := make([]policyReportResult, 0, len(cves))
		for _, cve := range cves {
			result := imageVulnerabilityResult(cve, scan.Platform, resultTimestamp)
			if result.Result == policyReportResultSkip {
				summary.Skip++
			} else {
				summary.Fail++
			}
			results = append(results, result)
		}

		labels := policyReportLabels(clusterName)
		labels[policyReportTypeLabel] = policyReportTypeImage
		annotations := map[string]string{policyReportImageAnnotation: scan.Image}
		if scan.Platform != "" {
			annotations[policyReportPlatformAnnotation] = scan.Platform
		}

		reports = append(reports, policyReport{
			APIVersion: policyReportAPIVersion,
			Kind:       clusterPolicyReportKind,
			Metadata: policyReportMeta{
				Name:        imagePolicyReportName(clusterName, scan.Image, scan.Platform),
				Labels:      labels,
				Annotations: annotations,
			},
			Results: results,
			Summary: summary,
		})
	}
	return reports
}

func imageVulnerabilityResult(cve imageprinter.CVE, platform string, timestamp metav1.Timestamp) policyReportResult {
	result := policyReportResultFail
	if cve.VexStatus == "not_affected" || cve.VexStatus == "fixed" {
		result = policyReportResultSkip
	}

	severity := cve.Severity
	if severity == "" {
		severity = apis.SeverityUnknownString
	}

	properties := map[string]string{
		"image":   cve.Image,
		"package": cve.Package,
	}
	if cve.Version != "" {
		properties["installedVersion"] = cve.Version
	}
	if cve.FixedState != "" {
		properties["fixState"] = cve.FixedState
	}
	fix := "no fix available"
	if len(cve.FixVersions) > 0 {
		fixedVersions := strings.Join(cve.FixVersions, ", ")
		properties["fixedVersions"] = fixedVersions
		fix = "fixed in " + fixedVersions
	}
	if platform != "" {
		properties["platform"] = platform
	}
	if cve.KEVKnown {
		properties["knownExploited"] = strconv.FormatBool(cve.KEV)
	}
	if cve.EPSS != nil {
		properties["epss"] = imageprinter.FormatEPSS(cve.EPSS)
	}
	if cve.VexStatus != "" {
		properties["vexStatus"] = cve.VexStatus
	}
	if cve.VexJustification != "" {
		properties["vexJustification"] = cve.VexJustification
	}

	return policyReportResult{
		Source:     policyReportSource,
		Policy:     cve.ID,
		Rule:       cve.Package,
		Category:   policyReportImageCategory,
		Severity:   mapPolicyReportSeverity(severity),
		Result:     result,
		Message:    fmt.Sprintf("%s severity vulnerability in %s %s, %s", severity, cve.Package, cve.Version, fix),
		Timestamp:  timestamp,
		Properties: properties,
	}
}

func imagePolicyReportName(clusterName, image, platform string) string {
	digest := sha256.Sum256([]byte(image + "\x00" + platform))
	hash := hex.EncodeToString(digest[:5])
	ref := sanitizeDNS1123Subdomain(image, validation.DNS1123LabelMaxLength-len("image--")-len(hash))
	if ref == "" {
		return policyReportName(clusterName, "image-"+hash)
	}
	return policyReportName(clusterName, "image-"+ref+"-"+hash)
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
		return printer.CloseOutput(pp.writer)
	}
	return nil
}
