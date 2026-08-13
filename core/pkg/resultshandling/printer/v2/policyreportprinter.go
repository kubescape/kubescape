package printer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

func (pp *PolicyReportPrinter) SetWriter(ctx context.Context, outputFile string) {
	if outputFile != "" {
		if strings.TrimSpace(outputFile) == "" {
			outputFile = policyReportOutputFile
		}
		ext := filepath.Ext(strings.TrimSpace(outputFile))
		if ext != printer.YamlOutputExt && ext != ".yml" {
			outputFile = outputFile + printer.YamlOutputExt
		}
	}
	pp.writer = printer.GetWriter(ctx, outputFile)
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

	for resourceID, result := range opaSessionObj.ResourcesResult {
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
			if policyResult == policyReportResultPass {
				s.Pass++
			} else {
				s.Fail++
			}
			summaries[namespace] = s
		}
	}

	clusterName := scanContextName(opaSessionObj)

	reports := make([]policyReport, 0, len(byNamespace))
	for namespace, results := range byNamespace {
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

func policyReportName(clusterName, namespace string) string {
	base := "kubescape"
	if namespace != "" {
		base = base + "-" + namespace
	}
	return base
}

func policyReportLabels(clusterName string) map[string]string {
	labels := map[string]string{
		"app.kubernetes.io/managed-by": policyReportSource,
	}
	if clusterName != "" {
		labels["kubescape.io/cluster"] = clusterName
	}
	return labels
}

func policyReportClusterScope(clusterName string) *policyReportScope {
	if clusterName == "" {
		return nil
	}
	return &policyReportScope{
		APIVersion: "v1",
		Kind:       "Cluster",
		Name:       clusterName,
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

func (pp *PolicyReportPrinter) CloseWriter() {
	if pp.writer != nil && pp.writer != os.Stdout {
		pp.writer.Close()
	}
}
