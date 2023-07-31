package prettyprinter

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	helpersv1 "github.com/kubescape/opa-utils/reporthandling/helpers/v1"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"k8s.io/utils/strings/slices"
)

const (
	linkToHelm               = "https://github.com/kubescape/helm-charts"
	linkToCICDSetup          = "https://hub.armosec.io/docs/integrations"
	configScanVerboseRunText = "Run with '--verbose'/'-v' flag for detailed resources view"
	imageScanVerboseRunText  = "Run with '--verbose'/'-v' flag for detailed vulnerabilities view"
	clusterScanRunText       = "Run a cluster scan: '$ kubescape scan'"
)

var (
	installHelmText      = fmt.Sprintf("Install helm for continuos monitoring: %s", linkToHelm)
	CICDSetupText        = fmt.Sprintf("Add Kubescape to CICD: %s", linkToCICDSetup)
	complianceFrameworks = []string{"nsa", "mitre"}
	cveSeverities        = []string{"Critical", "High", "Medium", "Low", "Negligible", "Unknown"}
)

func filterComplianceFrameworks(frameworks []reportsummary.IFrameworkSummary) []reportsummary.IFrameworkSummary {
	complianceFws := []reportsummary.IFrameworkSummary{}
	for _, fw := range frameworks {
		if slices.Contains(complianceFrameworks, strings.ToLower(fw.GetName())) {
			complianceFws = append(complianceFws, fw)
		}
	}
	return complianceFws
}

func ControlCountersForResource(l *helpersv1.AllLists) string {
	return fmt.Sprintf("Controls: %d (Failed: %d, action required: %d)", l.Len(), l.Failed(), l.Skipped())
}

func getWorkloadPrefixForCmd(namespace, kind, name string) string {
	if namespace == "" {
		return fmt.Sprintf("name: %s, kind: %s", name, kind)
	}
	return fmt.Sprintf("namespace: %s, name: %s, kind: %s", namespace, name, kind)
}

func getTopWorkloadsTitle(topWLsLen int) string {
	if topWLsLen > 1 {
		return "Your most risky workloads:\n"
	}
	if topWLsLen > 0 {
		return "Your most risky workload:\n"
	}
	return ""
}

// getSeverityToSummaryMap returns a map of severity to summary, if shouldMerge is true, it will merge Low, Negligible and Unknown to Other
func getSeverityToSummaryMap(summary imageprinter.ImageScanSummary, verboseMode bool) map[string]*imageprinter.SeveritySummary {
	tempMap := map[string]*imageprinter.SeveritySummary{}
	for severity, severitySummary := range summary.MapsSeverityToSummary {
		if !verboseMode {
			if severity == "Low" || severity == "Negligible" || severity == "Unknown" {
				severity = "Other"
			}
		}
		if _, ok := tempMap[severity]; !ok {
			tempMap[severity] = &imageprinter.SeveritySummary{}
		}
		tempMap[severity].NumberOfCVEs += severitySummary.NumberOfCVEs
		tempMap[severity].NumberOfFixableCVEs += severitySummary.NumberOfFixableCVEs
	}

	addEmptySeverities(tempMap, verboseMode)

	return tempMap
}

func addEmptySeverities(mapSeverityTSummary map[string]*imageprinter.SeveritySummary, verboseMode bool) {
	if verboseMode {
		for _, severity := range cveSeverities {
			if _, ok := mapSeverityTSummary[severity]; !ok {
				mapSeverityTSummary[severity] = &imageprinter.SeveritySummary{}
			}
		}
	} else {
		for _, severity := range []string{"Critical", "High", "Other"} {
			if _, ok := mapSeverityTSummary[severity]; !ok {
				mapSeverityTSummary[severity] = &imageprinter.SeveritySummary{}
			}
		}
	}
}

// filterCVEsBySeverities returns a list of CVEs only with the severities that are in the severities list
func filterCVEsBySeverities(cves []imageprinter.CVE, severities []string) []imageprinter.CVE {
	var filteredCVEs []imageprinter.CVE

	for _, cve := range cves {
		for _, severity := range severities {
			if cve.Severity == severity {
				filteredCVEs = append(filteredCVEs, cve)
			}
		}
	}

	return filteredCVEs
}

// sortTopVulnerablePackages sorts the top vulnerable packages by score. It return a map of packages to their score and version
func sortTopVulnerablePackages(pkgScores map[string]*imageprinter.PackageScore) map[string]*imageprinter.PackageScore {
	var ss []string
	for k := range pkgScores {
		ss = append(ss, k)
	}

	sort.Slice(ss, func(i, j int) bool {
		return pkgScores[ss[i]].Score > pkgScores[ss[j]].Score
	})

	var sortedMap = make(map[string]*imageprinter.PackageScore)

	for i := 0; i < len(ss) && i < TopPackagesNumber; i++ {
		sortedMap[ss[i]] = &imageprinter.PackageScore{
			Name:    pkgScores[ss[i]].Name,
			Score:   pkgScores[ss[i]].Score,
			Version: pkgScores[ss[i]].Version,
		}
	}

	return sortedMap
}

// / PRINTERS ///
func printTopVulnerabilities(writer *os.File, summary imageprinter.ImageScanSummary) {
	if len(summary.PackageScores) == 0 {
		return
	}

	cautils.InfoTextDisplay(writer, "\nMost vulnerable components:\n")

	topVulnerablePackages := sortTopVulnerablePackages(summary.PackageScores)
	for _, v := range topVulnerablePackages {
		cautils.SimpleDisplay(writer, "  * %s (%s)\n", v.Name, v.Version)
	}

	cautils.SimpleDisplay(writer, "\n")

	return
}

func printImageScanningSummary(writer *os.File, summary imageprinter.ImageScanSummary, verboseMode bool) {
	mapSeverityTSummary := getSeverityToSummaryMap(summary, verboseMode)

	// sort keys by severity
	keys := make([]string, 0, len(mapSeverityTSummary))
	for k := range mapSeverityTSummary {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return utils.ImageSeverityToInt(keys[i]) > utils.ImageSeverityToInt(keys[j])
	})

	if len(summary.CVEs) == 0 {
		cautils.InfoTextDisplay(writer, "Vulnerability summary - no vulnerabilities were found!\n\n")
		return
	}

	cautils.InfoTextDisplay(writer, "Vulnerability summary - %d vulnerabilities found:\n", len(summary.CVEs))

	for _, k := range keys {
		if k == "Other" {
			cautils.SimpleDisplay(writer, "  * %d %s \n", mapSeverityTSummary[k].NumberOfCVEs, k)
		} else {
			cautils.SimpleDisplay(writer, "  * %d %s\n", mapSeverityTSummary[k].NumberOfCVEs, k)
		}
	}

}

func printImagesCommands(writer *os.File, summary imageprinter.ImageScanSummary) {
	cautils.SimpleDisplay(writer, "(Scanned images: %s)\n", strings.Join(summary.Images, ", "))

	for _, img := range summary.Images {
		imgWithoutTag := strings.Split(img, ":")[0]
		cautils.SimpleDisplay(writer, fmt.Sprintf("Receive full report for %s image by running: '$ kubescape scan image %s'\n", imgWithoutTag, img))
	}

	cautils.InfoTextDisplay(writer, "\n")
}

func printNextSteps(writer *os.File, nextSteps []string, addLine bool) {
	cautils.InfoTextDisplay(writer, "Follow-up steps:\n")
	for _, ns := range nextSteps {
		cautils.SimpleDisplay(writer, "- "+ns+"\n")
	}
	if addLine {
		cautils.SimpleDisplay(writer, "\n")
	}
}

func printComplianceScore(writer *os.File, frameworks []reportsummary.IFrameworkSummary) {
	cautils.InfoTextDisplay(writer, "Compliance Score:\n")
	for _, fw := range frameworks {
		cautils.SimpleDisplay(writer, "* %s: %.2f%%\n", fw.GetName(), fw.GetComplianceScore())
	}

	cautils.SimpleDisplay(writer, "View full compliance report by running:'$ kubescape scan framework nsa,mitre'\n")

	cautils.InfoTextDisplay(writer, "\n")
}
