package prettyprinter

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/jwalton/gchalk"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	helpersv1 "github.com/kubescape/opa-utils/reporthandling/helpers/v1"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"k8s.io/utils/strings/slices"
)

const (
	configScanVerboseRunText = "Run with '--verbose'/'-v' flag for detailed resources view"
	imageScanVerboseRunText  = "Run with '--verbose'/'-v' flag for detailed vulnerabilities view"
	runCommandsText          = "Run one of the suggested commands to learn more about a failed control failure"
	ksHelmChartLink          = "https://github.com/kubescape/helm-charts/tree/main/charts/kubescape-cloud-operator"
	highStakesWlsText        = "High-stakes workloads are defined as those which Kubescape estimates would have the highest impact if they were to be exploited.\n\n"
)

var (
	scanWorkloadText     = fmt.Sprintf("Scan a workload with %s to see vulnerability information", getCallToActionString("'$ kubescape scan workload'"))
	installKubescapeText = fmt.Sprintf("Install Kubescape in your cluster for continuous monitoring and a full vulnerability report: %s", ksHelmChartLink)
	clusterScanRunText   = fmt.Sprintf("Run a cluster scan: %s", getCallToActionString("'$ kubescape scan'"))
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
	if topWLsLen > 0 {
		return "Highest-stake workloads\n"
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

// addEmptySeverities adds empty severities to the map
func addEmptySeverities(mapSeverityTSummary map[string]*imageprinter.SeveritySummary, verboseMode bool) {
	if verboseMode {
		// add all severities
		for _, severity := range cveSeverities {
			if _, ok := mapSeverityTSummary[severity]; !ok {
				mapSeverityTSummary[severity] = &imageprinter.SeveritySummary{}
			}
		}
	} else {
		// add only Critical, High and Other
		for _, severity := range []string{apis.SeverityCriticalString, apis.SeverityHighString, "Other"} {
			if _, ok := mapSeverityTSummary[severity]; !ok {
				mapSeverityTSummary[severity] = &imageprinter.SeveritySummary{}
			}
		}
	}
}

// getFilteredCVEs returns a list of CVEs to show in the table. If there are no vulnerabilities with severity Critical or High, it will return vulnerabilities with severity Medium. Otherwise it will return vulnerabilities with severity Critical or High
func getFilteredCVEs(cves []imageprinter.CVE) []imageprinter.CVE {
	// filter out vulnerabilities with severity lower than High
	filteredCVEs := filterCVEsBySeverities(cves, []string{apis.SeverityCriticalString, apis.SeverityHighString})

	// if there are no vulnerabilities with severity Critical or High, add vulnerabilities with severity Medium
	if len(filteredCVEs) == 0 {
		filteredCVEs = filterCVEsBySeverities(cves, []string{apis.SeverityMediumString})
	}

	return filteredCVEs
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

// getSortPackageScores returns a slice of package names sorted by score
func getSortPackageScores(pkgScores map[string]*imageprinter.PackageScore) []string {
	var ss []string
	for k := range pkgScores {
		ss = append(ss, k)
	}

	// sort by score. If score is equal, sort by name
	sort.Slice(ss, func(i, j int) bool {
		if pkgScores[ss[i]].Score == pkgScores[ss[j]].Score {
			return pkgScores[ss[i]].Name < pkgScores[ss[j]].Name
		}
		return pkgScores[ss[i]].Score > pkgScores[ss[j]].Score
	})

	return ss
}

// getSortedCVEsBySeverity returns a slice of CVEs sorted by severity
func getSortedCVEsBySeverity(mapSeverityToCVEsNumber map[string]int) []string {
	ss := make([]string, 0, len(mapSeverityToCVEsNumber))
	for k := range mapSeverityToCVEsNumber {
		ss = append(ss, k)
	}

	sort.Slice(ss, func(i, j int) bool {
		return utils.ImageSeverityToInt(ss[i]) > utils.ImageSeverityToInt(ss[j])
	})

	return ss

}

func printTopComponents(writer *os.File, summary imageprinter.ImageScanSummary) {
	if len(summary.PackageScores) == 0 {
		return
	}

	cautils.InfoTextDisplay(writer, "\nMost vulnerable components:\n")

	sortedPkgScores := getSortPackageScores(summary.PackageScores)

	for i := 0; i < len(sortedPkgScores) && i < TopPackagesNumber; i++ {
		topPkg := summary.PackageScores[sortedPkgScores[i]]
		output := fmt.Sprintf("  * %s (%s) -", topPkg.Name, topPkg.Version)

		sortedCVEs := getSortedCVEsBySeverity(topPkg.MapSeverityToCVEsNumber)

		for j := range sortedCVEs {
			output += fmt.Sprintf(" %d %s,", topPkg.MapSeverityToCVEsNumber[sortedCVEs[j]], sortedCVEs[j])
		}

		output = output[:len(output)-1]

		cautils.SimpleDisplay(writer, output+"\n")
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
		txt := "Vulnerability summary - no vulnerabilities were found!"
		cautils.InfoTextDisplay(writer, txt+"\n")
		cautils.SimpleDisplay(writer, strings.Repeat("─", len(txt))+"\n")
		return
	}

	txt := fmt.Sprintf("Vulnerability summary - %d vulnerabilities found:", len(summary.CVEs))
	cautils.InfoTextDisplay(writer, txt+"\n")
	cautils.SimpleDisplay(writer, strings.Repeat("─", len(txt))+"\n")

	if len(summary.Images) == 1 {
		cautils.SimpleDisplay(writer, "Image: %s\n", summary.Images[0])
	} else {
		cautils.SimpleDisplay(writer, "Images: %s\n", strings.Join(summary.Images, ", "))
	}

	for _, k := range keys {
		cautils.SimpleDisplay(writer, "  * %d %s \n", mapSeverityTSummary[k].NumberOfCVEs, utils.GetColorForVulnerabilitySeverity(k)(k))
	}

}

func printImagesCommands(writer *os.File, summary imageprinter.ImageScanSummary) {
	if len(summary.Images) > 3 {
		cautils.SimpleDisplay(writer, "Receive full report by running: kubescape image scan <image>\n")
	} else {
		for _, img := range summary.Images {
			imgWithoutTag := strings.Split(img, ":")[0]
			cautils.SimpleDisplay(writer, fmt.Sprintf("Receive full report for %s image by running: %s\n", imgWithoutTag, getCallToActionString(fmt.Sprintf("'$ kubescape image scan %s'", img))))
		}
	}

	cautils.InfoTextDisplay(writer, "\n")
}

func printNextSteps(writer *os.File, nextSteps []string, addLine bool) {
	txt := "What now?"
	cautils.InfoTextDisplay(writer, fmt.Sprintf("%s\n", txt))

	cautils.SimpleDisplay(writer, fmt.Sprintf("%s\n", strings.Repeat("─", len(txt))))

	for _, ns := range nextSteps {
		cautils.SimpleDisplay(writer, "* "+ns+"\n")
	}
	if addLine {
		cautils.SimpleDisplay(writer, "\n")
	}
}

func printComplianceScore(writer *os.File, frameworks []reportsummary.IFrameworkSummary) {
	txt := "Compliance Score"
	cautils.InfoTextDisplay(writer, fmt.Sprintf("%s\n", txt))

	cautils.SimpleDisplay(writer, fmt.Sprintf("%s\n", strings.Repeat("─", len(txt))))

	cautils.SimpleDisplay(writer, "The compliance score is calculated by multiplying control failures by the number of failures against supported compliance frameworks. Remediate controls, or configure your cluster baseline with exceptions, to improve this score.\n\n")

	for _, fw := range frameworks {
		cautils.SimpleDisplay(writer, "* %s: %s", fw.GetName(), gchalk.WithYellow().Bold(fmt.Sprintf("%.2f%%\n", fw.GetComplianceScore())))
	}

	cautils.SimpleDisplay(writer, fmt.Sprintf("\nView a full compliance report by running %s or %s\n", getCallToActionString("'$ kubescape scan framework nsa'"), getCallToActionString("'$ kubescape scan framework mitre'")))

	cautils.InfoTextDisplay(writer, "\n")
}

func getCallToActionString(action string) string {
	return gchalk.WithBrightBlue().Bold(action)
}
