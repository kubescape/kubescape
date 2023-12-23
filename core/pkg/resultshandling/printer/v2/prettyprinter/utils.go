package prettyprinter

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/jwalton/gchalk"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	helpersv1 "github.com/kubescape/opa-utils/reporthandling/helpers/v1"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"k8s.io/utils/strings/slices"
)

const (
	configScanVerboseRunText = "Run with '--verbose'/'-v' flag for detailed resources view"
	imageScanVerboseRunText  = "Run with '--verbose'/'-v' flag for detailed vulnerabilities view"
	runCommandsText          = "Run one of the suggested commands to learn more about a failed control failure"
	ksHelmChartLink          = "https://kubescape.io/docs/install-operator/"
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
		return "Highest-stake workloads"
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
	// Create a map to efficiently check if a severity is present in the severities slice
	severityMap := make(map[string]bool)
	for _, severity := range severities {
		severityMap[severity] = true
	}

	// Filter CVEs based on the severityMap
	filteredCVEs := []imageprinter.CVE{}
	for _, cve := range cves {
		if severityMap[cve.Severity] {
			filteredCVEs = append(filteredCVEs, cve)
		}
	}

	return filteredCVEs
}

// getSortPackageScores returns a slice of package names sorted by score
func getSortPackageScores(pkgScores map[string]*imageprinter.PackageScore) []string {
	sortedSlice := make([]string, 0, len(pkgScores))
	for pkgName, _ := range pkgScores {
		sortedSlice = append(sortedSlice, pkgName)
	}

	sort.Slice(sortedSlice, func(i, j int) bool {
		if pkgScores[sortedSlice[i]].Score == pkgScores[sortedSlice[j]].Score {
			return pkgScores[sortedSlice[i]].Name < pkgScores[sortedSlice[j]].Name
		}
		return pkgScores[sortedSlice[i]].Score > pkgScores[sortedSlice[j]].Score
	})

	return sortedSlice
}

// getSortedCVEsBySeverity returns a slice of CVEs sorted by severity
func getSortedCVEsBySeverity(mapSeverityToCVEsNumber map[string]int) []string {
	if len(mapSeverityToCVEsNumber) == 0 {
		// Handle empty mapSeverityToCVEsNumber map
		return []string{} // Return an empty slice
	}

	// Create a slice of severity-CVEs count pairs
	severityToCVEsCountPairs := make([][2]string, 0, len(mapSeverityToCVEsNumber))
	for severity, cvesCount := range mapSeverityToCVEsNumber {
		severityToCVEsCountPairs = append(severityToCVEsCountPairs, [2]string{severity, strconv.Itoa(cvesCount)})
	}

	// Sort the severity-CVEs count pairs by severity
	sort.Slice(severityToCVEsCountPairs, func(i, j int) bool {
		return utils.ImageSeverityToInt(severityToCVEsCountPairs[i][0]) > utils.ImageSeverityToInt(severityToCVEsCountPairs[j][0])
	})

	// Extract severities from the sorted slice of pairs
	var sortedSlice []string
	for _, severityToCVEsCountPair := range severityToCVEsCountPairs {
		sortedSlice = append(sortedSlice, severityToCVEsCountPair[0])
	}

	return sortedSlice
}

func printTopComponents(writer *os.File, summary imageprinter.ImageScanSummary) {
	if len(summary.PackageScores) == 0 {
		return
	}

	txt := "Components with most vulnerabilities"
	cautils.SectionHeadingDisplay(writer, txt)

	sortedPkgScores := getSortPackageScores(summary.PackageScores)

	for i := 0; i < len(sortedPkgScores) && i < TopPackagesNumber; i++ {
		topPkg := summary.PackageScores[sortedPkgScores[i]]
		output := fmt.Sprintf("%s (%s) -", topPkg.Name, topPkg.Version)

		sortedCVEs := getSortedCVEsBySeverity(topPkg.MapSeverityToCVEsNumber)

		for j := range sortedCVEs {
			output += fmt.Sprintf(" %d %s,", topPkg.MapSeverityToCVEsNumber[sortedCVEs[j]], utils.GetColorForVulnerabilitySeverity(sortedCVEs[j])(sortedCVEs[j]))
		}

		output = output[:len(output)-1]

		cautils.StarDisplay(writer, output+"\n")
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
		txt := "No vulnerabilities were found!"

		cautils.InfoDisplay(writer, txt+"\n")
		return
	}

	txt := fmt.Sprintf("%d vulnerabilities found", len(summary.CVEs))
	cautils.SectionHeadingDisplay(writer, txt)

	if len(summary.Images) == 1 {
		cautils.SimpleDisplay(writer, "Image: %s\n\n", summary.Images[0])
	} else if len(summary.Images) < 4 {
		cautils.SimpleDisplay(writer, "Images: %s\n\n", strings.Join(summary.Images, ", "))
	}

	for _, k := range keys {
		cautils.StarDisplay(writer, "%d %s \n", mapSeverityTSummary[k].NumberOfCVEs, utils.GetColorForVulnerabilitySeverity(k)(k))
	}

	cautils.SimpleDisplay(writer, "\n")

}

func printImagesCommands(writer *os.File, summary imageprinter.ImageScanSummary) {
	if len(summary.Images) > 3 {
		cautils.SimpleDisplay(writer, "Receive full report by running: kubescape scan image <image>\n")
	} else {
		for _, img := range summary.Images {
			imgWithoutTag := strings.Split(img, ":")[0]
			cautils.SimpleDisplay(writer, fmt.Sprintf("Receive a full report for %s by running: %s\n", imgWithoutTag, getCallToActionString(fmt.Sprintf("'$ kubescape scan image %s'", img))))
		}
	}

	cautils.SimpleDisplay(writer, "\n")
}

func printNextSteps(writer *os.File, nextSteps []string, addLine bool) {
	txt := "What now?"
	cautils.SectionHeadingDisplay(writer, txt)

	for _, ns := range nextSteps {
		cautils.StarDisplay(writer, ns+"\n")
	}
	if addLine {
		cautils.SimpleDisplay(writer, "\n")
	}
}

func printComplianceScore(writer *os.File, frameworks []reportsummary.IFrameworkSummary) {
	txt := "Compliance Score"
	cautils.SectionHeadingDisplay(writer, txt)
	cautils.SimpleDisplay(writer, "The compliance score is calculated by multiplying control failures by the number of failures against supported compliance frameworks. Remediate controls, or configure your cluster baseline with exceptions, to improve this score.\n\n")

	for _, fw := range frameworks {
		cautils.StarDisplay(writer, "%s: %s", fw.GetName(), gchalk.WithBrightYellow().Bold(fmt.Sprintf("%.2f%%\n", fw.GetComplianceScore())))
	}

	cautils.SimpleDisplay(writer, fmt.Sprintf("\nView a full compliance report by running %s or %s\n", getCallToActionString("'$ kubescape scan framework nsa'"), getCallToActionString("'$ kubescape scan framework mitre'")))

	cautils.SimpleDisplay(writer, "\n")
}

func getCallToActionString(action string) string {
	return gchalk.WithBrightWhite().Bold(action)
}
