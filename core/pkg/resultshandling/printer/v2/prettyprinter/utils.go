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
	linkToHelm               = "https://github.com/kubescape/helm-charts"
	linkToCICDSetup          = "https://hub.armosec.io/docs/integrations"
	configScanVerboseRunText = "Run with '--verbose'/'-v' flag for detailed resources view"
	imageScanVerboseRunText  = "Run with '--verbose'/'-v' flag for detailed vulnerabilities view"
)

var (
	clusterScanRunText   = fmt.Sprintf("Run a cluster scan: %s", getCallToActionString("'$ kubescape scan'"))
	installHelmText      = fmt.Sprintf("Install Kubescape in your cluster for continuous monitoring: %s", linkToHelm)
	CICDSetupText        = fmt.Sprintf("Add Kubescape to your CI/CD pipeline: %s", linkToCICDSetup)
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
		return "Your highest stake workloads:\n"
	}
	if topWLsLen > 0 {
		return "Your highest stake workload:\n"
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
		cautils.InfoTextDisplay(writer, "Vulnerability summary - no vulnerabilities were found!\n\n")
		return
	}

	cautils.InfoTextDisplay(writer, "Vulnerability summary - %d vulnerabilities found:\n", len(summary.CVEs))

	if len(summary.Images) == 1 {
		cautils.SimpleDisplay(writer, "Image: %s\n", summary.Images[0])
	} else {
		cautils.SimpleDisplay(writer, "Images: %s\n", strings.Join(summary.Images, ", "))
	}

	for _, k := range keys {
		if k == "Other" {
			cautils.SimpleDisplay(writer, "  * %d %s \n", mapSeverityTSummary[k].NumberOfCVEs, k)
		} else {
			cautils.SimpleDisplay(writer, "  * %d %s\n", mapSeverityTSummary[k].NumberOfCVEs, k)
		}
	}

}

func printImagesCommands(writer *os.File, summary imageprinter.ImageScanSummary) {
	for _, img := range summary.Images {
		imgWithoutTag := strings.Split(img, ":")[0]
		cautils.SimpleDisplay(writer, fmt.Sprintf("Receive full report for %s image by running: %s\n", imgWithoutTag, getCallToActionString(fmt.Sprintf("'$ kubescape scan image %s'", img))))
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

	cautils.SimpleDisplay(writer, fmt.Sprintf("View full compliance report by running: %s\n", getCallToActionString("'$ kubescape scan framework nsa,mitre'")))

	cautils.InfoTextDisplay(writer, "\n")
}

func getCallToActionString(action string) string {
	return gchalk.WithBrightBlue().Bold(action)
}
