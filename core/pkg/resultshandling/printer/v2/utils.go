package printer

import (
	"slices"
	"sort"
	"strings"
	"time"

	v5 "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/match"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/prioritization"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

const indicator = "†"

// ControlSummaryWithSeverity wraps ControlSummary to add severity field for JSON output
type ControlSummaryWithSeverity struct {
	reportsummary.ControlSummary
	Severity string `json:"severity"`
}

// ResourceAssociatedControlWithSeverity wraps ResourceAssociatedControl to add severity field
type ResourceAssociatedControlWithSeverity struct {
	resourcesresults.ResourceAssociatedControl
	Severity string      `json:"severity"`
	Evidence []PathValue `json:"evidence,omitempty"`
}

// PathValue pairs a failed path with the current value read from the
// resource object at that path. It's additive alongside the existing
// FailedPath/ReviewPath/FixPath strings already present on
// ResourceAssociatedControl - those are unchanged, so any existing
// consumer parsing them sees no difference; Evidence is a new, separate
// field a consumer opts into reading.
type PathValue struct {
	Path string `json:"path"`
	// Value is not omitempty: anyToString never returns a Go empty string on
	// a successful resolution (an empty JSON string field renders as the
	// literal "" two-character value), but omitempty would silently drop a
	// genuinely empty resolved value if that ever changes, serializing an
	// evidence item with only path and no indication a value exists.
	Value string `json:"value"`
}

// failedPathValues resolves each of control's FailedPaths against
// resource's captured object, skipping paths whose value is sensitive (see
// isSensitivePath) or that can't be resolved. An unresolved path is not
// treated as an error: a rule's FailedPath can legitimately not match this
// particular resource variant (e.g. a field that's absent rather than
// present-and-wrong), so it's silently omitted from Evidence rather than
// reported as a value.
func failedPathValues(control *resourcesresults.ResourceAssociatedControl, resource workloadinterface.IMetadata) []PathValue {
	if control == nil || resource == nil {
		return nil
	}
	obj := resource.GetObject()
	kind := resource.GetKind()
	var out []PathValue
	for j := range control.ResourceAssociatedRules {
		for k := range control.ResourceAssociatedRules[j].Paths {
			p := control.ResourceAssociatedRules[j].Paths[k].FailedPath
			if p == "" || isSensitivePath(kind, p) {
				continue
			}
			if val, ok := extractValueAtPath(obj, p); ok {
				out = append(out, PathValue{Path: p, Value: val})
			}
		}
	}
	return out
}

// ResultWithSeverity wraps Result to include severity in associated controls
type ResultWithSeverity struct {
	ResourceID          string                                  `json:"resourceID"`
	AssociatedControls  []ResourceAssociatedControlWithSeverity `json:"controls,omitempty"`
	PrioritizedResource *prioritization.PrioritizedResource     `json:"prioritizedResource,omitempty"`
}

// SummaryDetailsWithSeverity wraps SummaryDetails to include enriched controls
type SummaryDetailsWithSeverity struct {
	Controls                  map[string]ControlSummaryWithSeverity `json:"controls,omitempty"`
	Status                    apis.ScanningStatus                   `json:"status"`
	Frameworks                []reportsummary.FrameworkSummary      `json:"frameworks"`
	ResourcesSeverityCounters reportsummary.SeverityCounters        `json:"resourcesSeverityCounters"`
	ControlsSeverityCounters  reportsummary.SeverityCounters        `json:"controlsSeverityCounters"`
	StatusCounters            reportsummary.StatusCounters          `json:"ResourceCounters"`
	Vulnerabilities           reportsummary.VulnerabilitySummary    `json:"vulnerabilities"`
	Score                     float32                               `json:"score"`
	ComplianceScore           float32                               `json:"complianceScore"`
}

// PostureReportWithSeverity wraps PostureReport to include severity in controls
type PostureReportWithSeverity struct {
	ReportGenerationTime string                            `json:"generationTime"`
	ClusterAPIServerInfo any                               `json:"clusterAPIServerInfo"`
	ClusterCloudProvider string                            `json:"clusterCloudProvider"`
	CustomerGUID         string                            `json:"customerGUID"`
	ClusterName          string                            `json:"clusterName"`
	ReportID             string                            `json:"reportGUID"`
	SummaryDetails       SummaryDetailsWithSeverity        `json:"summaryDetails"`
	Resources            []reporthandling.Resource         `json:"resources,omitempty"`
	Attributes           []reportsummary.PostureAttributes `json:"attributes"`
	Results              []ResultWithSeverity              `json:"results,omitempty"`
	Metadata             reporthandlingv2.Metadata         `json:"metadata"`
	ResourceLabels       map[string]map[string]string      `json:"resourceLabels,omitempty"` // map[resourceID]map[labelKey]labelValue - extracted labels from workloads
	ScanCoverage         *cautils.ScanCoverage             `json:"scanCoverage,omitempty"`
	ExceptionAudit       *cautils.ExceptionAudit           `json:"exceptionAudit,omitempty"`
}

// enrichControlsWithSeverity adds severity field to controls based on scoreFactor
func enrichControlsWithSeverity(controls reportsummary.ControlSummaries) map[string]ControlSummaryWithSeverity {
	enrichedControls := make(map[string]ControlSummaryWithSeverity)
	for controlID, control := range controls {
		enrichedControl := ControlSummaryWithSeverity{
			ControlSummary: control,
			Severity:       apis.ControlSeverityToString(control.GetScoreFactor()),
		}
		enrichedControls[controlID] = enrichedControl
	}
	return enrichedControls
}

// enrichResultsWithSeverity adds severity field to controls in results, and
// - when allResources has an entry for the result's ResourceID - resolved
// evidence values for each control's failed paths.
func enrichResultsWithSeverity(results []resourcesresults.Result, controlSummaries reportsummary.ControlSummaries, allResources map[string]workloadinterface.IMetadata) []ResultWithSeverity {
	enrichedResults := make([]ResultWithSeverity, len(results))
	for i, result := range results {
		resource := allResources[result.ResourceID]
		enrichedControls := make([]ResourceAssociatedControlWithSeverity, len(result.AssociatedControls))
		for j, control := range result.AssociatedControls {
			// Get the severity from the control summary
			severity := "Unknown"
			if controlSummary, exists := controlSummaries[control.GetID()]; exists {
				severity = apis.ControlSeverityToString(controlSummary.GetScoreFactor())
			}
			enrichedControls[j] = ResourceAssociatedControlWithSeverity{
				ResourceAssociatedControl: control,
				Severity:                  severity,
				Evidence:                  failedPathValues(&control, resource),
			}
		}
		enrichedResults[i] = ResultWithSeverity{
			ResourceID:          result.ResourceID,
			AssociatedControls:  enrichedControls,
			PrioritizedResource: result.PrioritizedResource,
		}
	}
	return enrichedResults
}

// severityRank returns a comparable rank for a severity string; unknown values rank lowest.
func severityRank(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// FilterBySeverity drops controls (and matching associated controls in results)
// that are below minSeverity. Pass an empty minSeverity to disable filtering.
func FilterBySeverity(report *PostureReportWithSeverity, minSeverity string) {
	if minSeverity == "" || report == nil {
		return
	}
	threshold := severityRank(minSeverity)

	for id, control := range report.SummaryDetails.Controls {
		if severityRank(control.Severity) < threshold {
			delete(report.SummaryDetails.Controls, id)
		}
	}

	for i, result := range report.Results {
		filtered := result.AssociatedControls[:0]
		for _, control := range result.AssociatedControls {
			if severityRank(control.Severity) >= threshold {
				filtered = append(filtered, control)
			}
		}
		report.Results[i].AssociatedControls = filtered
	}
}

// ConvertToPostureReportWithSeverity converts PostureReport to PostureReportWithSeverity
func ConvertToPostureReportWithSeverity(report *reporthandlingv2.PostureReport) *PostureReportWithSeverity {
	return ConvertToPostureReportWithSeverityAndLabels(report, nil, nil)
}

// ConvertToPostureReportWithSeverityAndLabels converts PostureReport to PostureReportWithSeverity
// and extracts specified labels from workloads
func ConvertToPostureReportWithSeverityAndLabels(report *reporthandlingv2.PostureReport, labelsToCopy []string, allResources map[string]workloadinterface.IMetadata) *PostureReportWithSeverity {
	return ConvertToPostureReportWithSeverityLabelsAndCoverage(report, labelsToCopy, allResources, nil)
}

// ConvertToPostureReportWithSeverityLabelsAndCoverage converts PostureReport to PostureReportWithSeverity,
// extracts specified labels from workloads, and attaches scan coverage gaps.
func ConvertToPostureReportWithSeverityLabelsAndCoverage(report *reporthandlingv2.PostureReport, labelsToCopy []string, allResources map[string]workloadinterface.IMetadata, coverage *cautils.ScanCoverage) *PostureReportWithSeverity {
	if report == nil {
		return nil
	}
	enrichedControls := enrichControlsWithSeverity(report.SummaryDetails.Controls)
	enrichedResults := enrichResultsWithSeverity(report.Results, report.SummaryDetails.Controls, allResources)

	// Extract labels from resources if labelsToCopy is specified
	var resourceLabels map[string]map[string]string
	if len(labelsToCopy) > 0 && allResources != nil {
		resourceLabels = extractResourceLabels(allResources, labelsToCopy)
	}

	// only attach coverage when there is something to show
	var scanCoverage *cautils.ScanCoverage
	if coverage != nil && (len(coverage.FailedGVRPulls) > 0 || len(coverage.NotEvaluatedControls) > 0 || len(coverage.PartialGVRPulls) > 0 || len(coverage.PolicyDegradations) > 0 || len(coverage.VacuousFrameworks) > 0 || len(coverage.SkippedManifests) > 0) {
		scanCoverage = coverage
	}

	return &PostureReportWithSeverity{
		ReportGenerationTime: report.ReportGenerationTime.Format("2006-01-02T15:04:05Z07:00"),
		ClusterAPIServerInfo: report.ClusterAPIServerInfo,
		ClusterCloudProvider: report.ClusterCloudProvider,
		CustomerGUID:         report.CustomerGUID,
		ClusterName:          report.ClusterName,
		ReportID:             report.ReportID,
		SummaryDetails: SummaryDetailsWithSeverity{
			Controls:                  enrichedControls,
			Status:                    report.SummaryDetails.Status,
			Frameworks:                report.SummaryDetails.Frameworks,
			ResourcesSeverityCounters: report.SummaryDetails.ResourcesSeverityCounters,
			ControlsSeverityCounters:  report.SummaryDetails.ControlsSeverityCounters,
			StatusCounters:            report.SummaryDetails.StatusCounters,
			Vulnerabilities:           report.SummaryDetails.Vulnerabilities,
			Score:                     report.SummaryDetails.Score,
			ComplianceScore:           report.SummaryDetails.ComplianceScore,
		},
		Resources:      report.Resources,
		Attributes:     report.Attributes,
		Results:        enrichedResults,
		Metadata:       report.Metadata,
		ResourceLabels: resourceLabels,
		ScanCoverage:   scanCoverage,
	}
}

// extractResourceLabels extracts specified labels from all resources
func extractResourceLabels(allResources map[string]workloadinterface.IMetadata, labelsToCopy []string) map[string]map[string]string {
	resourceLabels := make(map[string]map[string]string)

	for resourceID, resource := range allResources {
		// IMetadata doesn't have GetLabels, need to cast to IBasicWorkload
		basicWorkload, ok := resource.(workloadinterface.IBasicWorkload)
		if !ok {
			continue
		}

		labels := basicWorkload.GetLabels()
		if labels == nil {
			continue
		}

		extractedLabels := make(map[string]string)
		for _, labelKey := range labelsToCopy {
			if value, exists := labels[labelKey]; exists {
				extractedLabels[labelKey] = value
			}
		}

		// Only add to result if at least one label was found
		if len(extractedLabels) > 0 {
			resourceLabels[resourceID] = extractedLabels
		}
	}

	return resourceLabels
}

// scanContextName returns the kube context this scan actually ran against.
//
// ScanInfo.GetClusterContextName() resolves the context from the kubeconfig the
// scan selected, and that value is recorded on the session metadata. Reading the
// process-global k8sinterface.GetContextName() instead would label the report
// with the ambient context, which differs whenever --kubeconfig or
// --kube-context points somewhere else. The global remains the fallback for
// sessions that carry no cluster context metadata.
func scanContextName(data *cautils.OPASessionObj) string {
	if data.Metadata != nil {
		if cluster := data.Metadata.ContextMetadata.ClusterContextMetadata; cluster != nil && cluster.ContextName != "" {
			return cluster.ContextName
		}
	}
	return k8sinterface.GetContextName()
}

// FinalizeResults finalize the results objects by copying data from map to lists
func FinalizeResults(data *cautils.OPASessionObj) *reporthandlingv2.PostureReport {
	if data.Report.ReportGenerationTime.IsZero() {
		data.Report.ReportGenerationTime = time.Now().UTC()
	}
	if data.Report.ClusterName == "" {
		data.Report.ClusterName = cautils.AdoptClusterName(scanContextName(data))
	}
	if data.Report.ReportID == "" {
		data.Report.ReportID = data.SessionID
	}
	report := reporthandlingv2.PostureReport{
		SummaryDetails:       data.Report.SummaryDetails,
		Metadata:             *data.Metadata,
		ClusterAPIServerInfo: data.Report.ClusterAPIServerInfo,
		ReportGenerationTime: data.Report.ReportGenerationTime,
		Attributes:           data.Report.Attributes,
		ClusterName:          data.Report.ClusterName,
		CustomerGUID:         data.Report.CustomerGUID,
		ReportID:             data.Report.ReportID,
		ClusterCloudProvider: data.Report.ClusterCloudProvider,
	}

	report.Results = make([]resourcesresults.Result, len(data.ResourcesResult))
	finalizeResults(report.Results, data.ResourcesResult, data.ResourcesPrioritized)

	if !data.OmitRawResources {
		report.Resources = finalizeResources(report.Results, data.AllResources, data.ResourceSource)
	}

	return &report
}
func finalizeResults(results []resourcesresults.Result, resourcesResult map[string]resourcesresults.Result, prioritizedResources map[string]prioritization.PrioritizedResource) {
	resourceIDs := make([]string, 0, len(resourcesResult))
	for resourceID := range resourcesResult {
		resourceIDs = append(resourceIDs, resourceID)
	}
	sort.Strings(resourceIDs)

	for index, resourceID := range resourceIDs {
		results[index] = resourcesResult[resourceID]

		// Deterministic per-resource layout: AssociatedControls arrive in
		// whatever order concurrent evaluation appended them (or however a
		// session built outside the processor assembled them), so sort by
		// ControlID before the report leaves this function.
		slices.SortFunc(results[index].AssociatedControls, func(a, b resourcesresults.ResourceAssociatedControl) int {
			return strings.Compare(a.ControlID, b.ControlID)
		})

		// Add prioritization information to the result
		if v, exist := prioritizedResources[resourceID]; exist {
			results[index].PrioritizedResource = &v
		}
	}
}

type infoStars struct {
	stars string
	info  string
}

// mapInfoToPrintInfo assigns a footnote marker to every distinct skip reason.
// Controls are walked in ID order: marker assignment follows iteration order, so
// ranging over the map directly gives a different marker per run and lets two
// calls over the same controls disagree.
func mapInfoToPrintInfo(controls reportsummary.ControlSummaries) []infoStars {
	controlIDs := make([]string, 0, len(controls))
	for controlID := range controls {
		controlIDs = append(controlIDs, controlID)
	}
	sort.Strings(controlIDs)

	infoToPrintInfo := []infoStars{}
	infoToPrintInfoMap := map[string]any{}
	starCount := indicator
	for _, controlID := range controlIDs {
		control := controls[controlID]
		if control.GetStatus().IsSkipped() && control.GetStatus().Info() != "" {
			if _, ok := infoToPrintInfoMap[control.GetStatus().Info()]; !ok {
				infoToPrintInfo = append(infoToPrintInfo, infoStars{
					info:  control.GetStatus().Info(),
					stars: starCount,
				})
				starCount += indicator
				infoToPrintInfoMap[control.GetStatus().Info()] = nil
			}
		}
	}
	return infoToPrintInfo
}

func finalizeResources(results []resourcesresults.Result, allResources map[string]workloadinterface.IMetadata, resourcesSource map[string]reporthandling.Source) []reporthandling.Resource {
	resources := make([]reporthandling.Resource, 0)
	for i := range results {
		if obj, ok := allResources[results[i].ResourceID]; ok {
			resource := *reporthandling.NewResourceIMetadata(obj)
			if r, ok := resourcesSource[results[i].ResourceID]; ok {
				resource.SetSource(&r)
			}
			resources = append(resources, resource)
		}
	}
	return resources
}

func setSeverityToSummaryMap(cves []imageprinter.CVE, mapSeverityToSummary map[string]*imageprinter.SeveritySummary) {
	for _, cve := range cves {
		if _, ok := mapSeverityToSummary[cve.Severity]; !ok {
			mapSeverityToSummary[cve.Severity] = &imageprinter.SeveritySummary{}
		}

		mapSeverityToSummary[cve.Severity].NumberOfCVEs += 1

		if cve.FixedState == string(v5.FixedState) {
			mapSeverityToSummary[cve.Severity].NumberOfFixableCVEs = mapSeverityToSummary[cve.Severity].NumberOfFixableCVEs + 1
		}
	}
}

// pkgScoreKey builds a collision-free map key from a package name and
// version. A plain "name@version" join is not enough on its own: Name and
// Version are free-form strings from Grype, and real-world values can
// contain "@" (e.g. npm scoped package names like "@angular/core"), so two
// different (name, version) pairs could still join to the same string -
// e.g. name="foo@bar", version="baz" and name="foo", version="bar@baz"
// both become "foo@bar@baz". Escaping "@" (and the escape character
// itself) in each part before joining ensures the delimiter "@" can always
// be told apart from an escaped literal one, so distinct pairs never
// collide.
func pkgScoreKey(name, version string) string {
	escape := func(s string) string {
		s = strings.ReplaceAll(s, `\`, `\\`)
		return strings.ReplaceAll(s, "@", `\@`)
	}
	return escape(name) + "@" + escape(version)
}

func setPkgNameToScoreMap(matches match.Matches, pkgScores map[string]*imageprinter.PackageScore) {
	for _, m := range matches.Sorted() {
		key := pkgScoreKey(m.Package.Name, m.Package.Version)

		if _, ok := pkgScores[key]; !ok {
			pkgScores[key] = &imageprinter.PackageScore{
				Version:                 m.Package.Version,
				Name:                    m.Package.Name,
				MapSeverityToCVEsNumber: make(map[string]int, 0),
			}
		}

		if _, ok := pkgScores[key].MapSeverityToCVEsNumber[m.Vulnerability.Metadata.Severity]; !ok {
			pkgScores[key].MapSeverityToCVEsNumber[m.Vulnerability.Metadata.Severity] = 1
		} else {
			pkgScores[key].MapSeverityToCVEsNumber[m.Vulnerability.Metadata.Severity] += 1
		}

		pkgScores[key].Score += utils.ImageSeverityToInt(m.Vulnerability.Metadata.Severity)
	}
}

func extractCVEs(matches match.Matches, image string, vexStatuses map[string]cautils.VexStatus) []imageprinter.CVE {
	var CVEs []imageprinter.CVE
	for _, m := range matches.Sorted() {
		cve := imageprinter.CVE{
			ID:          m.Vulnerability.Metadata.ID,
			Severity:    m.Vulnerability.Metadata.Severity,
			Package:     m.Package.Name,
			Version:     m.Package.Version,
			FixVersions: m.Vulnerability.Fix.Versions,
			FixedState:  m.Vulnerability.Fix.State.String(),
			Image:       image,
		}
		if vexStatus, ok := vexStatuses[cve.ID]; ok {
			cve.VexStatus = vexStatus.Status
			cve.VexJustification = vexStatus.Justification
		}
		CVEs = append(CVEs, cve)
	}
	return CVEs
}

// buildImageScanSummary aggregates per-image scan data into the summary every
// output format consumes. The image list is deduplicated with a set so this is
// O(N) in the number of images; the printer-local copies this replaces used
// slices.Contains and were O(N^2) on large image sets.
func buildImageScanSummary(imageScanData []cautils.ImageScanData) *imageprinter.ImageScanSummary {
	return buildImageScanSummaryWithTarget(imageScanData, true)
}

// buildMachineImageScanSummary preserves the historical image reference used
// by JSON and YAML reports. Platform metadata must not silently change image
// identifiers that downstream consumers use for joins and deduplication.
func buildMachineImageScanSummary(imageScanData []cautils.ImageScanData) *imageprinter.ImageScanSummary {
	return buildImageScanSummaryWithTarget(imageScanData, false)
}

func buildImageScanSummaryWithTarget(imageScanData []cautils.ImageScanData, includePlatform bool) *imageprinter.ImageScanSummary {
	imageScanSummary := &imageprinter.ImageScanSummary{
		CVEs:                  []imageprinter.CVE{},
		PackageScores:         map[string]*imageprinter.PackageScore{},
		MapsSeverityToSummary: map[string]*imageprinter.SeveritySummary{},
	}

	seenImages := make(map[string]struct{}, len(imageScanData))
	for i := range imageScanData {
		image := imageScanData[i].Image
		if includePlatform {
			image = imageScanData[i].Target()
		}
		if _, seen := seenImages[image]; !seen {
			seenImages[image] = struct{}{}
			imageScanSummary.Images = append(imageScanSummary.Images, image)
		}

		if imageScanSummary.VulnDBBuilt == nil {
			imageScanSummary.VulnDBBuilt = imageScanData[i].VulnDBBuilt
		}

		cves := extractCVEs(imageScanData[i].Matches, image, imageScanData[i].VexStatuses)
		imageScanSummary.CVEs = append(imageScanSummary.CVEs, cves...)

		setPkgNameToScoreMap(imageScanData[i].Matches, imageScanSummary.PackageScores)

		setSeverityToSummaryMap(cves, imageScanSummary.MapsSeverityToSummary)
	}

	return imageScanSummary
}
