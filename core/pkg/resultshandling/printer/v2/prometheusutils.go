package printer

import (
	"fmt"
	"strings"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

type metricsName string

const (
	ksMetrics        metricsName = "kubescape"
	metricsCluster   metricsName = "cluster"
	metricsScore     metricsName = "complianceScore"
	metricsCount     metricsName = "count"
	metricsFailed    metricsName = "failed"
	metricsSkipped   metricsName = "skipped"
	metricsPassed    metricsName = "passed"
	metricsControl   metricsName = "control"
	metricsControls  metricsName = "controls"
	metricsResource  metricsName = "resource"
	metricsResources metricsName = "resources"
	metricsFramework metricsName = "framework"
)

// ============================================ CLUSTER ============================================================
func (mrs *mComplianceScore) metrics() []string {
	/*
		##### Overall compliance score
		kubescape_cluster_ComplianceScore{} <compliance score>

		###### Overall resources counters
		kubescape_cluster_count_resources_failed{} <counter>
		kubescape_cluster_count_resources_skipped{} <counter>
		kubescape_cluster_count_resources_passed{} <counter>

		###### Overall controls counters
		kubescape_cluster_count_controls_failed{} <counter>
		kubescape_cluster_count_controls_skipped{} <counter>
		kubescape_cluster_count_controls_passed{} <counter>
	*/

	m := []string{}
	// overall
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s", mrs.prefix(), metricsScore), mrs.labels(), mrs.complianceScore))

	// resources
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s_%s_%s", mrs.prefix(), metricsCount, metricsResources, metricsFailed), mrs.labels(), mrs.resourcesCountFailed))
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s_%s_%s", mrs.prefix(), metricsCount, metricsResources, metricsSkipped), mrs.labels(), mrs.resourcesCountSkipped))
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s_%s_%s", mrs.prefix(), metricsCount, metricsResources, metricsPassed), mrs.labels(), mrs.resourcesCountPassed))

	// controls
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s_%s_%s", mrs.prefix(), metricsCount, metricsControl, metricsFailed), mrs.labels(), mrs.controlsCountFailed))
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s_%s_%s", mrs.prefix(), metricsCount, metricsControl, metricsSkipped), mrs.labels(), mrs.controlsCountSkipped))
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s_%s_%s", mrs.prefix(), metricsCount, metricsControl, metricsPassed), mrs.labels(), mrs.controlsCountPassed))

	return m
}
func (mrs *mComplianceScore) labels() string {
	return ""
}

func (mrs *mComplianceScore) prefix() string {
	return fmt.Sprintf("%s_%s", ksMetrics, metricsCluster)
}

// ============================================ CONTROL ============================================================

func (mcrs *mControlComplianceScore) metrics() []string {
	/*
		# Compliance score
		kubescape_control_complianceScore{name="<control name>",url="<docs url>",severity="<control severity>"} <compliance score>

		# Resources counters
		kubescape_control_count_resources_failed{name="<control name>",url="<docs url>",severity="<control severity>"} <counter>
		kubescape_control_count_resources_skipped{name="<control name>",url="<docs url>",severity="<control severity>"} <counter>
		kubescape_control_count_resources_passed{name="<control name>",url="<docs url>",severity="<control severity>"} <counter>
	*/

	m := []string{}
	// overall
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s", mcrs.prefix(), metricsScore), mcrs.labels(), mcrs.complianceScore))

	// resources
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s_%s_%s", mcrs.prefix(), metricsCount, metricsResources, metricsFailed), mcrs.labels(), mcrs.resourcesCountFailed))
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s_%s_%s", mcrs.prefix(), metricsCount, metricsResources, metricsSkipped), mcrs.labels(), mcrs.resourcesCountSkipped))
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s_%s_%s", mcrs.prefix(), metricsCount, metricsResources, metricsPassed), mcrs.labels(), mcrs.resourcesCountPassed))

	return m
}
func (mcrs *mControlComplianceScore) labels() string {
	r := fmt.Sprintf("name=\"%s\"", mcrs.controlName) + ","
	r += fmt.Sprintf("severity=\"%s\"", mcrs.severity) + ","
	r += fmt.Sprintf("link=\"%s\"", mcrs.link)
	return r
}
func (mcrs *mControlComplianceScore) prefix() string {
	return fmt.Sprintf("%s_%s", ksMetrics, metricsControl)
}

// ============================================ FRAMEWORK ============================================================

func (mfrs *mFrameworkComplianceScore) metrics() []string {
	/*
		#### Frameworks metrics
		kubescape_framework_complianceScore{name="<framework name>"} <compliance score>

		###### Frameworks resources counters
		kubescape_framework_count_resources_failed{} <counter>
		kubescape_framework_count_resources_skipped{} <counter>
		kubescape_framework_count_resources_passed{} <counter>

		###### Frameworks controls counters
		kubescape_framework_count_controls_failed{name="<framework name>"} <counter>
		kubescape_framework_count_controls_skipped{name="<framework name>"} <counter>
		kubescape_framework_count_controls_passed{name="<framework name>"} <counter>

	*/

	m := []string{}
	// overall
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s", mfrs.prefix(), metricsScore), mfrs.labels(), mfrs.complianceScore))

	// resources
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s_%s_%s", mfrs.prefix(), metricsCount, metricsResources, metricsFailed), mfrs.labels(), mfrs.resourcesCountFailed))
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s_%s_%s", mfrs.prefix(), metricsCount, metricsResources, metricsSkipped), mfrs.labels(), mfrs.resourcesCountSkipped))
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s_%s_%s", mfrs.prefix(), metricsCount, metricsResources, metricsPassed), mfrs.labels(), mfrs.resourcesCountPassed))

	// controls
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s_%s_%s", mfrs.prefix(), metricsCount, metricsControl, metricsFailed), mfrs.labels(), mfrs.controlsCountFailed))
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s_%s_%s", mfrs.prefix(), metricsCount, metricsControl, metricsSkipped), mfrs.labels(), mfrs.controlsCountSkipped))
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s_%s_%s", mfrs.prefix(), metricsCount, metricsControl, metricsPassed), mfrs.labels(), mfrs.controlsCountPassed))

	return m
}
func (mfrs *mFrameworkComplianceScore) labels() string {
	r := fmt.Sprintf("name=\"%s\"", mfrs.frameworkName)
	return r
}
func (mfrs *mFrameworkComplianceScore) prefix() string {
	return fmt.Sprintf("%s_%s", ksMetrics, metricsFramework)
}

// ============================================ RESOURCES ============================================================

func (mrc *mResources) metrics() []string {
	/*
		#### Resources metrics
		kubescape_resource_count_controls_failed{apiVersion="<>",kind="<>",namespace="<>",name="<>"} <counter>
		kubescape_resource_count_controls_skipped{apiVersion="<>",kind="<>",namespace="<>",name="<>"} <counter>
	*/

	m := []string{}

	// controls
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s_%s_%s", mrc.prefix(), metricsCount, metricsControls, metricsFailed), mrc.labels(), mrc.controlsCountFailed))
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s_%s_%s", mrc.prefix(), metricsCount, metricsControls, metricsSkipped), mrc.labels(), mrc.controlsCountSkipped))
	return m
}

func (mrc *mResources) labels() string {
	r := fmt.Sprintf("apiVersion=\"%s\"", mrc.apiVersion) + ","
	r += fmt.Sprintf("kind=\"%s\"", mrc.kind) + ","
	r += fmt.Sprintf("namespace=\"%s\"", mrc.namespace) + ","
	r += fmt.Sprintf("name=\"%s\"", mrc.name)
	return r
}
func (mrc *mResources) prefix() string {
	return fmt.Sprintf("%s_%s", ksMetrics, metricsResource)
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

func toRowInMetrics(name string, row string, value int) string {
	return fmt.Sprintf("%s{%s} %d", name, row, value)

}
func (m *Metrics) String() string {

	r := strings.Join(m.rs.metrics(), "\n") + "\n"
	for i := range m.listFrameworks {
		r += strings.Join(m.listFrameworks[i].metrics(), "\n") + "\n"
	}
	for i := range m.listControls {
		r += strings.Join(m.listControls[i].metrics(), "\n") + "\n"
	}
	for i := range m.listResources {
		r += strings.Join(m.listResources[i].metrics(), "\n") + "\n"
	}
	return r
}

type mComplianceScore struct {
	resourcesCountPassed  int
	resourcesCountFailed  int
	resourcesCountSkipped int
	controlsCountPassed   int
	controlsCountFailed   int
	controlsCountSkipped  int
	complianceScore       int
}

type mControlComplianceScore struct {
	controlName           string
	controlID             string
	link                  string
	severity              string
	remediation           string
	resourcesCountPassed  int
	resourcesCountFailed  int
	resourcesCountSkipped int
	complianceScore       int
}

type mFrameworkComplianceScore struct {
	frameworkName         string
	resourcesCountPassed  int
	resourcesCountFailed  int
	resourcesCountSkipped int
	controlsCountPassed   int
	controlsCountFailed   int
	controlsCountSkipped  int
	complianceScore       int
}

type mResources struct {
	name       string
	namespace  string
	apiVersion string
	kind       string
	// controlsCountPassed   int // unused
	controlsCountFailed  int
	controlsCountSkipped int
}
type Metrics struct {
	rs             mComplianceScore
	listFrameworks []mFrameworkComplianceScore
	listControls   []mControlComplianceScore
	listResources  []mResources
}

func (mrs *mComplianceScore) set(resources reportsummary.ICounters, controls reportsummary.ICounters) {
	mrs.resourcesCountSkipped = resources.Skipped()
	mrs.resourcesCountFailed = resources.Failed()
	mrs.resourcesCountPassed = resources.Passed()
	mrs.controlsCountFailed = controls.Failed()
	mrs.controlsCountPassed = controls.Passed()
	mrs.controlsCountSkipped = controls.Skipped()
}

func (mfrs *mFrameworkComplianceScore) set(resources reportsummary.ICounters, controls reportsummary.ICounters) {
	mfrs.resourcesCountSkipped = resources.Skipped()
	mfrs.resourcesCountFailed = resources.Failed()
	mfrs.resourcesCountPassed = resources.Passed()
	mfrs.controlsCountFailed = controls.Failed()
	mfrs.controlsCountPassed = controls.Passed()
	mfrs.controlsCountSkipped = controls.Skipped()
}

func (mcrs *mControlComplianceScore) set(resources reportsummary.ICounters) {
	mcrs.resourcesCountSkipped = resources.Skipped()
	mcrs.resourcesCountFailed = resources.Failed()
	mcrs.resourcesCountPassed = resources.Passed()
}
func (m *Metrics) setComplianceScores(summaryDetails *reportsummary.SummaryDetails) {
	m.rs.set(summaryDetails.NumberOfResources(), summaryDetails.NumberOfControls())
	m.rs.complianceScore = cautils.Float32ToInt(summaryDetails.GetScore())

	for _, fw := range summaryDetails.ListFrameworks() {
		mfrs := mFrameworkComplianceScore{
			frameworkName:   fw.GetName(),
			complianceScore: cautils.Float32ToInt(fw.GetComplianceScore()),
		}
		mfrs.set(fw.NumberOfResources(), fw.NumberOfControls())
		m.listFrameworks = append(m.listFrameworks, mfrs)
	}

	for _, control := range summaryDetails.ListControls() {
		mcrs := mControlComplianceScore{
			controlName:     control.GetName(),
			controlID:       control.GetID(),
			complianceScore: cautils.Float32ToInt(control.GetScore()),
			link:            cautils.GetControlLink(control.GetID()),
			severity:        apis.ControlSeverityToString(control.GetScoreFactor()),
			remediation:     control.GetRemediation(),
		}
		mcrs.set(control.NumberOfResources())
		m.listControls = append(m.listControls, mcrs)
	}
}

/* unused for now
// return -> (passed, skipped, failed)
func resourceControlStatusCounters(result *resourcesresults.Result) (int, int, int) {
	failed := 0
	skipped := 0
	passed := 0
	for i := range result.ListControls() {
		switch result.ListControls()[i].GetStatus(nil).Status() {
		case apis.StatusSkipped:
			skipped++
		case apis.StatusFailed:
			failed++
		case apis.StatusPassed:
			passed++
		}
	}
	return passed, skipped, failed
}

func (m *Metrics) setResourcesCounters(
	resources map[string]workloadinterface.IMetadata,
	results map[string]resourcesresults.Result) {

	for resourceID, result := range results {
		r, ok := resources[resourceID]
		if !ok {
			continue
		}
		passed, skipped, failed := resourceControlStatusCounters(&result)

		mrc := mResources{}
		mrc.apiVersion = r.GetApiVersion()
		mrc.namespace = r.GetNamespace()
		mrc.kind = r.GetKind()
		mrc.name = r.GetName()

		// append
		mrc.controlsCountPassed = passed
		mrc.controlsCountFailed = failed
		mrc.controlsCountSkipped = skipped

		m.listResources = append(m.listResources, mrc)
	}

}
*/
