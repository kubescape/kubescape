package v2

import (
	"fmt"
	"strings"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
)

type metricsName string

const (
	ksMetrics        metricsName = "kubescape"
	metricsCluster   metricsName = "cluster"
	metricsScore     metricsName = "riskScore"
	metricsCount     metricsName = "count"
	metricsFailed    metricsName = "failed"
	metricsExcluded  metricsName = "exclude"
	metricsPassed    metricsName = "passed"
	metricsControl   metricsName = "control"
	metricsControls  metricsName = "controls"
	metricsResource  metricsName = "resource"
	metricsResources metricsName = "resources"
	metricsFramework metricsName = "framework"
)

// ============================================ CLUSTER ============================================================
func (mrs *mRiskScore) metrics() []string {
	/*
		##### Overall risk score
		kubescape_cluster_riskScore{} <risk score>

		###### Overall resources counters
		kubescape_cluster_count_resources_failed{} <counter>
		kubescape_cluster_count_resources_excluded{} <counter>
		kubescape_cluster_count_resources_passed{} <counter>

		###### Overall controls counters
		kubescape_cluster_count_controls_failed{} <counter>
		kubescape_cluster_count_controls_excluded{} <counter>
		kubescape_cluster_count_controls_passed{} <counter>
	*/

	m := []string{}
	// overall
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s", mrs.prefix(), metricsScore), mrs.labels(), mrs.riskScore))

	// resources
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s_%s_%s", mrs.prefix(), metricsCount, metricsResources, metricsFailed), mrs.labels(), mrs.resourcesCountFailed))
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s_%s_%s", mrs.prefix(), metricsCount, metricsResources, metricsExcluded), mrs.labels(), mrs.resourcesCountExcluded))
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s_%s_%s", mrs.prefix(), metricsCount, metricsResources, metricsPassed), mrs.labels(), mrs.resourcesCountPassed))

	// controls
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s_%s_%s", mrs.prefix(), metricsCount, metricsControl, metricsFailed), mrs.labels(), mrs.controlsCountFailed))
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s_%s_%s", mrs.prefix(), metricsCount, metricsControl, metricsExcluded), mrs.labels(), mrs.controlsCountExcluded))
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s_%s_%s", mrs.prefix(), metricsCount, metricsControl, metricsPassed), mrs.labels(), mrs.controlsCountPassed))

	return m
}
func (mrs *mRiskScore) labels() string {
	return ""
}

func (mrs *mRiskScore) prefix() string {
	return fmt.Sprintf("%s_%s", ksMetrics, metricsCluster)
}

// ============================================ CONTROL ============================================================

func (mcrs *mControlRiskScore) metrics() []string {
	/*
		# Risk score
		kubescape_control_riskScore{name="<control name>",url="<docs url>",severity="<control severity>"} <risk score>

		# Resources counters
		kubescape_control_count_resources_failed{name="<control name>",url="<docs url>",severity="<control severity>"} <counter>
		kubescape_control_count_resources_excluded{name="<control name>",url="<docs url>",severity="<control severity>"} <counter>
		kubescape_control_count_resources_passed{name="<control name>",url="<docs url>",severity="<control severity>"} <counter>
	*/

	m := []string{}
	// overall
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s", mcrs.prefix(), metricsScore), mcrs.labels(), mcrs.riskScore))

	// resources
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s_%s_%s", mcrs.prefix(), metricsCount, metricsResources, metricsFailed), mcrs.labels(), mcrs.resourcesCountFailed))
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s_%s_%s", mcrs.prefix(), metricsCount, metricsResources, metricsExcluded), mcrs.labels(), mcrs.resourcesCountExcluded))
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s_%s_%s", mcrs.prefix(), metricsCount, metricsResources, metricsPassed), mcrs.labels(), mcrs.resourcesCountPassed))

	return m
}
func (mcrs *mControlRiskScore) labels() string {
	r := fmt.Sprintf("name=\"%s\"", mcrs.controlName) + ","
	r += fmt.Sprintf("severity=\"%s\"", mcrs.severity) + ","
	r += fmt.Sprintf("link=\"%s\"", mcrs.link)
	return r
}
func (mcrs *mControlRiskScore) prefix() string {
	return fmt.Sprintf("%s_%s", ksMetrics, metricsControl)
}

// ============================================ FRAMEWORK ============================================================

func (mfrs *mFrameworkRiskScore) metrics() []string {
	/*
		#### Frameworks metrics
		kubescape_framework_riskScore{name="<framework name>"} <risk score>

		###### Frameworks resources counters
		kubescape_framework_count_resources_failed{} <counter>
		kubescape_framework_count_resources_excluded{} <counter>
		kubescape_framework_count_resources_passed{} <counter>

		###### Frameworks controls counters
		kubescape_framework_count_controls_failed{name="<framework name>"} <counter>
		kubescape_framework_count_controls_excluded{name="<framework name>"} <counter>
		kubescape_framework_count_controls_passed{name="<framework name>"} <counter>

	*/

	m := []string{}
	// overall
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s", mfrs.prefix(), metricsScore), mfrs.labels(), mfrs.riskScore))

	// resources
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s_%s_%s", mfrs.prefix(), metricsCount, metricsResources, metricsFailed), mfrs.labels(), mfrs.resourcesCountFailed))
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s_%s_%s", mfrs.prefix(), metricsCount, metricsResources, metricsExcluded), mfrs.labels(), mfrs.resourcesCountExcluded))
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s_%s_%s", mfrs.prefix(), metricsCount, metricsResources, metricsPassed), mfrs.labels(), mfrs.resourcesCountPassed))

	// controls
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s_%s_%s", mfrs.prefix(), metricsCount, metricsControl, metricsFailed), mfrs.labels(), mfrs.controlsCountFailed))
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s_%s_%s", mfrs.prefix(), metricsCount, metricsControl, metricsExcluded), mfrs.labels(), mfrs.controlsCountExcluded))
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s_%s_%s", mfrs.prefix(), metricsCount, metricsControl, metricsPassed), mfrs.labels(), mfrs.controlsCountPassed))

	return m
}
func (mfrs *mFrameworkRiskScore) labels() string {
	r := fmt.Sprintf("name=\"%s\"", mfrs.frameworkName)
	return r
}
func (mfrs *mFrameworkRiskScore) prefix() string {
	return fmt.Sprintf("%s_%s", ksMetrics, metricsFramework)
}

// ============================================ RESOURCES ============================================================

func (mrc *mResources) metrics() []string {
	/*
		#### Resources metrics
		kubescape_resource_count_controls_failed{apiVersion="<>",kind="<>",namespace="<>",name="<>"} <counter>
		kubescape_resource_count_controls_excluded{apiVersion="<>",kind="<>",namespace="<>",name="<>"} <counter>
	*/

	m := []string{}

	// controls
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s_%s_%s", mrc.prefix(), metricsCount, metricsControls, metricsFailed), mrc.labels(), mrc.controlsCountFailed))
	m = append(m, toRowInMetrics(fmt.Sprintf("%s_%s_%s_%s", mrc.prefix(), metricsCount, metricsControls, metricsExcluded), mrc.labels(), mrc.controlsCountExcluded))
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

type mRiskScore struct {
	resourcesCountPassed   int
	resourcesCountFailed   int
	resourcesCountExcluded int
	controlsCountPassed    int
	controlsCountFailed    int
	controlsCountExcluded  int
	controlsCountSkipped   int
	riskScore              int
}

type mControlRiskScore struct {
	controlName            string
	controlID              string
	link                   string
	severity               string
	remediation            string
	resourcesCountPassed   int
	resourcesCountFailed   int
	resourcesCountExcluded int
	riskScore              int
}

type mFrameworkRiskScore struct {
	frameworkName          string
	resourcesCountPassed   int
	resourcesCountFailed   int
	resourcesCountExcluded int
	controlsCountPassed    int
	controlsCountFailed    int
	controlsCountExcluded  int
	controlsCountSkipped   int
	riskScore              int
}

type mResources struct {
	name                  string
	namespace             string
	apiVersion            string
	kind                  string
	controlsCountPassed   int
	controlsCountFailed   int
	controlsCountExcluded int
}
type Metrics struct {
	rs             mRiskScore
	listFrameworks []mFrameworkRiskScore
	listControls   []mControlRiskScore
	listResources  []mResources
}

func (mrs *mRiskScore) set(resources reportsummary.ICounters, controls reportsummary.ICounters) {
	mrs.resourcesCountExcluded = resources.Excluded()
	mrs.resourcesCountFailed = resources.Failed()
	mrs.resourcesCountPassed = resources.Passed()
	mrs.controlsCountExcluded = controls.Excluded()
	mrs.controlsCountFailed = controls.Failed()
	mrs.controlsCountPassed = controls.Passed()
	mrs.controlsCountSkipped = controls.Skipped()
}

func (mfrs *mFrameworkRiskScore) set(resources reportsummary.ICounters, controls reportsummary.ICounters) {
	mfrs.resourcesCountExcluded = resources.Excluded()
	mfrs.resourcesCountFailed = resources.Failed()
	mfrs.resourcesCountPassed = resources.Passed()
	mfrs.controlsCountExcluded = controls.Excluded()
	mfrs.controlsCountFailed = controls.Failed()
	mfrs.controlsCountPassed = controls.Passed()
	mfrs.controlsCountSkipped = controls.Skipped()
}

func (mcrs *mControlRiskScore) set(resources reportsummary.ICounters) {
	mcrs.resourcesCountExcluded = resources.Excluded()
	mcrs.resourcesCountFailed = resources.Failed()
	mcrs.resourcesCountPassed = resources.Passed()
}
func (m *Metrics) setRiskScores(summaryDetails *reportsummary.SummaryDetails) {
	m.rs.set(summaryDetails.NumberOfResources(), summaryDetails.NumberOfControls())
	m.rs.riskScore = cautils.Float32ToInt(summaryDetails.GetScore())

	for _, fw := range summaryDetails.ListFrameworks() {
		mfrs := mFrameworkRiskScore{
			frameworkName: fw.GetName(),
			riskScore:     cautils.Float32ToInt(fw.GetScore()),
		}
		mfrs.set(fw.NumberOfResources(), fw.NumberOfControls())
		m.listFrameworks = append(m.listFrameworks, mfrs)
	}

	for _, control := range summaryDetails.ListControls() {
		mcrs := mControlRiskScore{
			controlName: control.GetName(),
			controlID:   control.GetID(),
			riskScore:   cautils.Float32ToInt(control.GetScore()),
			link:        cautils.GetControlLink(control.GetID()),
			severity:    apis.ControlSeverityToString(control.GetScoreFactor()),
			remediation: control.GetRemediation(),
		}
		mcrs.set(control.NumberOfResources())
		m.listControls = append(m.listControls, mcrs)
	}
}

// return -> (passed, exceluded, failed)
func resourceControlStatusCounters(result *resourcesresults.Result) (int, int, int) {
	failed := 0
	excluded := 0
	passed := 0
	for i := range result.ListControls() {
		switch result.ListControls()[i].GetStatus(nil).Status() {
		case apis.StatusExcluded:
			excluded++
		case apis.StatusFailed:
			failed++
		case apis.StatusPassed:
			passed++
		}
	}
	return passed, excluded, failed
}
func (m *Metrics) setResourcesCounters(
	resources map[string]workloadinterface.IMetadata,
	results map[string]resourcesresults.Result) {

	for resourceID, result := range results {
		r, ok := resources[resourceID]
		if !ok {
			continue
		}
		passed, excluded, failed := resourceControlStatusCounters(&result)

		mrc := mResources{}
		mrc.apiVersion = r.GetApiVersion()
		mrc.namespace = r.GetNamespace()
		mrc.kind = r.GetKind()
		mrc.name = r.GetName()

		// append
		mrc.controlsCountPassed = passed
		mrc.controlsCountFailed = failed
		mrc.controlsCountExcluded = excluded

		m.listResources = append(m.listResources, mrc)
	}

}
