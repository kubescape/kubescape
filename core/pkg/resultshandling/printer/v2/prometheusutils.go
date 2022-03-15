package v2

import (
	"fmt"

	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/armosec/opa-utils/reporthandling/apis"
	"github.com/armosec/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/armosec/opa-utils/reporthandling/results/v1/resourcesresults"
)

type metricsName string

const (
	metricsFrameworkScore   metricsName = "kubescape_risk_score_framework"
	metricsControlScore     metricsName = "kubescape_risk_score_control"
	metricsScore            metricsName = "kubescape_risk_score"
	metricsresourceFailed   metricsName = "kubescape_resource_controls_number_of_failed"
	metricsresourcePassed   metricsName = "kubescape_resource_controls_number_of_passed"
	metricsresourceExcluded metricsName = "kubescape_resource_controls_number_of_exclude"
)

func (mrs *mRiskScore) string() string {
	r := fmt.Sprintf("resourcesCountFailed: \"%d\"", mrs.resourcesCountFailed) + ", "
	r += fmt.Sprintf("resourcesCountExcluded: \"%d\"", mrs.resourcesCountExcluded) + ", "
	r += fmt.Sprintf("resourcesCountPassed: \"%d\"", mrs.resourcesCountPassed) + ", "
	r += fmt.Sprintf("controlsCountFailed: \"%d\"", mrs.controlsCountFailed) + ", "
	r += fmt.Sprintf("controlsCountExcluded: \"%d\"", mrs.controlsCountExcluded) + ", "
	r += fmt.Sprintf("controlsCountPassed: \"%d\"", mrs.controlsCountPassed) + ", "
	r += fmt.Sprintf("controlsCountSkipped: \"%d\"", mrs.controlsCountSkipped) + ", "
	return r
}
func (mrs *mRiskScore) value() int {
	return mrs.riskScore
}

func (mcrs *mControlRiskScore) string() string {
	r := fmt.Sprintf("controlName: \"%s\"", mcrs.controlName) + ", "
	r += fmt.Sprintf("controlID: \"%s\"", mcrs.controlID) + ", "
	r += fmt.Sprintf("severity: \"%s\"", mcrs.severity) + ", "
	r += fmt.Sprintf("resourcesCountFailed: \"%d\"", mcrs.resourcesCountFailed) + ", "
	r += fmt.Sprintf("resourcesCountExcluded: \"%d\"", mcrs.resourcesCountExcluded) + ", "
	r += fmt.Sprintf("resourcesCountPassed: \"%d\"", mcrs.resourcesCountPassed) + ", "
	r += fmt.Sprintf("link: \"%s\"", mcrs.link) + ", "
	r += fmt.Sprintf("remediation: \"%s\"", mcrs.remediation)
	return r
}
func (mcrs *mControlRiskScore) value() int {
	return mcrs.riskScore
}

func (mfrs *mFrameworkRiskScore) string() string {
	r := fmt.Sprintf("frameworkName: \"%s\"", mfrs.frameworkName) + ", "
	r += fmt.Sprintf("resourcesCountFailed: \"%d\"", mfrs.resourcesCountFailed) + ", "
	r += fmt.Sprintf("resourcesCountExcluded: \"%d\"", mfrs.resourcesCountExcluded) + ", "
	r += fmt.Sprintf("resourcesCountPassed: \"%d\"", mfrs.resourcesCountPassed) + ", "
	r += fmt.Sprintf("controlsCountFailed: \"%d\"", mfrs.controlsCountFailed)
	r += fmt.Sprintf("controlsCountExcluded: \"%d\"", mfrs.controlsCountExcluded) + ", "
	r += fmt.Sprintf("controlsCountPassed: \"%d\"", mfrs.controlsCountPassed) + ", "
	r += fmt.Sprintf("controlsCountSkipped: \"%d\"", mfrs.controlsCountSkipped) + ", "
	return r
}
func (mfrs *mFrameworkRiskScore) value() int {
	return mfrs.riskScore
}
func (mrc *mResourceControls) string() string {
	r := fmt.Sprintf("apiVersion: \"%s\"", mrc.apiVersion) + ", "
	r += fmt.Sprintf("kind: \"%s\"", mrc.kind) + ", "
	r += fmt.Sprintf("namespace: \"%s\"", mrc.namespace) + ", "
	r += fmt.Sprintf("name: \"%s\"", mrc.name)
	return r
}
func (mrc *mResourceControls) value() int {
	return mrc.controls
}
func toRowInMetrics(name metricsName, row string, value int) string {
	return fmt.Sprintf("%s{%s} %d\n", name, row, value)

}
func (m *Metrics) String() string {

	r := toRowInMetrics(metricsScore, m.rs.string(), m.rs.value())
	for i := range m.listControls {
		r += toRowInMetrics(metricsControlScore, m.listControls[i].string(), m.listControls[i].value())
	}
	for i := range m.listFrameworks {
		r += toRowInMetrics(metricsFrameworkScore, m.listFrameworks[i].string(), m.listFrameworks[i].value())
	}
	for i := range m.listResourcesControlsFiled {
		r += toRowInMetrics(metricsresourceFailed, m.listResourcesControlsFiled[i].string(), m.listResourcesControlsFiled[i].value())
	}
	for i := range m.listResourcesControlsExcluded {
		r += toRowInMetrics(metricsresourceExcluded, m.listResourcesControlsExcluded[i].string(), m.listResourcesControlsExcluded[i].value())
	}
	for i := range m.listResourcesControlsPassed {
		r += toRowInMetrics(metricsresourcePassed, m.listResourcesControlsPassed[i].string(), m.listResourcesControlsPassed[i].value())
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
	riskScore              int // metric
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
	riskScore              int // metric
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
	riskScore              int // metric
}

type mResourceControls struct {
	name       string
	namespace  string
	apiVersion string
	kind       string
	controls   int // metric
}
type Metrics struct {
	rs                            mRiskScore
	listFrameworks                []mFrameworkRiskScore
	listControls                  []mControlRiskScore
	listResourcesControlsFiled    []mResourceControls
	listResourcesControlsPassed   []mResourceControls
	listResourcesControlsExcluded []mResourceControls
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
	m.rs.riskScore = int(summaryDetails.GetScore())

	for _, fw := range summaryDetails.ListFrameworks() {
		mfrs := mFrameworkRiskScore{
			frameworkName: fw.GetName(),
			riskScore:     int(fw.GetScore()),
		}
		mfrs.set(fw.NumberOfResources(), fw.NumberOfControls())
		m.listFrameworks = append(m.listFrameworks, mfrs)
	}

	for _, control := range summaryDetails.ListControls() {
		mcrs := mControlRiskScore{
			controlName: control.GetName(),
			controlID:   control.GetID(),
			riskScore:   int(control.GetScore()),
			link:        getControlLink(control.GetID()),
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

		mrc := mResourceControls{}
		mrc.apiVersion = r.GetApiVersion()
		mrc.namespace = r.GetNamespace()
		mrc.kind = r.GetKind()
		mrc.name = r.GetName()

		// append
		if passed > 0 {
			mrc.controls = passed
			m.listResourcesControlsPassed = append(m.listResourcesControlsPassed, mrc)
		}
		if failed > 0 {
			mrc.controls = failed
			m.listResourcesControlsFiled = append(m.listResourcesControlsFiled, mrc)
		}
		if excluded > 0 {
			mrc.controls = excluded
			m.listResourcesControlsExcluded = append(m.listResourcesControlsExcluded, mrc)
		}
	}
}
