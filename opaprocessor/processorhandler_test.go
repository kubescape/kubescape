package opaprocessor

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/mocks"
	"github.com/armosec/opa-utils/objectsenvelopes"
	"github.com/armosec/opa-utils/reporthandling"
	"github.com/armosec/opa-utils/resources"
	"github.com/stretchr/testify/assert"

	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/k8s-interface/workloadinterface"
	// _ "k8s.io/client-go/plugin/pkg/client/auth"
)

func NewOPAProcessorMock() *OPAProcessor {
	return &OPAProcessor{}
}
func TestProcess(t *testing.T) {

	// set k8s
	k8sResources := make(cautils.K8SResources)
	allResources := make(map[string]workloadinterface.IMetadata)
	imetaObj := objectsenvelopes.ListMapToMeta(k8sinterface.ConvertUnstructuredSliceToMap(k8sinterface.V1KubeSystemNamespaceMock().Items))
	for i := range imetaObj {
		allResources[imetaObj[i].GetID()] = imetaObj[i]
	}
	k8sResources["/v1/pods"] = workloadinterface.ListMetaIDs(imetaObj)

	// set opaSessionObj
	opaSessionObj := cautils.NewOPASessionObjMock()
	opaSessionObj.Frameworks = []reporthandling.Framework{*reporthandling.MockFrameworkA()}
	policies := ConvertFrameworksToPolicies(opaSessionObj.Frameworks, "")

	opaSessionObj.K8SResources = &k8sResources
	opaSessionObj.AllResources = allResources

	opap := NewOPAProcessor(opaSessionObj, resources.NewRegoDependenciesDataMock())
	opap.Process(policies)
	opap.updateResults()
	for _, f := range opap.PostureReport.FrameworkReports {
		for _, c := range f.ControlReports {
			for _, r := range c.RuleReports {
				for _, rr := range r.RuleResponses {
					// t.Errorf("AlertMessage: %v", rr.AlertMessage)
					if rr.Exception != nil {
						t.Errorf("Exception: %v", rr.Exception)
					}
				}
			}
		}
	}

}

func TestProcessResourcesResult(t *testing.T) {

	// set k8s
	k8sResources := make(cautils.K8SResources)

	deployment := mocks.MockDevelopmentWithHostpath()
	frameworks := []reporthandling.Framework{*mocks.MockFramework_0006_0013()}

	k8sResources["apps/v1/deployments"] = workloadinterface.ListMetaIDs([]workloadinterface.IMetadata{deployment})

	// set opaSessionObj
	opaSessionObj := cautils.NewOPASessionObjMock()
	opaSessionObj.Frameworks = frameworks

	policies := ConvertFrameworksToPolicies(opaSessionObj.Frameworks, "")
	ConvertFrameworksToSummaryDetails(&opaSessionObj.Report.SummaryDetails, opaSessionObj.Frameworks, policies)

	opaSessionObj.K8SResources = &k8sResources
	opaSessionObj.AllResources[deployment.GetID()] = deployment

	opap := NewOPAProcessor(opaSessionObj, resources.NewRegoDependenciesDataMock())
	opap.Process(policies)

	assert.Equal(t, 1, len(opaSessionObj.ResourcesResult))
	res := opaSessionObj.ResourcesResult[deployment.GetID()]
	assert.Equal(t, 2, len(res.ListControlsIDs(nil).All()))
	assert.Equal(t, 1, len(res.ListControlsIDs(nil).Failed()))
	assert.Equal(t, 1, len(res.ListControlsIDs(nil).Passed()))
	assert.True(t, res.GetStatus(nil).IsFailed())
	assert.False(t, res.GetStatus(nil).IsPassed())
	assert.Equal(t, deployment.GetID(), opaSessionObj.ResourcesResult[deployment.GetID()].ResourceID)

	opap.updateResults()
	res = opaSessionObj.ResourcesResult[deployment.GetID()]
	assert.Equal(t, 2, len(res.ListControlsIDs(nil).All()))
	assert.Equal(t, 2, len(res.ListControlsIDs(nil).All()))
	assert.Equal(t, 1, len(res.ListControlsIDs(nil).Failed()))
	assert.Equal(t, 1, len(res.ListControlsIDs(nil).Passed()))
	assert.True(t, res.GetStatus(nil).IsFailed())
	assert.False(t, res.GetStatus(nil).IsPassed())
	assert.Equal(t, deployment.GetID(), opaSessionObj.ResourcesResult[deployment.GetID()].ResourceID)

	// test resource counters
	summaryDetails := opaSessionObj.Report.SummaryDetails
	assert.Equal(t, 1, summaryDetails.NumberOfResources().All())
	assert.Equal(t, 1, summaryDetails.NumberOfResources().Failed())
	assert.Equal(t, 0, summaryDetails.NumberOfResources().Excluded())
	assert.Equal(t, 0, summaryDetails.NumberOfResources().Passed())

	// test resource listing
	assert.Equal(t, 1, len(summaryDetails.ListResourcesIDs().All()))
	assert.Equal(t, 1, len(summaryDetails.ListResourcesIDs().Failed()))
	assert.Equal(t, 0, len(summaryDetails.ListResourcesIDs().Excluded()))
	assert.Equal(t, 0, len(summaryDetails.ListResourcesIDs().Passed()))

	// test control listing
	assert.Equal(t, len(res.ListControlsIDs(nil).All()), len(summaryDetails.ListControls().All()))
	assert.Equal(t, len(res.ListControlsIDs(nil).Passed()), len(summaryDetails.ListControls().Passed()))
	assert.Equal(t, len(res.ListControlsIDs(nil).Failed()), len(summaryDetails.ListControls().Failed()))
	assert.Equal(t, len(res.ListControlsIDs(nil).Excluded()), len(summaryDetails.ListControls().Excluded()))
	assert.True(t, summaryDetails.GetStatus().IsFailed())

	opaSessionObj.Exceptions = []armotypes.PostureExceptionPolicy{*mocks.MockExceptionAllKinds(&armotypes.PosturePolicy{FrameworkName: frameworks[0].Name})}
	opap.updateResults()

	res = opaSessionObj.ResourcesResult[deployment.GetID()]
	assert.Equal(t, 2, len(res.ListControlsIDs(nil).All()))
	assert.Equal(t, 1, len(res.ListControlsIDs(nil).Excluded()))
	assert.Equal(t, 1, len(res.ListControlsIDs(nil).Passed()))
	assert.True(t, res.GetStatus(nil).IsExcluded())
	assert.False(t, res.GetStatus(nil).IsPassed())
	assert.False(t, res.GetStatus(nil).IsFailed())
	assert.Equal(t, deployment.GetID(), opaSessionObj.ResourcesResult[deployment.GetID()].ResourceID)

	// test resource listing
	summaryDetails = opaSessionObj.Report.SummaryDetails
	assert.Equal(t, 1, len(summaryDetails.ListResourcesIDs().All()))
	assert.Equal(t, 1, len(summaryDetails.ListResourcesIDs().Failed()))
	assert.Equal(t, 0, len(summaryDetails.ListResourcesIDs().Excluded()))
	assert.Equal(t, 0, len(summaryDetails.ListResourcesIDs().Passed()))
}
