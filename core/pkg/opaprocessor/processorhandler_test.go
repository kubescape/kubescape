package opaprocessor

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/mocks"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/resources"
	"github.com/stretchr/testify/assert"

	"github.com/kubescape/k8s-interface/workloadinterface"
	// _ "k8s.io/client-go/plugin/pkg/client/auth"
)

func NewOPAProcessorMock() *OPAProcessor {
	return &OPAProcessor{}
}
func TestProcessResourcesResult(t *testing.T) {

	// set k8s
	k8sResources := make(cautils.K8SResources)

	deployment := mocks.MockDevelopmentWithHostpath()
	frameworks := []reporthandling.Framework{*mocks.MockFramework_0006_0013()}

	k8sResources["apps/v1/deployments"] = workloadinterface.ListMetaIDs([]workloadinterface.IMetadata{deployment})

	// set opaSessionObj
	opaSessionObj := cautils.NewOPASessionObjMock()
	opaSessionObj.Policies = frameworks

	policies := ConvertFrameworksToPolicies(opaSessionObj.Policies, "")
	ConvertFrameworksToSummaryDetails(&opaSessionObj.Report.SummaryDetails, opaSessionObj.Policies, policies)

	opaSessionObj.K8SResources = &k8sResources
	opaSessionObj.AllResources[deployment.GetID()] = deployment

	opap := NewOPAProcessor(opaSessionObj, resources.NewRegoDependenciesDataMock())
	opap.Process(policies, nil)

	assert.Equal(t, 1, len(opaSessionObj.ResourcesResult))
	res := opaSessionObj.ResourcesResult[deployment.GetID()]
	assert.Equal(t, 2, res.ListControlsIDs(nil).All().Len())
	assert.Equal(t, 1, len(res.ListControlsIDs(nil).Failed()))
	assert.Equal(t, 1, len(res.ListControlsIDs(nil).Passed()))
	assert.True(t, res.GetStatus(nil).IsFailed())
	assert.False(t, res.GetStatus(nil).IsPassed())
	assert.Equal(t, deployment.GetID(), opaSessionObj.ResourcesResult[deployment.GetID()].ResourceID)

	opap.updateResults()
	res = opaSessionObj.ResourcesResult[deployment.GetID()]
	assert.Equal(t, 2, res.ListControlsIDs(nil).All().Len())
	assert.Equal(t, 2, res.ListControlsIDs(nil).All().Len())
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
	assert.Equal(t, 1, summaryDetails.ListResourcesIDs().All().Len())
	assert.Equal(t, 1, len(summaryDetails.ListResourcesIDs().Failed()))
	assert.Equal(t, 0, len(summaryDetails.ListResourcesIDs().Excluded()))
	assert.Equal(t, 0, len(summaryDetails.ListResourcesIDs().Passed()))

	// test control listing
	assert.Equal(t, res.ListControlsIDs(nil).All().Len(), summaryDetails.NumberOfControls().All())
	assert.Equal(t, len(res.ListControlsIDs(nil).Passed()), summaryDetails.NumberOfControls().Passed())
	assert.Equal(t, len(res.ListControlsIDs(nil).Failed()), summaryDetails.NumberOfControls().Failed())
	assert.Equal(t, len(res.ListControlsIDs(nil).Excluded()), summaryDetails.NumberOfControls().Excluded())
	assert.True(t, summaryDetails.GetStatus().IsFailed())

	opaSessionObj.Exceptions = []armotypes.PostureExceptionPolicy{*mocks.MockExceptionAllKinds(&armotypes.PosturePolicy{FrameworkName: frameworks[0].Name})}
	opap.updateResults()

	res = opaSessionObj.ResourcesResult[deployment.GetID()]
	assert.Equal(t, 2, res.ListControlsIDs(nil).All().Len())
	assert.Equal(t, 1, len(res.ListControlsIDs(nil).Excluded()))
	assert.Equal(t, 1, len(res.ListControlsIDs(nil).Passed()))
	assert.True(t, res.GetStatus(nil).IsExcluded())
	assert.False(t, res.GetStatus(nil).IsPassed())
	assert.False(t, res.GetStatus(nil).IsFailed())
	assert.Equal(t, deployment.GetID(), opaSessionObj.ResourcesResult[deployment.GetID()].ResourceID)

	// test resource listing
	summaryDetails = opaSessionObj.Report.SummaryDetails
	assert.Equal(t, 1, summaryDetails.ListResourcesIDs().All().Len())
	assert.Equal(t, 1, len(summaryDetails.ListResourcesIDs().Failed()))
	assert.Equal(t, 0, len(summaryDetails.ListResourcesIDs().Excluded()))
	assert.Equal(t, 0, len(summaryDetails.ListResourcesIDs().Passed()))
}
