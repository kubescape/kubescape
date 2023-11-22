package score

import (
	"testing"

	cautils "github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/stretchr/testify/assert"
)

func TestNewScoreWrapper(t *testing.T) {
	opaSessionObj := cautils.NewOPASessionObjMock()

	scoreWrapper := NewScoreWrapper(opaSessionObj)

	assert.NotNil(t, scoreWrapper)
	assert.NotNil(t, scoreWrapper.scoreUtil)
	assert.Equal(t, opaSessionObj, scoreWrapper.opaSessionObj)
}

func TestNewScoreWrapperWithNilAllResources(t *testing.T) {
	opaSessionObj := &cautils.OPASessionObj{
		AllResources: nil,
	}
	scoreWrapper := NewScoreWrapper(opaSessionObj)

	assert.NotNil(t, scoreWrapper)
	assert.NotNil(t, scoreWrapper.scoreUtil)
	assert.NotNil(t, scoreWrapper.opaSessionObj)
	assert.Nil(t, scoreWrapper.opaSessionObj.AllResources)
	assert.Empty(t, scoreWrapper.opaSessionObj.AllResources)
}

func TestCalculateReturnsNilErrorWhenReportVersionIsEPostureReportV2(t *testing.T) {
	opaSessionObj := cautils.NewOPASessionObjMock()
	scoreWrapper := NewScoreWrapper(opaSessionObj)

	err := scoreWrapper.Calculate(EPostureReportV2)

	assert.Nil(t, err)
}

func TestCalculateReturnsErrorWhenReportVersionIsEPostureReportV1(t *testing.T) {
	opaSessionObj := &cautils.OPASessionObj{}
	scoreWrapper := NewScoreWrapper(opaSessionObj)

	err := scoreWrapper.Calculate(EPostureReportV1)

	assert.Error(t, err)
	assert.Equal(t, "unsupported score calculator", err.Error())
}

func TestCalculateReturnsErrorWhenReportVersionIsNotSupported(t *testing.T) {
	opaSessionObj := &cautils.OPASessionObj{}
	scoreWrapper := NewScoreWrapper(opaSessionObj)

	err := scoreWrapper.Calculate("v3")

	assert.Error(t, err)
	assert.Equal(t, "unsupported score calculator", err.Error())
}
