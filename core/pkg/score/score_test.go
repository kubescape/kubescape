package score

import (
	"context"
	"testing"
	"time"

	cautils "github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/hostsensorutils"
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

func TestCalculateWithTelemetry_ContextDone(t *testing.T) {
	opaSessionObj := cautils.NewOPASessionObjMock()
	scoreWrapper := NewScoreWrapper(opaSessionObj)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	telemetryChan := make(chan hostsensorutils.SyscallEvent)
	err := scoreWrapper.CalculateWithTelemetry(ctx, EPostureReportV2, telemetryChan)
	assert.NoError(t, err)
}

func TestCalculateWithTelemetry_ChannelClose(t *testing.T) {
	opaSessionObj := cautils.NewOPASessionObjMock()
	scoreWrapper := NewScoreWrapper(opaSessionObj)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	telemetryChan := make(chan hostsensorutils.SyscallEvent, 2)
	telemetryChan <- hostsensorutils.SyscallEvent{}
	close(telemetryChan)

	err := scoreWrapper.CalculateWithTelemetry(ctx, EPostureReportV2, telemetryChan)
	assert.NoError(t, err)
}
