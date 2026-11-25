package score

import (
	"context"
	"errors"
	"fmt"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/hostsensorutils"
	"github.com/kubescape/opa-utils/score"
)

/*
	provides a wrapper for scoreUtils, since there's no common interface between postureReportV1 and PostureReportV2

and the need of concrete objects

	I've decided to create scoreWrapper that will allow calculating score regardless (as long as opaSessionObj is there)
*/
type ScoreWrapper struct {
	scoreUtil     *score.ScoreUtil
	opaSessionObj *cautils.OPASessionObj
}

type PostureReportVersion string

const (
	EPostureReportV1 PostureReportVersion = "v1"
	EPostureReportV2 PostureReportVersion = "V2"
)

func (su *ScoreWrapper) Calculate(reportVersion PostureReportVersion) error {
	if su == nil || su.opaSessionObj == nil {
		return errors.New("uninitialized score wrapper")
	}
	if su.scoreUtil == nil {
		su.scoreUtil = score.NewScore(su.opaSessionObj.AllResources)
	}
	if reportVersion == EPostureReportV2 {
		if su.opaSessionObj.Report == nil {
			return errors.New("nil posture report")
		}
		return su.scoreUtil.SetPostureReportComplianceScores(su.opaSessionObj.Report)
	}

	return fmt.Errorf("unsupported score calculator")
}

// CalculateWithTelemetry dynamically adjusts scores based on eBPF telemetry events.
// Note: Library code must never write directly to stdout as it would corrupt JSON/SARIF output.
func (su *ScoreWrapper) CalculateWithTelemetry(ctx context.Context, reportVersion PostureReportVersion, telemetryChan <-chan hostsensorutils.SyscallEvent) error {
	if su == nil || su.opaSessionObj == nil {
		return errors.New("uninitialized score wrapper")
	}
	// Dynamically adjust scores based on eBPF telemetry
	// This is a stub implementation
	for {
		select {
		case <-ctx.Done():
			return su.Calculate(reportVersion)
		case event, ok := <-telemetryChan:
			if !ok {
				// Channel closed, compute final score
				return su.Calculate(reportVersion)
			}
			logger.L().Debug("received telemetry", helpers.Interface("event", event))
			// Adjust su.opaSessionObj.Report scores dynamically based on utilized capabilities
		}
	}
}

func NewScoreWrapper(opaSessionObj *cautils.OPASessionObj) *ScoreWrapper {
	if opaSessionObj == nil {
		return &ScoreWrapper{
			scoreUtil: score.NewScore(nil),
		}
	}
	return &ScoreWrapper{
		scoreUtil:     score.NewScore(opaSessionObj.AllResources),
		opaSessionObj: opaSessionObj,
	}
}
