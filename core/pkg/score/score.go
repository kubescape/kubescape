package score

import (
	"context"
	"fmt"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/hostsensorutils"
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
	if reportVersion == EPostureReportV2 {
		return su.scoreUtil.SetPostureReportComplianceScores(su.opaSessionObj.Report)
	}

	return fmt.Errorf("unsupported score calculator")
}

func (su *ScoreWrapper) CalculateWithTelemetry(ctx context.Context, reportVersion PostureReportVersion, telemetryChan <-chan hostsensorutils.SyscallEvent) error {
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
			fmt.Printf("Received telemetry: %+v\n", event)
			// Adjust su.opaSessionObj.Report scores dynamically based on utilized capabilities
		}
	}
}

func NewScoreWrapper(opaSessionObj *cautils.OPASessionObj) *ScoreWrapper {
	return &ScoreWrapper{
		scoreUtil:     score.NewScore(opaSessionObj.AllResources),
		opaSessionObj: opaSessionObj,
	}
}
