package score

import (
	"fmt"

	"github.com/kubescape/opa-utils/score"

	"github.com/kubescape/kubescape/v3/core/cautils"
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

func NewScoreWrapper(opaSessionObj *cautils.OPASessionObj) *ScoreWrapper {
	return &ScoreWrapper{
		scoreUtil:     score.NewScore(opaSessionObj.AllResources),
		opaSessionObj: opaSessionObj,
	}
}
