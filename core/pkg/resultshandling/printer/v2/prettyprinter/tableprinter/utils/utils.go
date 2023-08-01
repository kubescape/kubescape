package utils

import (
	"fmt"
	"io"

	"github.com/fatih/color"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

type InfoStars struct {
	Stars string
	Info  string
}

func MapInfoToPrintInfoFromIface(ctrls []reportsummary.IControlSummary) []InfoStars {
	infoToPrintInfo := []InfoStars{}
	infoToPrintInfoMap := map[string]interface{}{}
	starCount := "*"
	for _, ctrl := range ctrls {
		if ctrl.GetStatus().IsSkipped() && ctrl.GetStatus().Info() != "" {
			if _, ok := infoToPrintInfoMap[ctrl.GetStatus().Info()]; !ok {
				infoToPrintInfo = append(infoToPrintInfo, InfoStars{
					Info:  ctrl.GetStatus().Info(),
					Stars: starCount,
				})
				starCount += "*"
				infoToPrintInfoMap[ctrl.GetStatus().Info()] = nil
			}
		}
	}
	return infoToPrintInfo
}

func MapInfoToPrintInfo(controls reportsummary.ControlSummaries) []InfoStars {
	infoToPrintInfo := []InfoStars{}
	infoToPrintInfoMap := map[string]interface{}{}
	starCount := "*"
	for _, control := range controls {
		if control.GetStatus().IsSkipped() && control.GetStatus().Info() != "" {
			if _, ok := infoToPrintInfoMap[control.GetStatus().Info()]; !ok {
				infoToPrintInfo = append(infoToPrintInfo, InfoStars{
					Info:  control.GetStatus().Info(),
					Stars: starCount,
				})
				starCount += "*"
				infoToPrintInfoMap[control.GetStatus().Info()] = nil
			}
		}
	}
	return infoToPrintInfo
}

func GetColor(severity int) color.Attribute {
	switch severity {
	case apis.SeverityCritical:
		return color.FgRed
	case apis.SeverityHigh:
		return color.FgYellow
	case apis.SeverityMedium:
		return color.FgCyan
	case apis.SeverityLow:
		return color.FgWhite
	default:
		return color.FgWhite
	}
}

func ImageSeverityToInt(severity string) int {
	switch severity {
	case apis.SeverityCriticalString:
		return 5
	case apis.SeverityHighString:
		return 4
	case apis.SeverityMediumString:
		return 3
	case apis.SeverityLowString:
		return 2
	case apis.SeverityNegligibleString:
		return 1
	default:
		return 0
	}
}

func FrameworksScoresToString(frameworks []reportsummary.IFrameworkSummary) string {
	if len(frameworks) == 1 {
		if frameworks[0].GetName() != "" {
			return fmt.Sprintf("FRAMEWORK %s\n", frameworks[0].GetName())
			// cautils.InfoTextDisplay(prettyPrinter.writer, ))
		}
	} else if len(frameworks) > 1 {
		p := "FRAMEWORKS: "
		i := 0
		for ; i < len(frameworks)-1; i++ {
			p += fmt.Sprintf("%s (compliance: %.2f), ", frameworks[i].GetName(), frameworks[i].GetComplianceScore())
		}
		p += fmt.Sprintf("%s (compliance: %.2f)\n", frameworks[i].GetName(), frameworks[i].GetComplianceScore())
		return p
	}
	return ""
}

func PrintInfo(writer io.Writer, infoToPrintInfo []InfoStars) {
	fmt.Println()
	for i := range infoToPrintInfo {
		cautils.InfoDisplay(writer, fmt.Sprintf("%s %s\n", infoToPrintInfo[i].Stars, infoToPrintInfo[i].Info))
	}
}

func GetStatusColor(status apis.ScanningStatus) color.Attribute {
	switch status {
	case apis.StatusPassed:
		return color.FgGreen
	case apis.StatusFailed:
		return color.FgRed
	case apis.StatusSkipped:
		return color.FgCyan
	default:
		return color.FgWhite
	}
}

func getColor(controlSeverity int) color.Attribute {
	switch controlSeverity {
	case apis.SeverityCritical:
		return color.FgRed
	case apis.SeverityHigh:
		return color.FgYellow
	case apis.SeverityMedium:
		return color.FgCyan
	case apis.SeverityLow:
		return color.FgWhite
	default:
		return color.FgWhite
	}
}
