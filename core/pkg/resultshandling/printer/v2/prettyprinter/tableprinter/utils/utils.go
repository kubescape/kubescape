package utils

import (
	"fmt"
	"io"
	"os"

	"github.com/enescakir/emoji"
	"github.com/jwalton/gchalk"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"golang.org/x/term"
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

func GetColor(severity int) func(...string) string {
	switch severity {
	case apis.SeverityCritical:
		return gchalk.WithAnsi256(1).Bold
	case apis.SeverityHigh:
		return gchalk.WithAnsi256(196).Bold
	case apis.SeverityMedium:
		return gchalk.WithAnsi256(166).Bold
	case apis.SeverityLow:
		return gchalk.WithAnsi256(220).Bold
	default:
		return gchalk.WithAnsi256(16).Bold
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
			return fmt.Sprintf("Framework scanned: %s\n", frameworks[0].GetName())
		}
	} else if len(frameworks) > 1 {
		p := "Frameworks scanned: "
		i := 0
		for ; i < len(frameworks)-1; i++ {
			p += fmt.Sprintf("%s (compliance score: %.2f), ", frameworks[i].GetName(), frameworks[i].GetComplianceScore())
		}
		p += fmt.Sprintf("%s (compliance score: %.2f)\n", frameworks[i].GetName(), frameworks[i].GetComplianceScore())
		return p
	}
	return ""
}

func PrintInfo(writer io.Writer, infoToPrintInfo []InfoStars) {
	fmt.Println()
	for i := range infoToPrintInfo {
		cautils.InfoDisplay(writer, fmt.Sprintf("%s %s %s\n", emoji.PoliceCarLight, infoToPrintInfo[i].Stars, infoToPrintInfo[i].Info))
	}
}

func GetStatusColor(status apis.ScanningStatus) func(...string) string {
	switch status {
	case apis.StatusPassed:
		return gchalk.WithGreen().Bold
	case apis.StatusFailed:
		return gchalk.WithRed().Bold
	case apis.StatusSkipped:
		return gchalk.WithCyan().Bold
	default:
		return gchalk.WithWhite().Bold
	}
}

func GetStatusIcon(status apis.ScanningStatus) string {
	switch status {
	case apis.StatusPassed:
		return "✅"
	case apis.StatusFailed:
		return "❌"
	case apis.StatusSkipped:
		return "⚠️"
	default:
		return "⚠️"
	}
}

func CheckShortTerminalWidth(rows [][]string, headers []string) bool {
	maxWidth := 0
	for _, row := range rows {
		rowWidth := 0
		for idx, cell := range row {
			cellLen := len(cell)
			if cellLen > 50 { // Take only 50 characters of each sentence for counting size
				cellLen = 50
			}
			if cellLen > len(headers[idx]) {
				rowWidth += cellLen
			} else {
				rowWidth += len(headers[idx])
			}
			rowWidth += 2
		}
		if rowWidth > maxWidth {
			maxWidth = rowWidth
		}
	}
	maxWidth += 10
	termWidth, _, err := term.GetSize(int(os.Stdin.Fd()))
	if err != nil {
		// Default to larger output table
		return false
	}
	return termWidth <= maxWidth
}

func GetColorForVulnerabilitySeverity(severity string) func(...string) string {
	switch severity {
	case apis.SeverityCriticalString:
		return gchalk.WithAnsi256(1).Bold
	case apis.SeverityHighString:
		return gchalk.WithAnsi256(196).Bold
	case apis.SeverityMediumString:
		return gchalk.WithAnsi256(166).Bold
	case apis.SeverityLowString:
		return gchalk.WithAnsi256(220).Bold
	case apis.SeverityNegligibleString:
		return gchalk.WithAnsi256(39).Bold
	case apis.SeverityUnknownString:
		return gchalk.WithAnsi256(30).Bold
	default:
		return gchalk.WithAnsi256(7).Bold
	}
}
