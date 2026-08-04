package utils

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/enescakir/emoji"
	"github.com/jedib0t/go-pretty/v6/table"
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
	infoToPrintInfoMap := map[string]any{}
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
	infoToPrintInfoMap := map[string]any{}
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
		var p strings.Builder
		p.WriteString("Frameworks scanned: ")
		i := 0
		for ; i < len(frameworks)-1; i++ {
			fmt.Fprintf(&p, "%s (compliance score: %s), ", frameworks[i].GetName(), cautils.ComplianceScoreToString(frameworks[i].GetComplianceScore(), 2))
		}
		fmt.Fprintf(&p, "%s (compliance score: %s)\n", frameworks[i].GetName(), cautils.ComplianceScoreToString(frameworks[i].GetComplianceScore(), 2))
		return p.String()
	}
	return ""
}

func PrintInfo(writer io.Writer, infoToPrintInfo []InfoStars) {
	fmt.Fprintln(writer)
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

func CheckShortTerminalWidth(rows []table.Row, headers table.Row) bool {
	maxWidth := 0
	for _, row := range rows {
		rowWidth := 0
		for idx, cell := range row {
			cellStr, ok := cell.(string)
			if !ok {
				// If cell is not a string, skip this calculation
				continue
			}
			cellLen := min(len(cellStr),
				// Take only 50 characters of each sentence for counting size
				50)
			headerStr, ok := headers[idx].(string)
			if !ok {
				// If header is not a string, use cell length
				rowWidth += cellLen
			} else if cellLen > len(headerStr) {
				rowWidth += cellLen
			} else {
				rowWidth += len(headerStr)
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

// MaxControlNameLen is the truncation limit shared by the category and
// summary table control-name columns, so the two stay in sync.
const MaxControlNameLen = 50

// TruncateName returns name unchanged if it is at most maxLen runes long,
// otherwise truncates it to maxLen runes plus an appended "..." (so the
// result is maxLen+3 runes when truncation happens).
// Slicing a string by byte index (name[:maxLen]) can split a multi-byte
// UTF-8 rune in half when name contains non-ASCII characters (e.g. non-Latin
// script, accented characters, emoji in resource/control names), producing
// invalid UTF-8 and garbled table output. Truncating by rune count avoids
// that.
func TruncateName(name string, maxLen int) string {
	runes := []rune(name)
	if len(runes) <= maxLen {
		return name
	}
	return string(runes[:maxLen]) + "..."
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
