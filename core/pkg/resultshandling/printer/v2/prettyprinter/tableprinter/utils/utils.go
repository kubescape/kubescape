package utils

import (
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/enescakir/emoji"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jwalton/gchalk"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"golang.org/x/term"
)

type InfoStars struct {
	Stars string
	Info  string
}

// isNilSummary also recognizes a nil summary pointer held in a non-nil interface.
func isNilSummary(summary any) bool {
	if summary == nil {
		return true
	}
	v := reflect.ValueOf(summary)
	return v.Kind() == reflect.Pointer && v.IsNil()
}

func MapInfoToPrintInfoFromIface(ctrls []reportsummary.IControlSummary) []InfoStars {
	return collectInfoStars(ctrls)
}

func MapInfoToPrintInfo(controls reportsummary.ControlSummaries) []InfoStars {
	ordered := make([]reportsummary.IControlSummary, 0, len(controls))
	for id := range controls {
		ctrl := controls[id]
		ordered = append(ordered, &ctrl)
	}
	return collectInfoStars(ordered)
}

// collectInfoStars assigns a star marker to each distinct info message. Every
// caller reaches it from a map or from a slice built by iterating one, so the
// controls are put in a fixed order first: without it the same scan hands a
// different star to each message on every run.
func collectInfoStars(ctrls []reportsummary.IControlSummary) []InfoStars {
	filtered := make([]reportsummary.IControlSummary, 0, len(ctrls))
	for _, ctrl := range ctrls {
		if !isNilSummary(ctrl) {
			filtered = append(filtered, ctrl)
		}
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].GetName() != filtered[j].GetName() {
			return filtered[i].GetName() < filtered[j].GetName()
		}
		return filtered[i].GetID() < filtered[j].GetID()
	})

	infoToPrintInfo := []InfoStars{}
	infoToPrintInfoMap := map[string]any{}
	starCount := "*"
	for _, ctrl := range filtered {
		status := ctrl.GetStatus()
		if status == nil || !status.IsSkipped() || status.Info() == "" {
			continue
		}
		if _, ok := infoToPrintInfoMap[status.Info()]; ok {
			continue
		}
		infoToPrintInfo = append(infoToPrintInfo, InfoStars{
			Info:  status.Info(),
			Stars: starCount,
		})
		starCount += "*"
		infoToPrintInfoMap[status.Info()] = nil
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
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case strings.ToLower(apis.SeverityCriticalString):
		return 5
	case strings.ToLower(apis.SeverityHighString):
		return 4
	case strings.ToLower(apis.SeverityMediumString):
		return 3
	case strings.ToLower(apis.SeverityLowString):
		return 2
	case strings.ToLower(apis.SeverityNegligibleString):
		return 1
	default:
		return 0
	}
}

func FrameworksScoresToString(frameworks []reportsummary.IFrameworkSummary) string {
	valid := make([]reportsummary.IFrameworkSummary, 0, len(frameworks))
	for _, fw := range frameworks {
		if !isNilSummary(fw) {
			valid = append(valid, fw)
		}
	}
	if len(valid) == 1 {
		if valid[0].GetName() != "" {
			return fmt.Sprintf("Framework scanned: %s\n", valid[0].GetName())
		}
	} else if len(valid) > 1 {
		var p strings.Builder
		p.WriteString("Frameworks scanned: ")
		for i, fw := range valid {
			scoreStr := "N/A"
			if fw.GetComplianceScore() >= 0 {
				scoreStr = cautils.ComplianceScoreToString(fw.GetComplianceScore(), 2)
			}
			separator := ", "
			if i == len(valid)-1 {
				separator = "\n"
			}
			fmt.Fprintf(&p, "%s (compliance score: %s)%s", fw.GetName(), scoreStr, separator)
		}
		return p.String()
	}
	return ""
}

func PrintInfo(writer io.Writer, infoToPrintInfo []InfoStars) {
	fmt.Fprintln(writer)
	for i := range infoToPrintInfo {
		cautils.InfoDisplay(writer, "%s %s %s\n", emoji.PoliceCarLight, infoToPrintInfo[i].Stars, infoToPrintInfo[i].Info)
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
			var headerStr string
			var hasHeaderStr bool
			if idx < len(headers) {
				headerStr, hasHeaderStr = headers[idx].(string)
			}
			if !hasHeaderStr {
				// If header is not available or not a string, use cell length
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
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case strings.ToLower(apis.SeverityCriticalString):
		return gchalk.WithAnsi256(1).Bold
	case strings.ToLower(apis.SeverityHighString):
		return gchalk.WithAnsi256(196).Bold
	case strings.ToLower(apis.SeverityMediumString):
		return gchalk.WithAnsi256(166).Bold
	case strings.ToLower(apis.SeverityLowString):
		return gchalk.WithAnsi256(220).Bold
	case strings.ToLower(apis.SeverityNegligibleString):
		return gchalk.WithAnsi256(39).Bold
	case strings.ToLower(apis.SeverityUnknownString):
		return gchalk.WithAnsi256(30).Bold
	default:
		return gchalk.WithAnsi256(7).Bold
	}
}
