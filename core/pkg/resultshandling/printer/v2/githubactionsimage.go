package printer

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
)

const githubActionsImageSummaryHeader = "\n#### High/Critical Vulnerabilities\n\n| Severity | Vulnerability | Package | Version | Fixed In | Exploit Signals | Image |\n| --- | --- | --- | --- | --- | --- | --- |\n"

type ghImageFinding struct {
	severityRank int
	image        string
	cve          imageprinter.CVE
}

type ghImageCounts struct {
	image         string
	critical      int
	high          int
	medium        int
	low           int
	other         int
	vexSuppressed int
}

func (gp *GitHubActionsPrinter) printImageScan(ctx context.Context, imageScanData []cautils.ImageScanData) error {
	findings, counts := collectImageFindings(imageScanData)

	var output strings.Builder
	emitted := min(len(findings), githubActionsMaxAnnotations)
	for _, finding := range findings[:emitted] {
		fmt.Fprintf(&output, "::error title=%s::%s\n",
			escapeAnnotationProperty(finding.title()),
			escapeAnnotationData(finding.message()))
	}

	belowThreshold, vexSuppressed := 0, 0
	for _, c := range counts {
		belowThreshold += c.medium + c.low + c.other
		vexSuppressed += c.vexSuppressed
	}
	fmt.Fprintf(&output, "Kubescape: %d of %d High/Critical vulnerability(ies) annotated; %d suppressed by GitHub's 10-annotation step limit; %d vulnerability(ies) below the High severity threshold; %d marked not affected or fixed by VEX. Use --format json for the complete report.\n",
		emitted, len(findings), len(findings)-emitted, belowThreshold, vexSuppressed)

	if _, err := gp.writer.WriteString(output.String()); err != nil {
		return fmt.Errorf("failed to write GitHub Actions output: %w", err)
	}

	if gp.stepSummaryPath != "" {
		render := func(maxBytes int) string { return generateImageStepSummary(counts, findings, maxBytes) }
		if err := writeStepSummary(ctx, gp.stepSummaryPath, render); err != nil {
			logger.L().Ctx(ctx).Warning("failed to write GitHub Actions step summary", helpers.Error(err))
		}
	}

	printer.LogOutputFile(gp.writer.Name())
	return nil
}

func collectImageFindings(imageScanData []cautils.ImageScanData) ([]ghImageFinding, []ghImageCounts) {
	var findings []ghImageFinding
	var cves []imageprinter.CVE
	merged := make(map[string]int)
	counts := make([]ghImageCounts, 0, len(imageScanData))
	for i := range imageScanData {
		data := &imageScanData[i]
		label := data.Image
		if data.Platform != "" {
			label = fmt.Sprintf("%s (%s)", data.Image, data.Platform)
		}
		cves = cves[:0]
		clear(merged)
		for _, cve := range extractCVEs(data.Matches, data.Image, data.VexStatuses) {
			key := cve.ID + "\x00" + cve.Package + "\x00" + cve.Version
			if idx, duplicate := merged[key]; duplicate {
				mergeDuplicateCVE(&cves[idx], cve)
				continue
			}
			cve.FixVersions = mergeFixVersions(nil, cve.FixVersions)
			merged[key] = len(cves)
			cves = append(cves, cve)
		}

		c := ghImageCounts{image: label}
		for _, cve := range cves {
			if cve.VexStatus == "not_affected" || cve.VexStatus == "fixed" {
				c.vexSuppressed++
				continue
			}
			rank := severityRank(cve.Severity)
			switch rank {
			case 4:
				c.critical++
			case 3:
				c.high++
			case 2:
				c.medium++
			case 1:
				c.low++
			default:
				c.other++
			}
			if rank >= 3 {
				findings = append(findings, ghImageFinding{severityRank: rank, image: label, cve: cve})
			}
		}
		counts = append(counts, c)
	}

	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.severityRank != b.severityRank {
			return a.severityRank > b.severityRank
		}
		if a.cve.KEV != b.cve.KEV {
			return a.cve.KEV
		}
		if ea, eb := epssScore(a.cve.EPSS), epssScore(b.cve.EPSS); ea != eb {
			return ea > eb
		}
		if a.cve.ID != b.cve.ID {
			return a.cve.ID < b.cve.ID
		}
		if a.cve.Package != b.cve.Package {
			return a.cve.Package < b.cve.Package
		}
		return a.image < b.image
	})
	return findings, counts
}

func mergeDuplicateCVE(dst *imageprinter.CVE, src imageprinter.CVE) {
	if severityRank(src.Severity) > severityRank(dst.Severity) {
		dst.Severity = src.Severity
	}
	dst.FixVersions = mergeFixVersions(dst.FixVersions, src.FixVersions)
	dst.KEV = dst.KEV || src.KEV
	dst.KEVKnown = dst.KEVKnown || src.KEVKnown
	if epssScore(src.EPSS) > epssScore(dst.EPSS) {
		dst.EPSS = src.EPSS
	}
}

func epssScore(e *imageprinter.EPSS) float64 {
	if e == nil {
		return -1
	}
	return e.Score
}

func (f ghImageFinding) severity() string {
	if f.severityRank == 4 {
		return "Critical"
	}
	return "High"
}

func (f ghImageFinding) title() string {
	return fmt.Sprintf("%s in %s %s", f.cve.ID, f.cve.Package, f.cve.Version)
}

func (f ghImageFinding) fixedIn() string {
	return strings.Join(f.cve.FixVersions, ", ")
}

func (f ghImageFinding) exploitSignals() string {
	var signals []string
	if f.cve.KEV {
		signals = append(signals, "CISA KEV")
	}
	if f.cve.EPSS != nil {
		signals = append(signals, "EPSS "+imageprinter.FormatEPSS(f.cve.EPSS))
	}
	return strings.Join(signals, ", ")
}

func (f ghImageFinding) message() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s vulnerability %s in %s %s (image %s).", f.severity(), f.cve.ID, f.cve.Package, f.cve.Version, f.image)
	if fixed := f.fixedIn(); fixed != "" {
		fmt.Fprintf(&b, " Fixed in %s.", fixed)
	} else {
		b.WriteString(" No fix is available.")
	}
	if signals := f.exploitSignals(); signals != "" {
		fmt.Fprintf(&b, " Exploit signals: %s.", signals)
	}
	return b.String()
}

func generateImageStepSummary(counts []ghImageCounts, findings []ghImageFinding, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}

	var base strings.Builder
	base.WriteString("### Kubescape Image Scan Summary\n\n")
	base.WriteString("| Image | Critical | High | Medium | Low | Other | VEX Suppressed |\n")
	base.WriteString("| --- | ---: | ---: | ---: | ---: | ---: | ---: |\n")
	for _, c := range counts {
		fmt.Fprintf(&base, "| %s | %d | %d | %d | %d | %d | %d |\n",
			sanitizeMarkdownTableCell(c.image), c.critical, c.high, c.medium, c.low, c.other, c.vexSuppressed)
	}

	var sections []summarySection
	if len(findings) > 0 {
		rows := make([]string, 0, len(findings))
		for _, f := range findings {
			rows = append(rows, fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s |\n",
				f.severity(),
				sanitizeMarkdownTableCell(f.cve.ID),
				sanitizeMarkdownTableCell(f.cve.Package),
				sanitizeMarkdownTableCell(f.cve.Version),
				orDash(sanitizeMarkdownTableCell(f.fixedIn())),
				orDash(f.exploitSignals()),
				sanitizeMarkdownTableCell(f.image)))
		}
		sections = append(sections, summarySection{header: githubActionsImageSummaryHeader, rows: rows})
	}
	return renderSummaryWithBudget(base.String(), sections, maxBytes)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
