package lsp

import (
	"cmp"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/filesizelimit"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/locationresolver"
	printerv2 "github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"go.lsp.dev/protocol"
	"go.lsp.dev/uri"
)

const diagnosticSource = "kubescape"

// severityOf maps a control's score factor to a diagnostic severity: critical and
// high controls are errors, medium ones warnings, and everything else
// information. The thresholds are the ones Kubescape's severities use
// (apis.ControlSeverityToInt), so an editor agrees with the CLI.
func severityOf(scoreFactor float32) protocol.DiagnosticSeverity {
	switch apis.ControlSeverityToInt(scoreFactor) {
	case apis.SeverityCritical, apis.SeverityHigh:
		return protocol.DiagnosticSeverityError
	case apis.SeverityMedium:
		return protocol.DiagnosticSeverityWarning
	default:
		return protocol.DiagnosticSeverityInformation
	}
}

// scanFindings is what one scan says about the files it read.
type scanFindings struct {
	// byFile holds the diagnostics of each file with findings, by path.
	byFile map[string][]protocol.Diagnostic
	// unreliable holds the files whose findings could not be placed or whose
	// manifest the scan could not load. What is known of them is kept as it is.
	unreliable map[string]struct{}
	// complete is false when the scan could not evaluate everything it was asked
	// to, so the absence of a finding proves nothing.
	complete bool
}

// findingsOf converts a scan's result into diagnostics by file.
func findingsOf(session *cautils.OPASessionObj, coverage cautils.ScanCoverage) scanFindings {
	out := scanFindings{
		byFile:     make(map[string][]protocol.Diagnostic),
		unreliable: make(map[string]struct{}),
		complete:   !degradedBeyondSkippedManifests(coverage),
	}
	for _, skipped := range coverage.SkippedManifests {
		out.unreliable[pathKey(skipped.Path)] = struct{}{}
	}
	if session == nil || session.Report == nil {
		return out
	}

	files := make(map[string]*manifest) // by path
	for resourceID, result := range session.ResourcesResult {
		if !cautils.ResourceStatus(&session.Report.SummaryDetails, &result).IsFailed() {
			continue
		}
		source := session.ResourceSource[resourceID]
		if source.RelativePath == "" {
			continue // not from a file: nothing to put a diagnostic on
		}
		root := source.Path
		if root == "" {
			continue
		}
		path := filepath.Join(root, source.RelativePath)
		file, ok := files[path]
		if !ok {
			file = loadManifest(path)
			files[path] = file
		}
		if file.err != nil {
			out.unreliable[pathKey(path)] = struct{}{}
			continue
		}
		resource, _ := session.GetResource(resourceID)
		docIndex, hasDoc := documentIndex(resource)
		for _, toPin := range result.AssociatedControls {
			ac := toPin
			if !cautils.ControlStatus(&session.Report.SummaryDetails, &ac).IsFailed() {
				continue
			}
			ctl := session.Report.SummaryDetails.Controls.GetControl(reportsummary.EControlCriteriaID, ac.GetID())
			if ctl == nil {
				continue
			}
			evidence := cautils.EvidenceControl(&session.Report.SummaryDetails, ac)
			pos := file.position(&evidence, docIndex, hasDoc)
			out.byFile[path] = append(out.byFile[path], diagnosticFor(ctl, resource, pos))
		}
	}
	for path := range out.byFile {
		sortDiagnostics(out.byFile[path])
	}
	return out
}

// degradedBeyondSkippedManifests is coverage.Degraded without the manifests the
// scan skipped. Each of those is unreliable on its own, and what is known of it
// is kept, so one file that doesn't parse leaves the rest of the scan complete
// rather than holding back the diagnostics of every other file.
func degradedBeyondSkippedManifests(coverage cautils.ScanCoverage) bool {
	coverage.SkippedManifests = nil
	coverage.ComputeCoverageScore(coverage.TotalControls)
	return coverage.Degraded
}

func diagnosticFor(ctl reportsummary.IControlSummary, resource workloadinterface.IMetadata, pos protocol.Position) protocol.Diagnostic {
	message := ctl.GetName()
	if resource != nil {
		message += fmt.Sprintf(" (%s/%s)", resource.GetKind(), resource.GetName())
	}
	if remediation := strings.TrimSpace(ctl.GetRemediation()); remediation != "" {
		message += "\nRemediation: " + remediation
	}
	d := protocol.Diagnostic{
		// The resolver gives a start and no end, so the range is zero-width.
		Range:    protocol.Range{Start: pos, End: pos},
		Severity: severityOf(ctl.GetScoreFactor()),
		Code:     protocol.String(ctl.GetID()),
		Source:   protocol.NewOptional(diagnosticSource),
		Message:  protocol.String(message),
	}
	if link := cautils.GetControlLink(ctl.GetID()); link != "" {
		d.CodeDescription = protocol.CodeDescription{Href: uri.URI(link)}
	}
	return d
}

// sortDiagnostics orders diagnostics by position, then code, then message, so
// that the same findings are always published in the same order.
func sortDiagnostics(ds []protocol.Diagnostic) {
	slices.SortStableFunc(ds, func(a, b protocol.Diagnostic) int {
		return cmp.Or(
			cmp.Compare(a.Range.Start.Line, b.Range.Start.Line),
			cmp.Compare(a.Range.Start.Character, b.Range.Start.Character),
			cmp.Compare(codeString(a), codeString(b)),
			cmp.Compare(messageString(a), messageString(b)),
		)
	})
}

func codeString(d protocol.Diagnostic) string {
	if s, ok := d.Code.(protocol.String); ok {
		return string(s)
	}
	return ""
}

func messageString(d protocol.Diagnostic) string {
	if s, ok := d.Message.(protocol.String); ok {
		return string(s)
	}
	return ""
}

// manifest is a manifest file as it is on disk: its lines, to convert the
// resolver's positions, and the resolver.
type manifest struct {
	lines    []string
	resolver *locationresolver.PathLocationResolver
	err      error
}

// loadManifest reads path, which must be a regular file within the size limit
// the scanner uses for manifests.
func loadManifest(path string) *manifest {
	data, err := readBounded(path)
	if err != nil {
		return &manifest{err: err}
	}
	m := &manifest{lines: splitLines(string(data))}
	// A resolver that cannot be made leaves the diagnostics at the fallback
	// position: the findings are still real.
	m.resolver, _ = locationresolver.NewPathLocationResolver(path, locationresolver.IndexedByWorkload(cautils.WorkloadDocuments))
	return m
}

func readBounded(path string) ([]byte, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%q is not a regular file", path)
	}
	limit := filesizelimit.GetMaxFileSize()
	if info.Size() > limit {
		return nil, fmt.Errorf("%q exceeds the manifest size limit", path)
	}
	return io.ReadAll(io.LimitReader(f, limit))
}

// splitLines splits on \n, \r\n and a lone \r, as YAML does.
func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.Split(s, "\n")
}

// position finds where a finding starts: the first failed path the control gives
// if the resolver can place it, else the resource's kind, else the start of the
// file. The fallbacks are real places in the right resource; the last is the
// documented position for a finding that cannot be placed at all.
func (m *manifest) position(evidence *resourcesresults.ResourceAssociatedControl, docIndex int, hasDoc bool) protocol.Position {
	if m.resolver == nil || !hasDoc {
		return protocol.Position{}
	}
	if paths := printerv2.AssistedRemediationPathsToString(evidence); len(paths) > 0 && paths[0] != "" {
		if loc, _ := m.resolver.ResolveLocation(paths[0], docIndex); loc.Line > 0 {
			return m.toPosition(loc)
		}
	}
	if loc, _ := m.resolver.ResolveLocation("kind", docIndex); loc.Line > 0 {
		return m.toPosition(loc)
	}
	return protocol.Position{}
}

// toPosition converts the resolver's location, whose line and column start at 1
// and whose column counts characters (runes) of the line, to an LSP position:
// zero-based, with the character counted in UTF-16 code units, the encoding LSP
// uses unless another is negotiated (none is). A location past the end of the
// file or line is clamped to it.
func (m *manifest) toPosition(loc locationresolver.Location) protocol.Position {
	if len(m.lines) == 0 {
		return protocol.Position{}
	}
	line := max(loc.Line-1, 0)
	if line >= len(m.lines) {
		line = len(m.lines) - 1
		return protocol.Position{Line: uint32(line), Character: utf16Len(m.lines[line])} //nolint:gosec // bounded by the file
	}
	return protocol.Position{Line: uint32(line), Character: utf16Offset(m.lines[line], loc.Column-1)} //nolint:gosec // bounded by the file
}

// utf16Offset is the length in UTF-16 code units of the first runes runes of
// line, or of all of it if it has fewer.
func utf16Offset(line string, runes int) uint32 {
	var units uint32
	for i := 0; i < len(line) && runes > 0; runes-- {
		r, size := utf8.DecodeRuneInString(line[i:])
		units += uint32(utf16.RuneLen(r)) //nolint:gosec // 1 or 2
		i += size
	}
	return units
}

func utf16Len(line string) uint32 { return utf16Offset(line, utf8.RuneCountInString(line)) }

// documentIndex is the position of the resource's document within its file. A
// local workload's path is "<file>:<index>"; the index follows the last colon,
// after any Windows drive letter's.
func documentIndex(resource any) (int, bool) {
	lw, ok := resource.(interface{ GetPath() string })
	if !ok {
		return 0, false
	}
	path := lw.GetPath()
	volume := filepath.VolumeName(path)
	rest := path[len(volume):]
	colon := strings.LastIndex(rest, ":")
	if colon < 0 {
		return 0, false
	}
	index, err := strconv.Atoi(rest[colon+1:])
	if err != nil || index < 0 {
		return 0, false
	}
	return index, true
}
