package watch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/diff"
)

// Baseline is the scan that later scans are compared with: the last one that was
// complete enough to compare with. It lives in memory for as long as a watch
// does, which is as long as there is anything to compare; nothing is saved, as a
// scan that is started again starts again from its first scan.
//
// A scan is handed to Observe, which compares it and decides whether it becomes
// the baseline. The rules:
//
//   - A scan that failed, or whose report cannot be read or compared, is not a
//     baseline and does not change it. The error is returned, and the baseline
//     is as it was.
//   - A scan that is incomplete is compared, so that what it does show is shown,
//     but is not a baseline: comparing with it would call what it left out new
//     when a later, complete scan has it. See Observation.Gaps for what makes a
//     scan incomplete. It is the report's own scanCoverage that says so, and a
//     report without one cannot say that it is complete.
//   - A policy input that came from a fallback (policyDegradations) does not
//     make a scan incomplete. It does not prevent the scan from being a baseline,
//     as it would for the whole of a watch that runs offline. What it does is
//     what Compare does with it: the findings it could affect are Incomparable,
//     with the reason.
//   - The first complete scan is the baseline, and has nothing to be compared
//     with. A first scan that is not complete is not, and the baseline waits for
//     one that is.
//   - The baseline changes in one step, once the scan has been read, compared and
//     found complete. Nothing is half done.
//
// A Baseline is safe for concurrent use, though a watch scans one scan at a time.
type Baseline struct {
	mu   sync.Mutex
	last *snapshot
}

// NewBaseline returns a Baseline that has no scan yet.
func NewBaseline() *Baseline { return &Baseline{} }

// Has reports whether there is a baseline to compare with.
func (b *Baseline) Has() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.last != nil
}

// Observation is what Observe made of a scan.
type Observation struct {
	// Result is the comparison with the baseline. It is nil when there was no
	// baseline.
	Result *Result
	// Initial is set when this scan became the first baseline.
	Initial bool
	// Advanced is set when this scan is now the baseline, which is when it was
	// complete.
	Advanced bool
	// Gaps say why the scan is not complete, and so is not the baseline: what the
	// report says it could not read, parse or evaluate. It is empty when it is.
	Gaps []string
	// Notes say what a complete scan went without that does not stop it from
	// being the baseline: policy inputs that came from a fallback.
	Notes []string
}

// Observe compares a scan with the baseline, and makes it the baseline if it is
// complete. scanErr is the error of the scan that made reportJSON, if it failed;
// the baseline is then kept, and the error returned, with reportJSON ignored.
func (b *Baseline) Observe(reportJSON []byte, scanErr error, options diff.Options) (*Observation, error) {
	if scanErr != nil {
		return nil, fmt.Errorf("the scan failed, so the baseline is kept: %w", scanErr)
	}
	next, err := newSnapshot(reportJSON)
	if err != nil {
		return nil, fmt.Errorf("the report cannot be compared, so the baseline is kept: %w", err)
	}
	gaps, notes, err := coverageOf(reportJSON)
	if err != nil {
		return nil, fmt.Errorf("the report cannot be compared, so the baseline is kept: %w", err)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	observation := &Observation{Gaps: gaps, Notes: notes}
	if b.last != nil {
		result, err := classify(b.last, next, options)
		if err != nil {
			return nil, fmt.Errorf("the scan cannot be compared with the baseline, so the baseline is kept: %w", err)
		}
		observation.Result = result
	}
	if len(gaps) == 0 {
		observation.Initial = b.last == nil
		observation.Advanced = true
		b.last = next
	}
	return observation, nil
}

// coverageOf says what a report's scanCoverage makes of the scan: the gaps that
// make it incomplete, and the notes that do not. It reads the coverage the scan
// wrote, with the type that wrote it, and invents no flag of its own.
func coverageOf(reportJSON []byte) (gaps, notes []string, err error) {
	var report struct {
		ScanCoverage *cautils.ScanCoverage `json:"scanCoverage"`
	}
	decoder := json.NewDecoder(bytes.NewReader(reportJSON))
	if err := decoder.Decode(&report); err != nil {
		return nil, nil, fmt.Errorf("read the scan coverage: %w", err)
	}
	coverage := report.ScanCoverage
	if coverage == nil {
		return []string{"the report has no scanCoverage, so it cannot say that the scan was complete"}, nil, nil
	}

	if coverage.TotalControls == 0 {
		gaps = append(gaps, "no control was in scope, so nothing was evaluated")
	}
	if n := len(coverage.FailedGVRPulls); n > 0 {
		gaps = append(gaps, fmt.Sprintf("%d resource type(s) could not be read", n))
	}
	if n := len(coverage.PartialGVRPulls); n > 0 {
		gaps = append(gaps, fmt.Sprintf("%d resource type(s) were read in part", n))
	}
	if n := len(coverage.SkippedManifests); n > 0 {
		gaps = append(gaps, fmt.Sprintf("%d manifest(s) were skipped: they could not be loaded", n))
	}
	if n := len(coverage.NotEvaluatedControls); n > 0 {
		ids := make([]string, 0, n)
		for _, control := range coverage.NotEvaluatedControls {
			ids = append(ids, control.ControlID)
		}
		sort.Strings(ids)
		gaps = append(gaps, fmt.Sprintf("%d control(s) were not evaluated: %s", n, strings.Join(ids, ", ")))
	}
	if n := len(coverage.PolicyDegradations); n > 0 {
		components := make([]string, 0, n)
		for _, degradation := range coverage.PolicyDegradations {
			components = append(components, degradation.Component)
		}
		sort.Strings(components)
		notes = append(notes, fmt.Sprintf("%d policy input(s) came from a fallback: %s", n, strings.Join(components, ", ")))
	}
	// A degraded scan with no recorded cause and no policy fallback is one the
	// report cannot account for; it is not taken to be complete.
	if coverage.Degraded && len(gaps) == 0 && len(coverage.PolicyDegradations) == 0 {
		gaps = append(gaps, "the scan is marked degraded with no recorded cause")
	}
	return gaps, notes, nil
}
