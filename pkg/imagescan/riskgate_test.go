package imagescan

import (
	"errors"
	"fmt"
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeRiskGateTestMatch(id string, kev bool, epss ...float64) match.Match {
	m := makeThresholdTestMatchWithMetadata(id, vulnerability.MediumSeverity.String())
	if kev {
		m.Vulnerability.Metadata.KnownExploited = []vulnerability.KnownExploited{{CVE: id}}
	}
	for _, score := range epss {
		m.Vulnerability.Metadata.EPSS = append(m.Vulnerability.Metadata.EPSS, vulnerability.EPSS{CVE: id, EPSS: score})
	}
	return m
}

func withFixState(m match.Match, state vulnerability.FixState) match.Match {
	m.Vulnerability.Fix.State = state
	return m
}

func TestEvaluateRiskGates(t *testing.T) {
	provider := thresholdStubVulnerabilityProvider{
		metadataByID: map[string]*vulnerability.Metadata{
			"CVE-provider-kev": {KnownExploited: []vulnerability.KnownExploited{{CVE: "CVE-provider-kev"}}},
		},
		errByID: map[string]error{"CVE-error": errors.New("lookup failed")},
	}

	tests := []struct {
		name        string
		gates       RiskGates
		matches     []match.Match
		onlyFixable bool
		want        RiskGateResult
	}{
		{
			name:    "disabled gates count nothing",
			matches: []match.Match{makeRiskGateTestMatch("CVE-kev", true, 0.9), makeThresholdTestMatch("CVE-error")},
		},
		{
			name:    "KEV match fails regardless of severity",
			gates:   RiskGates{FailOnKEV: true},
			matches: []match.Match{makeRiskGateTestMatch("CVE-kev", true), makeRiskGateTestMatch("CVE-plain", false)},
			want:    RiskGateResult{KEV: 1},
		},
		{
			name:    "EPSS equal to the threshold fails",
			gates:   RiskGates{EPSSThreshold: 0.5},
			matches: []match.Match{makeRiskGateTestMatch("CVE-at", false, 0.5), makeRiskGateTestMatch("CVE-below", false, 0.4999)},
			want:    RiskGateResult{EPSS: 1, EPSSChecked: 2, EPSSScored: 2},
		},
		{
			name:    "highest of several EPSS scores is used",
			gates:   RiskGates{EPSSThreshold: 0.5},
			matches: []match.Match{makeRiskGateTestMatch("GHSA-multi", false, 0.1, 0.7, 0.2)},
			want:    RiskGateResult{EPSS: 1, EPSSChecked: 1, EPSSScored: 1},
		},
		{
			name:    "unscored match cannot trip the EPSS gate",
			gates:   RiskGates{EPSSThreshold: 0.01},
			matches: []match.Match{makeRiskGateTestMatch("CVE-unscored", false)},
			want:    RiskGateResult{EPSSChecked: 1},
		},
		{
			name:    "both gates count independently",
			gates:   RiskGates{FailOnKEV: true, EPSSThreshold: 0.5},
			matches: []match.Match{makeRiskGateTestMatch("CVE-kev-low", true, 0.01), makeRiskGateTestMatch("CVE-hot", false, 0.9)},
			want:    RiskGateResult{KEV: 1, EPSS: 1, EPSSChecked: 2, EPSSScored: 2},
		},
		{
			name:        "only-fixable skips unfixed and unknown fix states",
			gates:       RiskGates{FailOnKEV: true},
			onlyFixable: true,
			matches: []match.Match{
				withFixState(makeRiskGateTestMatch("CVE-not-fixed", true), vulnerability.FixStateNotFixed),
				withFixState(makeRiskGateTestMatch("CVE-unknown-fix", true), vulnerability.FixStateUnknown),
				withFixState(makeRiskGateTestMatch("CVE-fixed", true), vulnerability.FixStateFixed),
			},
			want: RiskGateResult{KEV: 1},
		},
		{
			name:    "provider metadata is used when the match has none",
			gates:   RiskGates{FailOnKEV: true},
			matches: []match.Match{makeThresholdTestMatch("CVE-provider-kev")},
			want:    RiskGateResult{KEV: 1},
		},
		{
			name:    "unresolvable metadata fails closed",
			gates:   RiskGates{FailOnKEV: true},
			matches: []match.Match{makeThresholdTestMatch("CVE-error")},
			want:    RiskGateResult{Indeterminate: 1},
		},
		{
			name:        "only-fixable keeps its carve-out for definitively unfixable unresolvable matches",
			gates:       RiskGates{EPSSThreshold: 0.5},
			onlyFixable: true,
			matches: []match.Match{
				makeThresholdTestMatchWithFixState("CVE-error", vulnerability.FixStateWontFix),
			},
		},
		{
			name:        "only-fixable still fails closed on unresolvable matches with an unknown fix state",
			gates:       RiskGates{EPSSThreshold: 0.5},
			onlyFixable: true,
			matches:     []match.Match{makeThresholdTestMatch("CVE-error")},
			want:        RiskGateResult{Indeterminate: 1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EvaluateRiskGates(tt.gates, match.NewMatches(tt.matches...), provider, tt.onlyFixable)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestEvaluateRiskGatesNilProviderFailsClosed(t *testing.T) {
	got := EvaluateRiskGates(RiskGates{FailOnKEV: true}, match.NewMatches(makeThresholdTestMatch("CVE-x")), nil, false)
	assert.Equal(t, RiskGateResult{Indeterminate: 1}, got)
}

func TestEvaluateRiskGatesDrainsAllMatches(t *testing.T) {
	var calls int
	provider := countingThresholdProvider{
		thresholdStubVulnerabilityProvider: thresholdStubVulnerabilityProvider{},
		calls:                              &calls,
	}
	const n = 25
	ms := make([]match.Match, 0, n)
	for i := 0; i < n; i++ {
		ms = append(ms, makeThresholdTestMatch(fmt.Sprintf("CVE-unknown-%d", i)))
	}
	got := EvaluateRiskGates(RiskGates{FailOnKEV: true}, match.NewMatches(ms...), provider, false)
	assert.Equal(t, n, got.Indeterminate)
	assert.Equal(t, n, calls, "every match must be visited; stopping early leaks the Enumerate producer goroutine")
}

// TestRiskGatesHonorSeverityExceptions pins that a regular severity exception
// waives a KEV finding: exceptions remove matches before the gate sees them.
func TestRiskGatesHonorSeverityExceptions(t *testing.T) {
	provider := thresholdStubVulnerabilityProvider{
		metadataByID: map[string]*vulnerability.Metadata{
			"CVE-2020-15999": {Severity: vulnerability.MediumSeverity.String()},
		},
	}
	matches := match.NewMatches(makeRiskGateTestMatch("CVE-2020-15999", true, 0.64))
	gates := RiskGates{FailOnKEV: true, EPSSThreshold: 0.5}

	waived := filterMatchesBasedOnSeverity([]string{"Medium"}, matches, provider)
	assert.Equal(t, RiskGateResult{}, EvaluateRiskGates(gates, waived, provider, false))

	kept := filterMatchesBasedOnSeverity([]string{"Low"}, matches, provider)
	assert.Equal(t, RiskGateResult{KEV: 1, EPSS: 1, EPSSChecked: 1, EPSSScored: 1}, EvaluateRiskGates(gates, kept, provider, false))
}

func TestCheckRiskGates(t *testing.T) {
	images := []cautils.ImageScanData{
		{Matches: match.NewMatches(makeRiskGateTestMatch("CVE-kev", true, 0.01))},
		{Matches: match.NewMatches(makeRiskGateTestMatch("CVE-hot", false, 0.97), makeRiskGateTestMatch("CVE-warm", false, 0.6))},
	}

	t.Run("disabled gates pass", func(t *testing.T) {
		assert.NoError(t, CheckRiskGates(RiskGates{}, images, false))
	})
	t.Run("counts accumulate across images", func(t *testing.T) {
		err := CheckRiskGates(RiskGates{FailOnKEV: true, EPSSThreshold: 0.5}, images, false)
		require.EqualError(t, err, "image scan result exceeds exploitability gates: 1 vulnerability match(es) listed in CISA KEV; 2 vulnerability match(es) with an EPSS score at or above 0.5")
	})
	t.Run("no breach passes", func(t *testing.T) {
		assert.NoError(t, CheckRiskGates(RiskGates{EPSSThreshold: 0.99}, images, false))
	})
}

func TestRiskGateFailure(t *testing.T) {
	assert.NoError(t, RiskGateFailure(RiskGates{FailOnKEV: true}, RiskGateResult{}))

	err := RiskGateFailure(RiskGates{FailOnKEV: true}, RiskGateResult{KEV: 2})
	require.EqualError(t, err, "image scan result exceeds exploitability gates: 2 vulnerability match(es) listed in CISA KEV")

	err = RiskGateFailure(RiskGates{EPSSThreshold: 0.25}, RiskGateResult{EPSS: 1, EPSSChecked: 3, EPSSScored: 3})
	require.EqualError(t, err, "image scan result exceeds exploitability gates: 1 vulnerability match(es) with an EPSS score at or above 0.25")

	err = RiskGateFailure(RiskGates{FailOnKEV: true}, RiskGateResult{Indeterminate: 1})
	require.EqualError(t, err, "image scan result exceeds exploitability gates: 1 vulnerability match(es) whose exploitability data could not be determined")
}

func TestHighestEPSS(t *testing.T) {
	_, ok := HighestEPSS(nil)
	assert.False(t, ok)

	score, ok := HighestEPSS([]vulnerability.EPSS{{EPSS: 0.2}, {EPSS: 0.9}, {EPSS: 0.4}})
	assert.True(t, ok)
	assert.Equal(t, 0.9, score)

	score, ok = HighestEPSS([]vulnerability.EPSS{{EPSS: 0}})
	assert.True(t, ok, "a zero score is still a score")
	assert.Equal(t, 0.0, score)
}
