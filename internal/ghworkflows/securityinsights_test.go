package ghworkflows

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// These tests guard SECURITY-INSIGHTS.yml at the repository root, the OpenSSF
// Security Insights document that supply-chain consumers (OpenSSF Scorecard,
// CNCF project reviews) read to learn how this repository secures itself.
//
// Nothing linked the document to reality, so it rotted for years: the
// expiration date passed in October 2024, the attested release ("1.0.0") was
// four major versions behind, two listed core maintainers had already moved
// to Emeritus in project-governance, and the contribution policy rejected
// automated pull requests while dependabot[bot] merges sat in the git
// history. Each of those was a false attestation no consumer could detect.
//
// The date assertions are the part review cannot catch: an insights document
// goes stale while nobody touches it, so expiry is a property of time, not of
// change. repo-hygiene.yaml therefore runs this package on a monthly schedule
// in addition to pull requests.
const securityInsightsName = "SECURITY-INSIGHTS.yml"

// securityInsights is the subset of the Security Insights schema these tests
// assert on. Unknown keys are tolerated on purpose, like the Dependabot
// decoder in this package: the spec carries many optional sections, and a
// strict decoder would turn adopting one into a spurious failure here.
type securityInsights struct {
	Header struct {
		SchemaVersion  string `yaml:"schema-version"`
		LastUpdated    string `yaml:"last-updated"`
		ExpirationDate string `yaml:"expiration-date"`
		ProjectURL     string `yaml:"project-url"`
		ProjectRelease string `yaml:"project-release"`
	} `yaml:"header"`
	ProjectLifecycle struct {
		Status          string   `yaml:"status"`
		CoreMaintainers []string `yaml:"core-maintainers"`
	} `yaml:"project-lifecycle"`
}

// securityInsightsDateLayouts are the date forms the spec permits: a calendar
// date, or a full RFC3339 timestamp.
var securityInsightsDateLayouts = []string{time.RFC3339, "2006-01-02"}

func securityInsightsPath(t *testing.T) string {
	t.Helper()

	return filepath.Join(repoRoot(t), securityInsightsName)
}

func loadSecurityInsights(t *testing.T) securityInsights {
	t.Helper()

	content, err := os.ReadFile(securityInsightsPath(t))
	require.NoErrorf(t, err, "cannot read %s", securityInsightsName)

	var insights securityInsights
	require.NoErrorf(t, yaml.Unmarshal(content, &insights),
		"%s is not valid YAML; supply-chain consumers read this file, and a parse error invalidates every attestation in it",
		securityInsightsName)

	return insights
}

// parseSecurityInsightsDate accepts both spec-permitted date forms and fails
// listing the layouts it tried. It also reports whether the value carried
// day granularity, because a date-only value means "sometime during that
// day", not midnight UTC: comparing it to the instant clock would flag every
// same-day update as future-dated while UTC is still on the previous day.
func parseSecurityInsightsDate(t *testing.T, field, value string) (time.Time, bool) {
	t.Helper()

	for _, layout := range securityInsightsDateLayouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, layout == securityInsightsDateLayouts[1]
		}
	}

	t.Fatalf("%s in %s must be a date (YYYY-MM-DD) or an RFC3339 timestamp, got %q",
		field, securityInsightsName, value)
	return time.Time{}, false
}

// isFutureReference reports whether a parsed date reference lies in the
// future, at the granularity the source value carried.
//
// A date-only value may legitimately name tomorrow's UTC date: it is written
// by a contributor in their local calendar, and every inhabited timezone is
// ahead of UTC by less than a day. The check exists to catch documents that
// sit years in the past or typo a far-off year, so one day of skew is
// tolerated and anything beyond it fails.
func isFutureReference(parsed time.Time, dateOnly bool) bool {
	now := time.Now().UTC()
	if dateOnly {
		// ISO dates order identically as strings, so this is a calendar-day
		// comparison against the latest local date any timezone can be on.
		return parsed.Format("2006-01-02") > now.AddDate(0, 0, 1).Format("2006-01-02")
	}
	return parsed.After(now)
}

// TestSecurityInsightsHeaderIsPopulated keeps the fields consumers key off
// present and non-empty; the document named release "1.0.0" for years after
// the project had moved on to v4.
func TestSecurityInsightsHeaderIsPopulated(t *testing.T) {
	insights := loadSecurityInsights(t)

	assert.NotEmpty(t, insights.Header.SchemaVersion, "schema-version is required")
	assert.NotEmpty(t, insights.Header.ProjectURL, "project-url is required")
	assert.NotEmptyf(t, insights.Header.ProjectRelease,
		"project-release is required; an insights document that names no release describes no release")
	assert.Equal(t, "active", insights.ProjectLifecycle.Status)
}

// TestSecurityInsightsIsNotExpired is the direct regression test for the
// expired document: the expiration date had passed almost two years earlier
// and nothing failed, because nothing was checking.
func TestSecurityInsightsIsNotExpired(t *testing.T) {
	insights := loadSecurityInsights(t)

	require.NotEmpty(t, insights.Header.ExpirationDate, "expiration-date is required")

	// Strict instant comparison, even for date-only values: for an expiry
	// check, failing near the boundary is the safe direction.
	expiration, _ := parseSecurityInsightsDate(t, "expiration-date", insights.Header.ExpirationDate)
	assert.Truef(t, expiration.After(time.Now().UTC()),
		"%s expired on %s; an expired document attests nothing and must be reviewed and refreshed",
		securityInsightsName, expiration.Format(time.RFC3339))
}

// TestSecurityInsightsDatesAreCoherent keeps the header internally consistent:
// no future-dated updates, and no document that expires before it was written.
func TestSecurityInsightsDatesAreCoherent(t *testing.T) {
	insights := loadSecurityInsights(t)

	require.NotEmpty(t, insights.Header.LastUpdated, "last-updated is required")

	lastUpdated, dateOnly := parseSecurityInsightsDate(t, "last-updated", insights.Header.LastUpdated)
	assert.Falsef(t, isFutureReference(lastUpdated, dateOnly),
		"last-updated %s is in the future", insights.Header.LastUpdated)

	if insights.Header.ExpirationDate != "" {
		expiration, _ := parseSecurityInsightsDate(t, "expiration-date", insights.Header.ExpirationDate)
		assert.Truef(t, expiration.After(lastUpdated),
			"expiration-date %s is not after last-updated %s",
			insights.Header.ExpirationDate, insights.Header.LastUpdated)
	}
}

// coreMaintainerRe matches the `github:<handle>` form the document uses for
// every core-maintainer entry.
var coreMaintainerRe = regexp.MustCompile(`^github:[A-Za-z0-9][A-Za-z0-9-]*$`)

// TestSecurityInsightsListsCoreMaintainers keeps the maintainer entries
// well-formed and resolvable: the list had grown two Emeritus maintainers
// because retirements recorded in project-governance never propagated here.
func TestSecurityInsightsListsCoreMaintainers(t *testing.T) {
	insights := loadSecurityInsights(t)

	require.NotEmpty(t, insights.ProjectLifecycle.CoreMaintainers,
		"core-maintainers is required; a security document with no accountable humans attests nothing")

	for _, maintainer := range insights.ProjectLifecycle.CoreMaintainers {
		t.Run(maintainer, func(t *testing.T) {
			assert.Regexp(t, coreMaintainerRe, maintainer,
				"core-maintainer entries must be `github:<handle>` so consumers can resolve them")
		})
	}
}
