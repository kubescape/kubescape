package ghworkflows

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// These tests guard security-insights.yml at the repository root, the OpenSSF
// Security Insights document that supply-chain consumers (the OSPS Baseline
// scanner, CLOMonitor, CNCF project reviews) read to learn how this repository
// secures itself.
//
// Nothing linked the document to reality, so it rotted for years: the
// expiration date passed in October 2024, the attested release ("1.0.0") was
// four major versions behind, two listed core maintainers had already moved
// to Emeritus in project-governance, and the contribution policy rejected
// automated pull requests while dependabot[bot] merges sat in the git
// history. Each of those was a false attestation no consumer could detect.
//
// It also stayed on schema 1.0.0 after the spec moved to v2. The OSPS Baseline
// scanner parses the file strictly, so it rejected it ("unknown field") and
// reported the repository as having no Security Insights at all. The schema is
// now checked by the security-insights action in repo-hygiene.yaml; these
// tests cover freshness, the contact lists, and that only one copy exists.
//
// The date assertions are the part review cannot catch: an insights document
// goes stale while nobody touches it, so expiry is a property of time, not of
// change. repo-hygiene.yaml therefore runs this package on a monthly schedule
// in addition to pull requests.
const (
	securityInsightsName = "security-insights.yml"

	// securityInsightsURL is the raw file on master. Other Kubescape
	// repositories inherit the project section by pointing
	// header.project-si-source at it, and that needs raw YAML, not the page.
	securityInsightsURL = "https://raw.githubusercontent.com/kubescape/kubescape/master/" + securityInsightsName

	// securityInsightsMaxReviewMonths bounds the age of last-reviewed. v2 has
	// no expiration-date; six months is the expiry window the v1 file used.
	securityInsightsMaxReviewMonths = 6

	// securityInsightsDateLayout is the only date form v2 allows.
	securityInsightsDateLayout = "2006-01-02"
)

type securityInsightsContact struct {
	Name    string `yaml:"name"`
	Primary bool   `yaml:"primary"`
	Social  string `yaml:"social"`
}

// securityInsights is the subset of the Security Insights schema these tests
// assert on. Unknown keys are tolerated on purpose, like the Dependabot
// decoder in this package: the spec carries many optional sections, and a
// strict decoder would turn adopting one into a spurious failure here.
type securityInsights struct {
	Header struct {
		SchemaVersion string `yaml:"schema-version"`
		LastUpdated   string `yaml:"last-updated"`
		LastReviewed  string `yaml:"last-reviewed"`
		URL           string `yaml:"url"`
	} `yaml:"header"`
	Project struct {
		Name           string                    `yaml:"name"`
		Administrators []securityInsightsContact `yaml:"administrators"`
	} `yaml:"project"`
	Repository struct {
		URL      string                    `yaml:"url"`
		Status   string                    `yaml:"status"`
		CoreTeam []securityInsightsContact `yaml:"core-team"`
		Security struct {
			Assessments struct {
				Self securityInsightsAssessment `yaml:"self"`
			} `yaml:"assessments"`
		} `yaml:"security"`
	} `yaml:"repository"`
}

type securityInsightsAssessment struct {
	Evidence string `yaml:"evidence"`
	Date     string `yaml:"date"`
	Comment  string `yaml:"comment"`
}

const (
	securityAssessmentPath = "docs/security/self-assessment.md"
	securityAssessmentURL  = "https://github.com/kubescape/kubescape/blob/master/" + securityAssessmentPath
	securityAssessmentLink = "[Security Self-Assessment](security/self-assessment.md)"
)

// validateSecurityAssessment checks that the Security Insights evidence points
// to the intended assessment and that the document is present and indexed.
func validateSecurityAssessment(root string, assessment securityInsightsAssessment) error {
	if assessment.Evidence != securityAssessmentURL {
		return fmt.Errorf("repository.security.assessments.self.evidence must be %q, got %q", securityAssessmentURL, assessment.Evidence)
	}

	assessmentPath := filepath.Join(root, filepath.FromSlash(securityAssessmentPath))
	content, err := os.ReadFile(assessmentPath)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", securityAssessmentPath, err)
	}
	if strings.TrimSpace(string(content)) == "" {
		return fmt.Errorf("%s must not be empty", securityAssessmentPath)
	}

	indexPath := filepath.Join(root, "docs", "README.md")
	index, err := os.ReadFile(indexPath)
	if err != nil {
		return fmt.Errorf("cannot read docs/README.md: %w", err)
	}
	if !strings.Contains(string(index), securityAssessmentLink) {
		return fmt.Errorf("docs/README.md must contain %s", securityAssessmentLink)
	}
	return nil
}

func securityAssessmentPathIsWatched(patterns []string, path string) bool {
	for _, pattern := range patterns {
		if pathCoveredBy(pattern, filepath.ToSlash(path)) {
			return true
		}
	}
	return false
}

func writeSecurityAssessmentFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "docs", "security"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, filepath.FromSlash(securityAssessmentPath)), []byte("# Security assessment\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "docs", "README.md"), []byte(securityAssessmentLink+"\n"), 0o600))
	return root
}

func TestSecurityAssessmentEvidenceIsValid(t *testing.T) {
	insights := loadSecurityInsights(t)
	require.NoError(t, validateSecurityAssessment(repoRoot(t), insights.Repository.Security.Assessments.Self))
}

func TestValidateSecurityAssessmentRejectsRegressions(t *testing.T) {
	tests := []struct {
		name       string
		evidence   string
		assessment string
		index      string
		wantError  string
	}{
		{name: "incorrect evidence", evidence: "https://example.com/wrong.md", assessment: "# Assessment", index: securityAssessmentLink, wantError: "evidence must be"},
		{name: "missing file", evidence: securityAssessmentURL, assessment: "missing", index: securityAssessmentLink, wantError: "cannot read " + securityAssessmentPath},
		{name: "empty file", evidence: securityAssessmentURL, assessment: "", index: securityAssessmentLink, wantError: securityAssessmentPath + " must not be empty"},
		{name: "whitespace-only file", evidence: securityAssessmentURL, assessment: " \n\t", index: securityAssessmentLink, wantError: securityAssessmentPath + " must not be empty"},
		{name: "missing index link", evidence: securityAssessmentURL, assessment: "# Assessment", index: "# Documentation", wantError: "docs/README.md must contain"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := writeSecurityAssessmentFixture(t)
			assessmentPath := filepath.Join(root, filepath.FromSlash(securityAssessmentPath))
			if tt.assessment == "missing" {
				require.NoError(t, os.Remove(assessmentPath))
			} else {
				require.NoError(t, os.WriteFile(assessmentPath, []byte(tt.assessment), 0o600))
			}
			require.NoError(t, os.WriteFile(filepath.Join(root, "docs", "README.md"), []byte(tt.index), 0o600))

			err := validateSecurityAssessment(root, securityInsightsAssessment{Evidence: tt.evidence})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantError)
		})
	}
}

func TestRepoHygieneWatchesSecurityAssessmentDocs(t *testing.T) {
	var workflow hygieneWorkflow
	loadWorkflow(t, hygieneWorkflowName, &workflow)
	paths := workflow.On.PullRequest.Paths

	for _, path := range []string{"docs/README.md", securityAssessmentPath} {
		assert.Truef(t, securityAssessmentPathIsWatched(paths, path),
			"%s must trigger %s so docs-only changes run this validation", path, hygieneWorkflowName)
	}

	for _, removed := range []string{"docs/README.md", securityAssessmentPath} {
		t.Run("detects removal of "+removed, func(t *testing.T) {
			filtered := make([]string, 0, len(paths))
			for _, path := range paths {
				if path != removed {
					filtered = append(filtered, path)
				}
			}
			assert.Falsef(t, securityAssessmentPathIsWatched(filtered, removed),
				"removing %s from the workflow paths must be detected", removed)
		})
	}
}

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

func parseSecurityInsightsDate(t *testing.T, field, value string) time.Time {
	t.Helper()

	parsed, err := time.Parse(securityInsightsDateLayout, value)
	if err != nil {
		t.Fatalf("%s in %s must be a date (YYYY-MM-DD), got %q", field, securityInsightsName, value)
	}
	return parsed
}

// isFutureDate reports whether a date lies in the future.
//
// A date may legitimately name tomorrow's UTC date: it is written by a
// contributor in their local calendar, and every inhabited timezone is ahead
// of UTC by less than a day. The check exists to catch documents that typo a
// far-off year, so one day of skew is tolerated and anything beyond it fails.
func isFutureDate(parsed time.Time) bool {
	// ISO dates order identically as strings, so this is a calendar-day
	// comparison against the latest local date any timezone can be on.
	latest := time.Now().UTC().AddDate(0, 0, 1).Format(securityInsightsDateLayout)
	return parsed.Format(securityInsightsDateLayout) > latest
}

// schemaV2Re matches the schema versions the struct above can read. v1 to v2
// changed the layout of the whole document, so another major version should
// fail here instead of being half-read.
var schemaV2Re = regexp.MustCompile(`^2\.[0-9]+\.[0-9]+$`)

// TestSecurityInsightsHeaderIsPopulated keeps the fields consumers key off
// present and pointing at this repository.
func TestSecurityInsightsHeaderIsPopulated(t *testing.T) {
	insights := loadSecurityInsights(t)

	assert.Regexp(t, schemaV2Re, insights.Header.SchemaVersion,
		"schema-version must be a 2.x.y release of the Security Insights spec")
	assert.Equal(t, securityInsightsURL, insights.Header.URL,
		"header.url must be the raw file on master; other repositories inherit the project section from there")
	assert.NotEmpty(t, insights.Header.LastUpdated, "last-updated is required")
	assert.NotEmpty(t, insights.Header.LastReviewed, "last-reviewed is required")
	assert.NotEmpty(t, insights.Project.Name, "project.name is required")
	assert.Equal(t, "https://github.com/kubescape/kubescape", insights.Repository.URL)
	assert.Equal(t, "active", insights.Repository.Status)
}

// TestSecurityInsightsIsFresh replaces the v1 expiry check, which was added
// after the expiration date had passed almost two years earlier and nothing
// failed. v2 has no expiration-date, so the check moves to last-reviewed.
func TestSecurityInsightsIsFresh(t *testing.T) {
	insights := loadSecurityInsights(t)

	require.NotEmpty(t, insights.Header.LastReviewed, "last-reviewed is required")

	// Strict comparison: for an expiry check, failing near the boundary is the
	// safe direction.
	lastReviewed := parseSecurityInsightsDate(t, "last-reviewed", insights.Header.LastReviewed)
	reviewBy := lastReviewed.AddDate(0, securityInsightsMaxReviewMonths, 0)
	assert.Truef(t, reviewBy.After(time.Now().UTC()),
		"%s was last reviewed on %s and was due for review by %s; check it against the repository and update last-reviewed",
		securityInsightsName, insights.Header.LastReviewed, reviewBy.Format(securityInsightsDateLayout))
}

// TestSecurityInsightsDatesAreCoherent keeps the header dates out of the
// future.
func TestSecurityInsightsDatesAreCoherent(t *testing.T) {
	insights := loadSecurityInsights(t)

	for field, value := range map[string]string{
		"last-updated":  insights.Header.LastUpdated,
		"last-reviewed": insights.Header.LastReviewed,
	} {
		t.Run(field, func(t *testing.T) {
			require.NotEmptyf(t, value, "%s is required", field)
			assert.Falsef(t, isFutureDate(parseSecurityInsightsDate(t, field, value)),
				"%s %s is in the future", field, value)
		})
	}
}

// TestSecurityInsightsIsTheOnlyCopy fails on a second insights file in the
// root or .github. The OSPS Baseline scanner matches the name
// case-insensitively and takes the first hit in GitHub's byte-ordered listing,
// so an old SECURITY-INSIGHTS.yml next to this file would be read instead of
// it. CLOMonitor picks between copies in a different order, so one copy is
// the only safe number.
func TestSecurityInsightsIsTheOnlyCopy(t *testing.T) {
	root := repoRoot(t)

	for _, dir := range []string{root, filepath.Join(root, ".github")} {
		entries, err := os.ReadDir(dir)
		require.NoErrorf(t, err, "cannot list %s", dir)

		for _, entry := range entries {
			if !strings.EqualFold(entry.Name(), securityInsightsName) {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			assert.Equalf(t, securityInsightsPath(t), path,
				"%s is a second copy of %s; keep only the one at the repository root",
				path, securityInsightsName)
		}
	}
}

// githubProfileRe matches the `social` value used for every contact, so each
// one resolves to a GitHub account.
var githubProfileRe = regexp.MustCompile(`^https://github\.com/[A-Za-z0-9][A-Za-z0-9-]*$`)

// TestSecurityInsightsContactsAreResolvable keeps both contact lists
// well-formed. The spec says only one contact should be marked primary; this
// also requires one, so each list has a first point of contact.
func TestSecurityInsightsContactsAreResolvable(t *testing.T) {
	insights := loadSecurityInsights(t)

	for list, contacts := range map[string][]securityInsightsContact{
		"project.administrators": insights.Project.Administrators,
		"repository.core-team":   insights.Repository.CoreTeam,
	} {
		t.Run(list, func(t *testing.T) {
			require.NotEmptyf(t, contacts,
				"%s is required; a security document with no accountable humans attests nothing", list)

			primaries := 0
			for _, contact := range contacts {
				assert.NotEmptyf(t, contact.Name, "every %s entry needs a name", list)
				assert.Regexpf(t, githubProfileRe, contact.Social,
					"%s entry %q must set social to a GitHub profile URL", list, contact.Name)
				if contact.Primary {
					primaries++
				}
			}
			assert.Equalf(t, 1, primaries, "%s must mark exactly one contact as primary", list)
		})
	}
}
