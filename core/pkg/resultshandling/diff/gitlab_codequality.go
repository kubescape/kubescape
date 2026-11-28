package diff

import (
	"fmt"
	"io"
	"strings"
)

const (
	diffCodeQualityEngine    = "kubescape"
	diffCodeQualityCategory  = "Security"
	diffCodeQualityIssueType = "issue"
)

type diffCodeQualityIssue struct {
	Type        string                  `json:"type"`
	CheckName   string                  `json:"check_name"`
	Description string                  `json:"description"`
	Content     diffCodeQualityContent  `json:"content"`
	Categories  []string                `json:"categories"`
	Severity    string                  `json:"severity"`
	Fingerprint string                  `json:"fingerprint"`
	EngineName  string                  `json:"engine_name"`
	Location    diffCodeQualityLocation `json:"location"`
}

type diffCodeQualityContent struct {
	Body string `json:"body"`
}

type diffCodeQualityLocation struct {
	Path  string               `json:"path"`
	Lines diffCodeQualityLines `json:"lines"`
}

type diffCodeQualityLines struct {
	Begin int `json:"begin"`
}

// PrintGitLabCodeQuality writes new and incomparable posture regressions as a
// GitLab Code Quality JSON report (the CodeClimate subset rendered in GitLab
// merge request widgets and diff views across all tiers). Findings without a
// repository-relative source path are skipped because GitLab Code Quality
// requires location.path to reference a repository file.
func PrintGitLabCodeQuality(w io.Writer, cs *ChangeSet, threshold string) error {
	findings := Regressions(cs, threshold).all()
	issues := make([]diffCodeQualityIssue, 0, len(findings))
	for _, f := range findings {
		c := f.Change
		repoPath, ok := normalizeRepoRelativePath(c.SourcePath)
		if !ok {
			continue
		}
		checkName := defaultIfEmpty(c.ControlID, "kubescape-diff")
		controlLabel := defaultIfEmpty(c.ControlName, checkName)
		issues = append(issues, diffCodeQualityIssue{
			Type:        diffCodeQualityIssueType,
			CheckName:   checkName,
			Description: fmt.Sprintf("%s: %s", findingTitle(f.Kind, c), controlLabel),
			Content:     diffCodeQualityContent{Body: findingDetails(c)},
			Categories:  []string{diffCodeQualityCategory},
			Severity:    gitLabCodeQualitySeverity(c.Severity),
			Fingerprint: stableFindingID(f.Kind, c),
			EngineName:  diffCodeQualityEngine,
			Location: diffCodeQualityLocation{
				Path:  repoPath,
				Lines: diffCodeQualityLines{Begin: 1},
			},
		})
	}
	return encodeJSON(w, issues)
}

func gitLabCodeQualitySeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return "critical"
	case "high":
		return "major"
	case "medium":
		return "minor"
	default:
		return "info"
	}
}
