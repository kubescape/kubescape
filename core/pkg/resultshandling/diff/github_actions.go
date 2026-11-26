package diff

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"
)

const (
	githubActionsMaxAnnotations       = 10
	githubActionsMaxStepSummaryBytes  = 1024*1024 - 4*1024
	githubActionsSummaryTruncatedNote = "\n\n_Summary truncated to stay within the 1 MiB GitHub Actions step summary limit._\n"
	githubActionsStepSummaryEnvVar    = "GITHUB_STEP_SUMMARY"
)

// PrintGitHubActions emits GitHub Actions ::error workflow annotations for
// new and incomparable posture regressions at or above threshold (capped at
// the 10-annotation per-step runner limit) and appends a Markdown regression
// summary to GITHUB_STEP_SUMMARY when configured.
func PrintGitHubActions(w io.Writer, cs *ChangeSet, threshold string) error {
	findings := Regressions(cs, threshold).all()
	ew := errWriter{w: w}

	limit := len(findings)
	if limit > githubActionsMaxAnnotations {
		limit = githubActionsMaxAnnotations
	}

	for _, f := range findings[:limit] {
		title := fmt.Sprintf("Kubescape %s regression: %s", f.Kind, f.Change.ControlID)
		if f.Change.Severity != "" {
			title = fmt.Sprintf("Kubescape %s regression: %s (%s)", f.Kind, f.Change.ControlID, f.Change.Severity)
		}
		msg := buildPostureAnnotationMessage(f)
		if f.Change.Path != "" {
			ew.printf("::error file=%s,title=%s::%s\n",
				escapeWorkflowProperty(f.Change.Path),
				escapeWorkflowProperty(title),
				escapeWorkflowData(msg),
			)
		} else {
			ew.printf("::error title=%s::%s\n",
				escapeWorkflowProperty(title),
				escapeWorkflowData(msg),
			)
		}
	}

	if len(findings) > githubActionsMaxAnnotations {
		ew.printf("::warning title=Kubescape Diff::Showing %d of %d regressions; see the step summary or rerun with --format markdown for the full list.\n",
			githubActionsMaxAnnotations, len(findings))
	}

	if ew.err != nil {
		return ew.err
	}

	return appendStepSummary(func() (string, error) {
		var buf bytes.Buffer
		if err := PrintMarkdown(&buf, cs, threshold); err != nil {
			return "", err
		}
		return buf.String(), nil
	})
}

// PrintVulnerabilityGitHubActions emits GitHub Actions ::error workflow
// annotations for new vulnerabilities at or above threshold (capped at the
// 10-annotation per-step runner limit) and appends a Markdown summary to
// GITHUB_STEP_SUMMARY when configured.
func PrintVulnerabilityGitHubActions(w io.Writer, cs *VulnerabilityChangeSet, threshold string) error {
	var findings []VulnerabilityChange
	if cs != nil {
		raw := newVulnerabilitiesAtOrAbove(cs, threshold)
		findings = make([]VulnerabilityChange, len(raw))
		copy(findings, raw)
		sortVulnerabilityChanges(findings)
	}

	ew := errWriter{w: w}

	limit := len(findings)
	if limit > githubActionsMaxAnnotations {
		limit = githubActionsMaxAnnotations
	}

	for _, c := range findings[:limit] {
		title := fmt.Sprintf("Kubescape new vulnerability: %s (%s)", defaultIfEmpty(c.ID, "unknown"), defaultIfEmpty(c.Severity, "Unknown"))
		fix := "none"
		if len(c.FixedIn) > 0 {
			fix = strings.Join(c.FixedIn, ", ")
		}
		msg := fmt.Sprintf("package=%s version=%s fix=%s",
			defaultIfEmpty(c.Package, "unknown"),
			defaultIfEmpty(c.Version, "unknown"),
			fix,
		)
		ew.printf("::error title=%s::%s\n",
			escapeWorkflowProperty(title),
			escapeWorkflowData(msg),
		)
	}

	if len(findings) > githubActionsMaxAnnotations {
		ew.printf("::warning title=Kubescape Diff::Showing %d of %d new vulnerabilities; see the step summary or rerun with --format markdown for the full list.\n",
			githubActionsMaxAnnotations, len(findings))
	}

	if ew.err != nil {
		return ew.err
	}

	return appendStepSummary(func() (string, error) {
		if cs == nil {
			return "", nil
		}
		var buf bytes.Buffer
		if err := PrintVulnerabilityMarkdown(&buf, cs, threshold); err != nil {
			return "", err
		}
		return buf.String(), nil
	})
}

func defaultIfEmpty(val, fallback string) string {
	if val == "" {
		return fallback
	}
	return val
}

func buildPostureAnnotationMessage(f ciFinding) string {
	parts := []string{
		fmt.Sprintf("resource=%s", defaultIfEmpty(f.Change.ResourceID, "unknown")),
		fmt.Sprintf("control=%s", defaultIfEmpty(f.Change.ControlID, "unknown")),
		fmt.Sprintf("severity=%s", defaultIfEmpty(f.Change.Severity, "Unknown")),
		fmt.Sprintf("base=%s", defaultIfEmpty(f.Change.BaseStatus, "none")),
		fmt.Sprintf("head=%s", defaultIfEmpty(f.Change.HeadStatus, "none")),
	}
	if f.Change.ControlName != "" {
		parts = append(parts, fmt.Sprintf("name=%s", f.Change.ControlName))
	}
	if f.Change.Reason != "" {
		parts = append(parts, fmt.Sprintf("reason=%s", f.Change.Reason))
	}
	return strings.Join(parts, "; ")
}

func appendStepSummary(render func() (string, error)) error {
	summaryPath := strings.TrimSpace(os.Getenv(githubActionsStepSummaryEnvVar))
	if summaryPath == "" {
		return nil
	}
	var existingSize int64
	if info, err := os.Stat(summaryPath); err == nil { // #nosec G304,G703 -- GITHUB_STEP_SUMMARY is runner-provided
		existingSize = info.Size()
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stating %s: %w", githubActionsStepSummaryEnvVar, err)
	}
	remaining := int64(githubActionsMaxStepSummaryBytes) - existingSize
	if remaining <= 0 {
		return nil
	}

	content, err := render()
	if err != nil {
		return err
	}
	if content == "" {
		return nil
	}
	if int64(len(content)) > remaining {
		noteLen := len(githubActionsSummaryTruncatedNote)
		if remaining <= int64(noteLen) {
			return nil
		}
		maxLen := int(remaining) - noteLen
		for maxLen > 0 && !utf8.RuneStart(content[maxLen]) {
			maxLen--
		}
		content = content[:maxLen] + githubActionsSummaryTruncatedNote
	}

	f, err := os.OpenFile(summaryPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304,G703 -- GITHUB_STEP_SUMMARY is runner-provided
	if err != nil {
		return fmt.Errorf("opening %s: %w", githubActionsStepSummaryEnvVar, err)
	}
	_, writeErr := io.WriteString(f, content)
	closeErr := f.Close()
	if writeErr != nil {
		return fmt.Errorf("writing %s: %w", githubActionsStepSummaryEnvVar, writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("closing %s: %w", githubActionsStepSummaryEnvVar, closeErr)
	}
	return nil
}

// stripWorkflowControls removes non-printable ASCII control characters (except tab, CR, and LF)
// and DEL to prevent workflow command truncation or terminal escape injection (CWE-150).
func stripWorkflowControls(s string) string {
	hasControl := false
	for _, r := range s {
		if (r < 0x20 && r != '\t' && r != '\n' && r != '\r') || r == 0x7f {
			hasControl = true
			break
		}
	}
	if !hasControl {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if (r < 0x20 && r != '\t' && r != '\n' && r != '\r') || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func escapeWorkflowData(s string) string {
	s = stripWorkflowControls(s)
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	return s
}

func escapeWorkflowProperty(s string) string {
	s = escapeWorkflowData(s)
	s = strings.ReplaceAll(s, ",", "%2C")
	s = strings.ReplaceAll(s, ":", "%3A")
	return s
}
