package predict

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/kubescape/kubescape/v4/core/pkg/pss"
)

const outputDirPerm = 0o750

// writeOutput dispatches to the appropriate formatter based on format string.
func writeOutput(result pss.NamespaceResult, format, outputFile string, verbose bool) (retErr error) {
	var w io.Writer
	if outputFile != "" {
		if dir, _ := filepath.Split(outputFile); dir != "" {
			if err := os.MkdirAll(dir, outputDirPerm); err != nil {
				return fmt.Errorf("cannot create output directory %q: %w", dir, err)
			}
		}

		f, err := os.OpenFile(outputFile, os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			return fmt.Errorf("cannot create output file %q: %w", outputFile, err)
		}
		info, err := f.Stat()
		if err != nil {
			_ = f.Close()
			return fmt.Errorf("cannot stat output file %q: %w", outputFile, err)
		}
		if info.Mode().IsRegular() {
			if err := f.Chmod(0o600); err != nil {
				_ = f.Close()
				return fmt.Errorf("cannot set permissions on output file %q: %w", outputFile, err)
			}
			if err := f.Truncate(0); err != nil {
				_ = f.Close()
				return fmt.Errorf("cannot truncate output file %q: %w", outputFile, err)
			}
		}
		defer func() {
			if cerr := f.Close(); cerr != nil && retErr == nil {
				retErr = cerr
			}
		}()
		w = f
	} else {
		w = os.Stdout
	}

	switch format {
	case "json":
		return writeJSON(w, result)
	case "table":
		return writeTable(w, result, verbose)
	case "sarif":
		return writeSARIF(w, result)
	case "junit":
		return writeJUnit(w, result)
	case "pretty-printer":
		return writePretty(w, result, verbose)
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

// --- JSON formatter ---

type jsonOutput struct {
	Namespace       string         `json:"namespace"`
	TargetLevel     string         `json:"target_level"`
	Summary         jsonSummary    `json:"summary"`
	FailingWorkload []jsonWorkload `json:"failing_workloads"`
	DecodeWarnings  []string       `json:"decode_warnings,omitempty"`
}

type jsonSummary struct {
	TotalWorkloads         int    `json:"total_workloads"`
	Passing                int    `json:"passing"`
	Failing                int    `json:"failing"`
	CurrentEffective       string `json:"current_effective_level"`
	Unevaluated            int    `json:"unevaluated,omitempty"`
	EffectiveLevelComplete *bool  `json:"current_effective_level_complete,omitempty"`
}

type jsonWorkload struct {
	Kind       string          `json:"kind"`
	Name       string          `json:"name"`
	Violations []jsonViolation `json:"violations"`
	PassesAt   string          `json:"passes_at"`
}

type jsonViolation struct {
	Check       string `json:"check"`
	Container   string `json:"container"`
	Level       string `json:"level"`
	Description string `json:"description"`
}

// writeJSON formats the prediction results as JSON.
func writeJSON(w io.Writer, result pss.NamespaceResult) error {
	out := jsonOutput{
		Namespace:   result.Namespace,
		TargetLevel: result.TargetLevel.String(),
		Summary: jsonSummary{
			TotalWorkloads:   result.TotalWorkloads,
			Passing:          result.PassingWorkloads,
			Failing:          result.FailingWorkloads,
			CurrentEffective: result.CurrentEffectiveLevel.String(),
		},
		FailingWorkload: make([]jsonWorkload, 0),
		DecodeWarnings:  result.DecodeWarnings,
	}

	if result.UnevaluatedWorkloads > 0 {
		out.Summary.Unevaluated = result.UnevaluatedWorkloads
		complete := false
		out.Summary.EffectiveLevelComplete = &complete
	}

	for _, r := range result.FailingResults() {
		jw := jsonWorkload{
			Kind:       r.Kind,
			Name:       r.Name,
			Violations: make([]jsonViolation, 0, len(r.Violations)),
			PassesAt:   r.PassesAt.String(),
		}
		for _, v := range r.Violations {
			jw.Violations = append(jw.Violations, jsonViolation{
				Check:       v.Check,
				Container:   v.Container,
				Level:       v.Level.String(),
				Description: v.Description,
			})
		}
		out.FailingWorkload = append(out.FailingWorkload, jw)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// writeTable formats the prediction results as a summary table.
func writeTable(w io.Writer, result pss.NamespaceResult, verbose bool) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "KIND\tNAME\tPASSES_AT\tVIOLATIONS"); err != nil {
		return err
	}

	for _, r := range result.Results {
		if len(r.Violations) == 0 && !verbose {
			continue
		}
		violations := "-"
		if len(r.Violations) > 0 {
			var parts []string
			for _, v := range r.Violations {
				label := v.Check
				if v.Container != "" {
					label += ":" + v.Container
				}
				parts = append(parts, label)
			}
			violations = strings.Join(parts, ", ")
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.Kind, r.Name, r.PassesAt.String(), violations); err != nil {
			return err
		}
	}

	if err := tw.Flush(); err != nil {
		return err
	}

	// Summary line
	if _, err := fmt.Fprintf(w, "\nSummary: %d/%d workloads pass at %s (current effective level: %s)\n",
		result.PassingWorkloads, result.TotalWorkloads,
		result.TargetLevel.String(), result.CurrentEffectiveLevel.String()); err != nil {
		return err
	}

	return nil
}

// --- Pretty printer ---

type errorWriter struct {
	w   io.Writer
	err error
}

func (ew *errorWriter) printf(format string, a ...any) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintf(ew.w, format, a...)
}

func (ew *errorWriter) println(a ...any) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintln(ew.w, a...)
}

// writePretty formats the prediction results in a human-readable format.
func writePretty(w io.Writer, result pss.NamespaceResult, verbose bool) error {
	ew := &errorWriter{w: w}
	ns := result.Namespace
	if ns == "" {
		ns = "(local files)"
	}

	ew.printf("\n")
	ew.printf("PSS Compliance Prediction\n")
	ew.printf("  Namespace:    %s\n", ns)
	ew.printf("  Target Level: %s\n", result.TargetLevel.String())
	ew.printf("\n")

	if result.TotalWorkloads == 0 {
		ew.println("  No workloads found.")
		return ew.err
	}

	// Print failing workloads
	failing := result.FailingResults()
	if len(failing) > 0 {
		ew.printf("Failing Workloads (%d):\n\n", len(failing))
		for _, r := range failing {
			ew.printf("  ✗ %s/%s  (passes at: %s)\n", r.Kind, r.Name, r.PassesAt.String())
			for _, v := range r.Violations {
				container := ""
				if v.Container != "" {
					container = fmt.Sprintf(" [%s]", v.Container)
				}
				ew.printf("    • %s%s (%s): %s\n", v.Check, container, v.Level.String(), v.Description)
			}
			ew.println()
		}
	}

	// Print passing workloads if verbose
	if verbose {
		passing := result.PassingResults()
		if len(passing) > 0 {
			ew.printf("Passing Workloads (%d):\n\n", len(passing))
			for _, r := range passing {
				ew.printf("  ✓ %s/%s\n", r.Kind, r.Name)
			}
			ew.println()
		}
	}

	// Decode warnings
	if len(result.DecodeWarnings) > 0 {
		ew.printf("Warnings (%d unevaluated):\n", result.UnevaluatedWorkloads)
		for _, warning := range result.DecodeWarnings {
			ew.printf("  ⚠ %s\n", warning)
		}
		ew.println()
	}

	// Summary
	ew.printf("Summary: %d/%d workloads pass at %s\n",
		result.PassingWorkloads, result.TotalWorkloads, result.TargetLevel.String())
	ew.printf("Current effective namespace level: %s\n", result.CurrentEffectiveLevel.String())
	ew.println()

	return ew.err
}

// --- SARIF formatter ---

type sarifReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string             `json:"id"`
	ShortDescription sarifMessage       `json:"shortDescription"`
	HelpURI          string             `json:"helpUri"`
	DefaultConfig    sarifDefaultConfig `json:"defaultConfiguration"`
}

type sarifDefaultConfig struct {
	Level string `json:"level"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations"`
}

type sarifLogicalLocation struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

// writeSARIF formats the prediction results as a SARIF report.
func writeSARIF(w io.Writer, result pss.NamespaceResult) error {
	// Collect unique rule IDs
	ruleMap := make(map[string]pss.Level)
	for _, r := range result.FailingResults() {
		for _, v := range r.Violations {
			ruleID := "PSS/" + v.Check
			if existing, ok := ruleMap[ruleID]; !ok || v.Level < existing {
				ruleMap[ruleID] = v.Level
			}
		}
	}

	rules := make([]sarifRule, 0)
	for ruleID, level := range ruleMap {
		sarifLevel := "warning"
		if level <= pss.Baseline {
			sarifLevel = "error"
		}
		rules = append(rules, sarifRule{
			ID:               ruleID,
			ShortDescription: sarifMessage{Text: fmt.Sprintf("PSS %s check", strings.TrimPrefix(ruleID, "PSS/"))},
			HelpURI:          "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
			DefaultConfig:    sarifDefaultConfig{Level: sarifLevel},
		})
	}

	results := make([]sarifResult, 0)
	for _, r := range result.FailingResults() {
		for _, v := range r.Violations {
			ruleID := "PSS/" + v.Check
			level := "warning"
			if v.Level <= pss.Baseline {
				level = "error"
			}
			fqn := fmt.Sprintf("%s/%s", r.Kind, r.Name)
			if result.Namespace != "" {
				fqn = fmt.Sprintf("%s/%s/%s", result.Namespace, r.Kind, r.Name)
			}
			if v.Container != "" {
				fqn += "/" + v.Container
			}
			results = append(results, sarifResult{
				RuleID:  ruleID,
				Level:   level,
				Message: sarifMessage{Text: v.Description},
				Locations: []sarifLocation{{
					LogicalLocations: []sarifLogicalLocation{{
						Name:               r.Name,
						FullyQualifiedName: fqn,
						Kind:               r.Kind,
					}},
				}},
			})
		}
	}

	report := sarifReport{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "kubescape",
					InformationURI: "https://kubescape.io",
					Version:        "1.0.0",
					Rules:          rules,
				},
			},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// --- JUnit formatter ---

type junitTestSuites struct {
	XMLName   xml.Name         `xml:"testsuites"`
	TestSuite []junitTestSuite `xml:"testsuite"`
}

type junitTestSuite struct {
	XMLName   xml.Name        `xml:"testsuite"`
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Skipped   int             `xml:"skipped,attr"`
	Timestamp string          `xml:"timestamp,attr"`
	TestCases []junitTestCase `xml:"testcase"`
}

type junitTestCase struct {
	XMLName   xml.Name      `xml:"testcase"`
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
	Skipped   *junitSkipped `xml:"skipped,omitempty"`
}

type junitSkipped struct {
	Message string `xml:"message,attr"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Text    string `xml:",chardata"`
}

// writeJUnit formats the prediction results as a JUnit XML report.
func writeJUnit(w io.Writer, result pss.NamespaceResult) error {
	ns := result.Namespace
	if ns == "" {
		ns = "local"
	}
	suiteName := fmt.Sprintf("PSS Compliance: %s @ %s", ns, result.TargetLevel.String())

	var testCases []junitTestCase
	for _, r := range result.Results {
		tc := junitTestCase{
			Name:      fmt.Sprintf("%s/%s", r.Kind, r.Name),
			ClassName: fmt.Sprintf("pss.%s.%s", ns, r.Kind),
		}
		if len(r.Violations) > 0 {
			var lines []string
			for _, v := range r.Violations {
				line := fmt.Sprintf("[%s] %s", v.Check, v.Description)
				if v.Container != "" {
					line = fmt.Sprintf("[%s] container=%s: %s", v.Check, v.Container, v.Description)
				}
				lines = append(lines, line)
			}
			tc.Failure = &junitFailure{
				Message: fmt.Sprintf("%d PSS violation(s) at %s; passes at %s",
					len(r.Violations), result.TargetLevel.String(), r.PassesAt.String()),
				Type: "PSS Violation",
				Text: strings.Join(lines, "\n"),
			}
		}
		testCases = append(testCases, tc)
	}

	for _, warning := range result.DecodeWarnings {
		testCases = append(testCases, junitTestCase{
			Name:      warning,
			ClassName: fmt.Sprintf("pss.%s.unevaluated", ns),
			Skipped:   &junitSkipped{Message: warning},
		})
	}

	suites := junitTestSuites{
		TestSuite: []junitTestSuite{{
			Name:      suiteName,
			Tests:     result.TotalWorkloads,
			Failures:  result.FailingWorkloads,
			Skipped:   result.UnevaluatedWorkloads,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			TestCases: testCases,
		}},
	}

	if _, err := fmt.Fprint(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(suites); err != nil {
		return err
	}
	_, err := fmt.Fprintln(w)
	return err
}
