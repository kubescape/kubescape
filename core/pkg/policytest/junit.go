package policytest

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"time"
)

// junitReportName is the name of the <testsuites> root element. CI systems
// show it as the title of the report.
const junitReportName = "kubescape policy test"

type junitTestSuites struct {
	XMLName  xml.Name         `xml:"testsuites"`
	Name     string           `xml:"name,attr"`
	Tests    int              `xml:"tests,attr"`
	Failures int              `xml:"failures,attr"`
	Errors   int              `xml:"errors,attr"`
	Time     string           `xml:"time,attr"`
	Suites   []junitTestSuite `xml:"testsuite"`
}

type junitTestSuite struct {
	Name     string          `xml:"name,attr"`
	Tests    int             `xml:"tests,attr"`
	Failures int             `xml:"failures,attr"`
	Errors   int             `xml:"errors,attr"`
	Time     string          `xml:"time,attr"`
	Cases    []junitTestCase `xml:"testcase"`
}

type junitTestCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Time      string        `xml:"time,attr"`
	Failure   *junitProblem `xml:"failure,omitempty"`
	Error     *junitProblem `xml:"error,omitempty"`
}

// junitProblem is the body of a <failure> or <error> element.
type junitProblem struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Text    string `xml:",chardata"`
}

// JUnitReport renders results as a JUnit XML report, the format CI systems
// such as GitLab, Jenkins and Azure Pipelines read test results from.
//
// Each rule becomes a <testsuite> and each of its cases a <testcase> named
// after the case, with the rule as its classname, so the report names a case
// the way policy test prints it. A case whose output differs from its
// expected.json is a <failure> carrying the diff; a case that could not be
// loaded or evaluated is an <error>, the same distinction CaseResult makes
// between Diff and Err. Suites appear in the order their rules first appear in
// results, and a rule without results has no suite.
func JUnitReport(results []CaseResult) ([]byte, error) {
	report := junitTestSuites{Name: junitReportName}
	suiteIndex := map[string]int{}
	// suiteDurations[i] is the summed time of report.Suites[i]'s cases.
	var suiteDurations []time.Duration
	var total time.Duration

	for _, result := range results {
		i, ok := suiteIndex[result.RuleName]
		if !ok {
			i = len(report.Suites)
			suiteIndex[result.RuleName] = i
			report.Suites = append(report.Suites, junitTestSuite{Name: result.RuleName})
			suiteDurations = append(suiteDurations, 0)
		}
		suite := &report.Suites[i]

		testCase := junitTestCase{
			Name:      result.CaseName,
			ClassName: result.RuleName,
			Time:      junitSeconds(result.Duration),
		}
		switch {
		case result.Err != nil:
			testCase.Error = &junitProblem{
				Message: result.Err.Error(),
				Type:    "error",
				Text:    result.Err.Error(),
			}
			suite.Errors++
			report.Errors++
		case !result.Passed:
			testCase.Failure = &junitProblem{
				Message: "rule output does not match " + expectedFileName,
				Type:    "mismatch",
				Text:    result.Diff,
			}
			suite.Failures++
			report.Failures++
		}

		suite.Cases = append(suite.Cases, testCase)
		suite.Tests++
		suiteDurations[i] += result.Duration
		report.Tests++
		total += result.Duration
	}

	for i := range report.Suites {
		report.Suites[i].Time = junitSeconds(suiteDurations[i])
	}
	report.Time = junitSeconds(total)

	var buf bytes.Buffer
	buf.WriteString(xml.Header)
	enc := xml.NewEncoder(&buf)
	enc.Indent("", "  ")
	if err := enc.Encode(report); err != nil {
		return nil, fmt.Errorf("encode JUnit report: %w", err)
	}
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}

// junitSeconds formats d as the decimal seconds JUnit's time attributes hold.
func junitSeconds(d time.Duration) string {
	return fmt.Sprintf("%.3f", d.Seconds())
}
