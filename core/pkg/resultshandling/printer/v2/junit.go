package printer

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/shared"
)

const (
	junitOutputFile = "report"
	junitOutputExt  = ".xml"
)

var _ printer.IPrinter = &JunitPrinter{}

type JunitPrinter struct {
	writer  *os.File
	verbose bool
}

// https://llg.cubic.org/docs/junit/

type JUnitXML struct {
	TestSuites JUnitTestSuites `xml:"testsuites"`
}

// JUnitTestSuites represents the test summary
type JUnitTestSuites struct {
	XMLName  xml.Name         `xml:"testsuites"`
	Suites   []JUnitTestSuite `xml:"testsuite"`              // list of controls
	Errors   int              `xml:"errors,attr"`            // total number of tests with error result from all testsuites
	Failures int              `xml:"failures,attr"`          // total number of failed tests from all testsuites
	Tests    int              `xml:"tests,attr"`             // total number of tests from all testsuites. Some software may expect to only see the number of successful tests from all testsuites though
	Time     string           `xml:"time,attr,omitempty"`    // time in seconds to execute all test suites
	Name     string           `xml:"name,attr,omitempty"`    // ? Add framework names ?
}

// JUnitTestSuite represents a single control
type JUnitTestSuite struct {
	XMLName    xml.Name        `xml:"testsuite"`
	Tests      int             `xml:"tests,attr"`                // total number of tests from this testsuite. Some software may expect to only see the number of successful tests though
	Name       string          `xml:"name,attr"`                 // Full (class) name of the test for non-aggregated testsuite documents. Class name without the package for aggregated testsuites documents. Required
	Errors     int             `xml:"errors,attr"`               // The total number of tests in the suite that errors
	Failures   int             `xml:"failures,attr"`             // The total number of tests in the suite that failed
	Hostname   string          `xml:"hostname,attr,omitempty"`   // Host on which the tests were executed ? cluster name ?
	ID         int             `xml:"id,attr"`                   // Starts at 0 for the first testsuite and is incremented by 1 for each following testsuite
	Skipped    int             `xml:"skipped,attr"`              // The total number of skipped tests
	Time       string          `xml:"time,attr,omitempty"`       // Time taken (in seconds) to execute the tests in the suite
	Timestamp  string          `xml:"timestamp,attr,omitempty"`  // when the test was executed in ISO 8601 format (2014-01-21T16:17:18)
	Properties []JUnitProperty `xml:"properties>property,omitempty"`
	TestCases  []JUnitTestCase `xml:"testcase"`
}

// JUnitTestCase represents a single resource
type JUnitTestCase struct {
	XMLName     xml.Name          `xml:"testcase"`
	Classname   string            `xml:"classname,attr"`      // Full class name for the class the test method is in. required
	Name        string            `xml:"name,attr"`           // Name of the test method, required
	Time        string            `xml:"time,attr,omitempty"` // Time taken (in seconds) to execute the test. optional
	SkipMessage *JUnitSkipMessage `xml:"skipped,omitempty"`
	Failure     *JUnitFailure     `xml:"failure,omitempty"`
}

// JUnitSkipMessage contains the reason why a testcase was skipped.
type JUnitSkipMessage struct {
	Message string `xml:"message,attr"`
}

// JUnitProperty represents a key/value pair used to define properties.
type JUnitProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

// JUnitFailure contains data related to a failed test.
type JUnitFailure struct {
	Message  string `xml:"message,attr"`
	Type     string `xml:"type,attr"`
	Contents string `xml:",chardata"`
}

func NewJunitPrinter(verbose bool) *JunitPrinter {
	return &JunitPrinter{
		verbose: verbose,
	}
}

func (jp *JunitPrinter) SetWriter(ctx context.Context, outputFile string) {
	if outputFile != "" {
		if strings.TrimSpace(outputFile) == "" {
			outputFile = junitOutputFile
		}
		if filepath.Ext(strings.TrimSpace(outputFile)) != junitOutputExt {
			outputFile = outputFile + junitOutputExt
		}
	}
	jp.writer = printer.GetWriter(ctx, outputFile)
}

func (jp *JunitPrinter) Score(score float32) {
	// Handle invalid scores
	if score > 100 {
		score = 100
	} else if score < 0 {
		score = 0
	}

	fmt.Fprintf(os.Stderr, "\nOverall compliance-score (100- Excellent, 0- All failed): %d\n", cautils.Float32ToInt(score))
}

func (jp *JunitPrinter) PrintNextSteps() {

}

func (jp *JunitPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) {
	if opaSessionObj == nil {
		logger.L().Ctx(ctx).Error("failed to print results, missing data")
		return
	}

	junitResult := testsSuites(opaSessionObj)
	postureReportStr, err := xml.MarshalIndent(junitResult, "", "  ")
	if err != nil {
		logger.L().Ctx(ctx).Fatal("failed to Marshal xml result object", helpers.Error(err))
	}

	if _, err := jp.writer.Write([]byte(xml.Header)); err != nil {
		logger.L().Ctx(ctx).Error("failed to write results", helpers.Error(err))
		return
	}
	if _, err := jp.writer.Write(postureReportStr); err != nil {
		logger.L().Ctx(ctx).Error("failed to write results", helpers.Error(err))
		return
	}
	printer.LogOutputFile(jp.writer.Name())
}

// iso8601Timestamp returns the report generation time in ISO 8601 format,
// falling back to the current time when ReportGenerationTime is the zero value.
func iso8601Timestamp(t time.Time) string {
	if t.IsZero() {
		t = time.Now().UTC()
	}
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

// aggregateSuiteCounts sums the Tests/Failures/Errors counters across child
// testsuites. Extracted so the aggregation can be unit-tested directly,
// independent of the production code path (which never populates child Errors).
func aggregateSuiteCounts(suites []JUnitTestSuite) (tests, failures, errors int) {
	for _, s := range suites {
		tests += s.Tests
		failures += s.Failures
		errors += s.Errors
	}
	return
}

func testsSuites(results *cautils.OPASessionObj) *JUnitTestSuites {
	suites := listTestsSuite(results)
	tests, failures, errs := aggregateSuiteCounts(suites)
	return &JUnitTestSuites{
		Suites:   suites,
		Tests:    tests,
		Failures: failures,
		Errors:   errs,
		Name:     "Kubescape Scanning",
	}
}
func listTestsSuite(results *cautils.OPASessionObj) []JUnitTestSuite {
	var testSuites []JUnitTestSuite
	timestamp := iso8601Timestamp(results.Report.ReportGenerationTime)

	// control scan
	if len(results.Report.SummaryDetails.ListFrameworks()) == 0 {
		testSuite := JUnitTestSuite{}
		testSuite.Tests = results.Report.SummaryDetails.NumberOfControls().All()
		testSuite.Failures = results.Report.SummaryDetails.NumberOfControls().Failed()
		testSuite.Skipped = results.Report.SummaryDetails.NumberOfControls().Skipped()
		testSuite.Timestamp = timestamp
		testSuite.ID = 0
		testSuite.Name = "kubescape"
		testSuite.Properties = properties(results.Report.SummaryDetails.Score)
		testSuite.TestCases = testsCases(results, &results.Report.SummaryDetails.Controls, "Kubescape")
		testSuites = append(testSuites, testSuite)
		return testSuites
	}

	for i, f := range results.Report.SummaryDetails.Frameworks {
		testSuite := JUnitTestSuite{}
		testSuite.Tests = f.NumberOfControls().All()
		testSuite.Failures = f.NumberOfControls().Failed()
		testSuite.Skipped = f.NumberOfControls().Skipped()
		testSuite.Timestamp = timestamp
		testSuite.ID = i
		testSuite.Name = f.Name
		testSuite.Properties = properties(f.Score)
		testSuite.TestCases = testsCases(results, f.GetControls(), f.GetName())
		testSuites = append(testSuites, testSuite)
	}

	return testSuites
}
func testsCases(results *cautils.OPASessionObj, controls reportsummary.IControlsSummaries, classname string) []JUnitTestCase {
	var testCases []JUnitTestCase

	controlIDs := controls.ListControlsIDs(nil).All()
	sortedIDs := make([]string, 0, len(controlIDs))
	for cID := range controlIDs {
		sortedIDs = append(sortedIDs, cID)
	}
	sort.Strings(sortedIDs)

	for _, cID := range sortedIDs {
		testCase := JUnitTestCase{}
		control := results.Report.SummaryDetails.Controls.GetControl(reportsummary.EControlCriteriaID, cID)

		testCase.Name = control.GetName()
		testCase.Classname = classname

		if control.GetStatus().IsFailed() {
			resources := map[string]interface{}{}
			for rId, status := range control.ListResourcesIDs(nil).All() {
				if status != apis.StatusFailed {
					continue
				}

				resource := results.AllResources[rId]
				sourcePath := ""
				if ResourceSourcePath, ok := results.ResourceSource[rId]; ok {
					sourcePath = ResourceSourcePath.RelativePath
				}
				resources[resourceToString(resource, sourcePath)] = nil
			}
			resourcesStr := shared.MapStringToSlice(resources)
			sort.Strings(resourcesStr)
			testCaseFailure := JUnitFailure{}
			testCaseFailure.Type = "Control"
			testCaseFailure.Message = fmt.Sprintf("%s failed on %d resource(s)", control.GetName(), len(resourcesStr))
			testCaseFailure.Contents = fmt.Sprintf("Remediation: %s\nMore details: %s\n\n%s", control.GetRemediation(), cautils.GetControlLink(control.GetID()), strings.Join(resourcesStr, "\n"))

			testCase.Failure = &testCaseFailure
		} else if control.GetStatus().IsSkipped() {
			testCase.SkipMessage = &JUnitSkipMessage{
				Message: buildSkipMessage(control.GetStatus()),
			}

		}
		testCases = append(testCases, testCase)
	}
	return testCases
}

// buildSkipMessage constructs a human-readable skip reason from StatusInfo.
// It uses SubStatus (e.g. "configuration", "irrelevant") and appends InnerInfo when available.
func buildSkipMessage(status apis.IStatus) string {
	if status == nil {
		return ""
	}
	subStatus := strings.TrimSpace(string(status.GetSubStatus()))
	if si, ok := status.(*apis.StatusInfo); ok {
		info := strings.TrimSpace(si.InnerInfo)
		if subStatus != "" && info != "" {
			return fmt.Sprintf("%s: %s", subStatus, info)
		}
		if info != "" {
			return info
		}
	}
	return subStatus
}

func resourceToString(resource workloadinterface.IMetadata, sourcePath string) string {
	sep := "; "
	s := ""
	s += fmt.Sprintf("apiVersion: %s", resource.GetApiVersion()) + sep
	s += fmt.Sprintf("kind: %s", resource.GetKind()) + sep
	if resource.GetNamespace() != "" {
		s += fmt.Sprintf("namespace: %s", resource.GetNamespace()) + sep
	}
	s += fmt.Sprintf("name: %s", resource.GetName())
	if sourcePath != "" {
		s += sep + fmt.Sprintf("sourcePath: %s", sourcePath)
	}
	return s
}

func properties(complianceScore float32) []JUnitProperty {
	return []JUnitProperty{
		{
			Name:  "complianceScore",
			Value: fmt.Sprintf("%.2f", complianceScore),
		},
	}
}
