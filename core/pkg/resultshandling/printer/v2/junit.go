package v2

import (
	"encoding/xml"
	"fmt"
	"os"
	"strings"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
)

/*
riskScore
status
*/
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
	Suites   []JUnitTestSuite `xml:"testsuite"`     // list of controls
	Errors   int              `xml:"errors,attr"`   // total number of tests with error result from all testsuites
	Disabled int              `xml:"disabled,attr"` // total number of disabled tests from all testsuites
	Failures int              `xml:"failures,attr"` // total number of failed tests from all testsuites
	Tests    int              `xml:"tests,attr"`    // total number of tests from all testsuites. Some software may expect to only see the number of successful tests from all testsuites though
	Time     string           `xml:"time,attr"`     // time in seconds to execute all test suites
	Name     string           `xml:"name,attr"`     // ? Add framework names ?
}

// JUnitTestSuite represents a single control
type JUnitTestSuite struct {
	XMLName    xml.Name        `xml:"testsuite"`
	Name       string          `xml:"name,attr"`      // Full (class) name of the test for non-aggregated testsuite documents. Class name without the package for aggregated testsuites documents. Required
	Disabled   int             `xml:"disabled,attr"`  // The total number of disabled tests in the suite. optional. not supported by maven surefire.
	Errors     int             `xml:"errors,attr"`    // The total number of tests in the suite that errors
	Failures   int             `xml:"failures,attr"`  // The total number of tests in the suite that failed
	Hostname   string          `xml:"hostname,attr"`  // Host on which the tests were executed ? cluster name ?
	ID         int             `xml:"id,attr"`        // Starts at 0 for the first testsuite and is incremented by 1 for each following testsuite
	Skipped    string          `xml:"skipped,attr"`   // The total number of skipped tests
	Time       string          `xml:"time,attr"`      // Time taken (in seconds) to execute the tests in the suite
	Timestamp  string          `xml:"timestamp,attr"` // when the test was executed in ISO 8601 format (2014-01-21T16:17:18)
	File       string          `xml:"file,attr"`      // The file be tested
	Properties []JUnitProperty `xml:"properties>property,omitempty"`
	TestCases  []JUnitTestCase `xml:"testcase"`
}

// JUnitTestCase represents a single resource
type JUnitTestCase struct {
	XMLName     xml.Name          `xml:"testcase"`
	Classname   string            `xml:"classname,attr"` // Full class name for the class the test method is in. required
	Status      string            `xml:"status,attr"`    // Status
	Name        string            `xml:"name,attr"`      // Name of the test method, required
	Time        string            `xml:"time,attr"`      // Time taken (in seconds) to execute the test. optional
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

const (
	lineSeparator         = "\n===================================================================================================================\n\n"
	testCaseTypeResources = "Resources"
)

func NewJunitPrinter(verbose bool) *JunitPrinter {
	return &JunitPrinter{
		verbose: verbose,
	}
}

func (junitPrinter *JunitPrinter) SetWriter(outputFile string) {
	junitPrinter.writer = printer.GetWriter(outputFile)
}

func (junitPrinter *JunitPrinter) Score(score float32) {
	fmt.Fprintf(os.Stderr, "\nOverall risk-score (0- Excellent, 100- All failed): %d\n", cautils.Float32ToInt(score))
}

func (junitPrinter *JunitPrinter) ActionPrint(opaSessionObj *cautils.OPASessionObj) {
	junitResult := testsSuites(opaSessionObj)
	postureReportStr, err := xml.Marshal(junitResult)
	if err != nil {
		logger.L().Fatal("failed to Marshal xml result object", helpers.Error(err))
	}

	logOUtputFile(junitPrinter.writer.Name())
	if _, err := junitPrinter.writer.Write(postureReportStr); err != nil {
		logger.L().Error("failed to write results", helpers.Error(err))
	}
}

func testsSuites(results *cautils.OPASessionObj) *JUnitTestSuites {
	return &JUnitTestSuites{
		Suites:   listTestsSuite(results),
		Tests:    results.Report.SummaryDetails.NumberOfResources().All(),
		Name:     "Kubescape Scanning",
		Failures: results.Report.SummaryDetails.NumberOfResources().Failed(),
	}
}

// aggregate resources source to a list of resources results
func sourceToResourcesResults(results *cautils.OPASessionObj) map[string][]resourcesresults.Result {
	resourceResults := make(map[string][]resourcesresults.Result)
	for i := range results.ResourceSource {
		if r, ok := results.ResourcesResult[i]; ok {
			if _, ok := resourceResults[results.ResourceSource[i].RelativePath]; !ok {
				resourceResults[results.ResourceSource[i].RelativePath] = []resourcesresults.Result{}
			}
			resourceResults[results.ResourceSource[i].RelativePath] = append(resourceResults[results.ResourceSource[i].RelativePath], r)
		}
	}
	return resourceResults
}

// listTestsSuite returns a list of testsuites
func listTestsSuite(results *cautils.OPASessionObj) []JUnitTestSuite {
	var testSuites []JUnitTestSuite
	resourceResults := sourceToResourcesResults(results)
	counter := 0
	// control scan
	for path, resourcesResult := range resourceResults {
		testSuite := JUnitTestSuite{}
		testSuite.Timestamp = results.Report.ReportGenerationTime.String()
		testSuite.ID = counter
		counter++
		testSuite.File = path
		testSuite.TestCases = testsCases(results, resourcesResult)
		if len(testSuite.TestCases) > 0 {
			testSuites = append(testSuites, testSuite)
		}
	}

	return testSuites
}

func failedControlsToFailureMessage(results *cautils.OPASessionObj, controls []resourcesresults.ResourceAssociatedControl, severityCounter []int) string {
	msg := ""
	for _, c := range controls {
		control := results.Report.SummaryDetails.Controls.GetControl(reportsummary.EControlCriteriaID, c.GetID())
		if c.GetStatus(nil).IsFailed() {
			msg += fmt.Sprintf("Test: %s\n", control.GetName())
			msg += fmt.Sprintf("Severity: %s\n", apis.ControlSeverityToString(control.GetScoreFactor()))
			msg += fmt.Sprintf("Remediation: %s\n", control.GetRemediation())
			msg += fmt.Sprintf("Link: %s\n", cautils.GetControlLink(control.GetID()))
			if failedPaths := failedPathsToString(&c); len(failedPaths) > 0 {
				msg += fmt.Sprintf("Failed paths: \n - %s\n", strings.Join(failedPaths, "\n - "))
			}
			if fixPaths := fixPathsToString(&c); len(fixPaths) > 0 {
				msg += fmt.Sprintf("Available fix: \n - %s\n", strings.Join(fixPaths, "\n - "))
			}
			msg += "\n"

			severityCounter[apis.ControlSeverityToInt(control.GetScoreFactor())] += 1
		}
	}
	return msg
}

// Every testCase includes a file (even if the file contains several resources)
func testsCases(results *cautils.OPASessionObj, resourcesResult []resourcesresults.Result) []JUnitTestCase {
	var testCases []JUnitTestCase
	testCase := JUnitTestCase{}
	testCaseFailure := JUnitFailure{}
	testCaseFailure.Type = testCaseTypeResources
	message := ""

	// severityCounter represents the severities, 0: Unknown, 1: Low, 2: Medium, 3: High, 4: Critical
	severityCounter := make([]int, apis.NumberOfSeverities, apis.NumberOfSeverities)

	for i := range resourcesResult {
		if failedControls := failedControlsToFailureMessage(results, resourcesResult[i].ListControls(), severityCounter); failedControls != "" {
			message += fmt.Sprintf("%sResource: %s\n\n%s", lineSeparator, resourceNameToString(results.AllResources[resourcesResult[i].GetResourceID()]), failedControls)
		}
	}
	testCaseFailure.Message += fmt.Sprintf("%s\n%s", getSummaryMessage(severityCounter), message)

	testCase.Failure = &testCaseFailure
	if testCase.Failure.Message != "" {
		testCases = append(testCases, testCase)
	}

	return testCases
}

func getSummaryMessage(severityCounter []int) string {
	total := 0
	severities := ""
	for i, count := range severityCounter {
		if apis.SeverityNumberToString(i) == apis.SeverityNumberToString(apis.SeverityUnknown) {
			continue
		}
		severities += fmt.Sprintf("%s: %d, ", apis.SeverityNumberToString(i), count)
		total += count
	}
	if len(severities) == 0 {
		return ""
	}
	return fmt.Sprintf("Total: %d (%s)", total, severities[:len(severities)-2])
}

func resourceNameToString(resource workloadinterface.IMetadata) string {
	s := ""
	s += fmt.Sprintf("kind=%s/", resource.GetKind())
	if resource.GetNamespace() != "" {
		s += fmt.Sprintf("namespace=%s/", resource.GetNamespace())
	}
	s += fmt.Sprintf("name=%s", resource.GetName())
	return s
}
