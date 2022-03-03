package v2

import (
	"encoding/xml"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/logger"
	"github.com/armosec/kubescape/cautils/logger/helpers"
	"github.com/armosec/kubescape/resultshandling/printer"
	"github.com/armosec/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/armosec/opa-utils/shared"
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
	Errors     int             `xml:"errors,attr"`    // The total number of tests in the suite that errored
	Failures   int             `xml:"failures,attr"`  // The total number of tests in the suite that failed
	Hostname   string          `xml:"hostname,attr"`  // Host on which the tests were executed ? cluster name ?
	ID         int             `xml:"id,attr"`        // Starts at 0 for the first testsuite and is incremented by 1 for each following testsuite
	Skipped    string          `xml:"skipped,attr"`   // The total number of skipped tests
	Time       string          `xml:"time,attr"`      // Time taken (in seconds) to execute the tests in the suite
	Timestamp  string          `xml:"timestamp,attr"` // when the test was executed in ISO 8601 format (2014-01-21T16:17:18)
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

func NewJunitPrinter(verbose bool) *JunitPrinter {
	return &JunitPrinter{
		verbose: verbose,
	}
}

func (junitPrinter *JunitPrinter) SetWriter(outputFile string) {
	junitPrinter.writer = printer.GetWriter(outputFile)
}

func (junitPrinter *JunitPrinter) Score(score float32) {
	fmt.Fprintf(os.Stderr, "\nOverall risk-score (0- Excellent, 100- All failed): %d\n", int(score))
}

func (junitPrinter *JunitPrinter) ActionPrint(opaSessionObj *cautils.OPASessionObj) {
	junitResult := testsSuites(opaSessionObj)
	postureReportStr, err := xml.Marshal(junitResult)
	if err != nil {
		logger.L().Fatal("failed to Marshal xml result object", helpers.Error(err))
	}

	logOUtputFile(junitPrinter.writer.Name())

	junitPrinter.writer.Write(postureReportStr)
}

func testsSuites(results *cautils.OPASessionObj) *JUnitTestSuites {
	return &JUnitTestSuites{
		Suites:   listTestsSuite(results),
		Tests:    results.Report.SummaryDetails.NumberOfControls().All(),
		Name:     "Kubescape Scanning",
		Failures: results.Report.SummaryDetails.NumberOfControls().Failed(),
	}
}
func listTestsSuite(results *cautils.OPASessionObj) []JUnitTestSuite {
	var testSuites []JUnitTestSuite

	// control scan
	if len(results.Report.SummaryDetails.ListFrameworks().All()) == 0 {
		testSuite := JUnitTestSuite{}
		testSuite.Failures = results.Report.SummaryDetails.NumberOfControls().Failed()
		testSuite.Timestamp = results.Report.ReportGenerationTime.String()
		testSuite.ID = 0
		testSuite.Name = "kubescape"
		testSuite.Properties = properties(results.Report.SummaryDetails.Score)
		testSuite.TestCases = testsCases(results, &results.Report.SummaryDetails.Controls, "Kubescape")
		testSuites = append(testSuites, testSuite)
		return testSuites
	}

	for i, f := range results.Report.SummaryDetails.Frameworks {
		testSuite := JUnitTestSuite{}
		testSuite.Failures = f.NumberOfControls().Failed()
		testSuite.Timestamp = results.Report.ReportGenerationTime.String()
		testSuite.ID = i
		testSuite.Name = f.Name
		testSuite.Properties = properties(f.Score)
		testSuite.TestCases = testsCases(results, f.ListControls(), f.GetName())
		testSuites = append(testSuites, testSuite)
	}

	return testSuites
}
func testsCases(results *cautils.OPASessionObj, controls reportsummary.IControlsSummaries, classname string) []JUnitTestCase {
	var testCases []JUnitTestCase

	for _, cID := range controls.ListControlsIDs().All() {
		testCase := JUnitTestCase{}
		control := results.Report.SummaryDetails.Controls.GetControl(reportsummary.EControlCriteriaID, cID)

		testCase.Name = control.GetName()
		testCase.Classname = classname
		testCase.Status = string(control.GetStatus().Status())

		if control.GetStatus().IsFailed() {
			resources := map[string]interface{}{}
			resourceIDs := control.ListResourcesIDs().Failed()
			for j := range resourceIDs {
				resource := results.AllResources[resourceIDs[j]]
				resources[resourceToString(resource)] = nil
			}
			resourcesStr := shared.MapStringToSlice(resources)
			sort.Strings(resourcesStr)
			testCaseFailure := JUnitFailure{}
			testCaseFailure.Type = "Control"
			// testCaseFailure.Contents =
			testCaseFailure.Message = fmt.Sprintf("Remediation: %s\nMore details: %s\n\n%s", control.GetRemediation(), getControlURL(control.GetID()), strings.Join(resourcesStr, "\n"))

			testCase.Failure = &testCaseFailure
		} else if control.GetStatus().IsSkipped() {
			testCase.SkipMessage = &JUnitSkipMessage{
				Message: "", // TODO - fill after statusInfo is supportred
			}

		}
		testCases = append(testCases, testCase)
	}
	return testCases
}

func resourceToString(resource workloadinterface.IMetadata) string {
	sep := "; "
	s := ""
	s += fmt.Sprintf("apiVersion: %s", resource.GetApiVersion()) + sep
	s += fmt.Sprintf("kind: %s", resource.GetKind()) + sep
	if resource.GetNamespace() != "" {
		s += fmt.Sprintf("namespace: %s", resource.GetNamespace()) + sep
	}
	s += fmt.Sprintf("name: %s", resource.GetName())
	return s
}

func properties(riskScore float32) []JUnitProperty {
	return []JUnitProperty{
		{
			Name:  "riskScore",
			Value: fmt.Sprintf("%.2f", riskScore),
		},
	}
}
