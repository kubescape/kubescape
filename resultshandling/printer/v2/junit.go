package v2

import (
	"encoding/xml"
	"fmt"
	"os"
	"strings"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/logger"
	"github.com/armosec/kubescape/cautils/logger/helpers"
	"github.com/armosec/kubescape/resultshandling/printer"
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

func (junitPrinter *JunitPrinter) FinalizeData(opaSessionObj *cautils.OPASessionObj) {
	finalizeReport(opaSessionObj)
}

func (junitPrinter *JunitPrinter) ActionPrint(opaSessionObj *cautils.OPASessionObj) {
	junitResult, err := junitPrinter.convertPostureReportToJunitResult(opaSessionObj)
	if err != nil {
		logger.L().Fatal("failed to build xml result object", helpers.Error(err))
	}
	postureReportStr, err := xml.Marshal(junitResult)
	if err != nil {
		logger.L().Fatal("failed to Marshal xml result object", helpers.Error(err))
	}
	junitPrinter.writer.Write(postureReportStr)
}

func (junitPrinter *JunitPrinter) convertPostureReportToJunitResult(results *cautils.OPASessionObj) (*JUnitTestSuites, error) {

	// // Frameworks
	// for _, frameworksReports := range results.Report.ListFrameworks().All() {
	// 	fw := JUnitFrameworks{}
	// 	fw.Name = frameworksReports.GetName()
	// 	fw.RiskScore = frameworksReports.GetScore()
	// 	fw.Status = string(frameworksReports.GetStatus().Status())
	// 	juResult.Frameworks = append(juResult.Frameworks, fw)
	// }
	testSuites := JUnitTestSuites{
		XMLName: xml.Name{
			Local: "Kubescape scan results",
		},
	}
	testSuites.Failures = results.Report.SummaryDetails.NumberOfResources().Failed()
	testSuites.Tests = results.Report.SummaryDetails.NumberOfResources().All()
	testSuites.Disabled = results.Report.SummaryDetails.NumberOfResources().Skipped()
	// summary.errors =
	// summary.Name = "?"

	// resources
	counter := 0
	for resourceID, resourceResult := range results.ResourcesResult {
		counter++

		// resource data
		testSuite := JUnitTestSuite{
			XMLName: xml.Name{
				Local: resourceID,
			},
		}
		testSuite.Name = resourceID
		testSuite.Disabled = 0
		testSuite.Errors = 0
		testSuite.Failures = len(resourceResult.ListControlsIDs(nil).Failed())
		testSuite.Hostname = ""
		testSuite.ID = counter
		// testSuite.Skipped = ""
		testSuite.Time = ""
		testSuite.Timestamp = results.PostureReport.ReportGenerationTime.String()

		testSuite.Properties = []JUnitProperty{
			{
				Name:  "ID",
				Value: resourceID,
			},
		}

		// controls
		for _, control := range resourceResult.ListControls() {
			testCase := JUnitTestCase{
				XMLName: xml.Name{
					Local: control.GetName(),
					Space: getControlURL(control.GetID()),
				},
			}
			testCase.Name = control.GetName()
			testCase.Classname = control.GetID()
			testCase.Status = string(control.GetStatus(nil).Status())

			if control.GetStatus(nil).IsFailed() {
				paths := failedPathsToString(&control)

				testCaseFailure := JUnitFailure{}
				testCaseFailure.Contents = fmt.Sprintf("More deatiles: %s", getControlURL(control.GetID()))
				testCaseFailure.Message = strings.Join(paths, ";")
				testCaseFailure.Type = "" // TODO - suppot add/modify

				testCase.Failure = &testCaseFailure
			}

			testSuite.TestCases = append(testSuite.TestCases, testCase)
		}

		testSuites.Suites = append(testSuites.Suites, testSuite)
	}

	return &testSuites, nil
}

// func (junitPrinter *JunitPrinter) convertPostureReportToJunitResult(results *cautils.OPASessionObj) (*JUnitTestSuites, error) {

// 	// // Frameworks
// 	// for _, frameworksReports := range results.Report.ListFrameworks().All() {
// 	// 	fw := JUnitFrameworks{}
// 	// 	fw.Name = frameworksReports.GetName()
// 	// 	fw.RiskScore = frameworksReports.GetScore()
// 	// 	fw.Status = string(frameworksReports.GetStatus().Status())
// 	// 	juResult.Frameworks = append(juResult.Frameworks, fw)
// 	// }
// 	testSuites := JUnitTestSuites{
// 		XMLName: xml.Name{
// 			Local: "Kubescape scan results",
// 		},
// 	}
// 	testSuites.Failures = results.Report.SummaryDetails.NumberOfControls().Failed()
// 	testSuites.Tests = results.Report.SummaryDetails.NumberOfControls().All()
// 	testSuites.Disabled = results.Report.SummaryDetails.NumberOfControls().Skipped()
// 	// summary.errors =
// 	// summary.Name = "?"

// 	// controls
// 	for _, controlIDs := range results.Report.ListControlsIDs().All() {
// 		controlReport := results.Report.SummaryDetails.Controls.GetControl(reportsummary.EControlCriteriaID, controlIDs)

// 		// control data
// 		testSuite := JUnitTestSuite{
// 			XMLName: xml.Name{
// 				Local: controlReport.GetName(),
// 				Space: getControlURL(controlReport.GetID()),
// 			},
// 		}
// 		testSuite.Name = controlReport.GetName()
// 		testSuite.Disabled = 0
// 		testSuite.Errors = 0
// 		testSuite.Failures = controlReport.NumberOfResources().Failed()
// 		testSuite.Hostname = ""
// 		testSuite.ID = 0
// 		// testSuite.Skipped = ""
// 		testSuite.Time = ""
// 		testSuite.Timestamp = ""

// 		testCase.Classname = controlReport.GetID()
// 		testCase.Url = getControlURL(controlReport.GetID())
// 		testCase.Name = controlReport.GetName()
// 		testCase.Status = string(controlReport.GetStatus().Status())

// 		// resources counters
// 		testCase.AllResources = controlReport.NumberOfResources().All()
// 		testCase.Excluded = controlReport.NumberOfResources().Excluded()
// 		testCase.Failed = controlReport.NumberOfResources().Failed()

// 		// resources
// 		var jUnitResources []JUnitResource
// 		for _, resourceID := range controlReport.ListResourcesIDs().All() {
// 			result, ok := results.ResourcesResult[resourceID]
// 			if !ok {
// 				continue
// 			}
// 			if result.GetStatus(nil).IsPassed() && !junitPrinter.verbose { // add passed resources only in verbose mode
// 				continue
// 			}

// 			jUnitResource := JUnitResource{}
// 			rules := result.ListRulesOfControl(controlReport.GetID(), "")
// 			for _, rule := range rules {
// 				jUnitResource.FailedPaths = append(jUnitResource.FailedPaths, rule.Paths...)
// 			}
// 			if resource, ok := results.AllResources[resourceID]; ok {
// 				jUnitResource.Name = resource.GetName()
// 				jUnitResource.Namespace = resource.GetNamespace()
// 				jUnitResource.Kind = resource.GetKind()
// 				jUnitResource.ApiVersion = resource.GetApiVersion()
// 			}

// 			jUnitResources = append(jUnitResources, jUnitResource)
// 		}
// 		testCase.Resources = jUnitResources
// 		juResult.Suites = append(juResult.Suites, testCase)
// 	}

// 	return &juResult, nil
// }
