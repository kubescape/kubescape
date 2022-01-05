package v2

import (
	"encoding/xml"
	"fmt"
	"os"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/resultshandling/printer"
	reporthandlingv2 "github.com/armosec/opa-utils/reporthandling/v2"
)

type JunitPrinter struct {
	writer *os.File
}

func NewJunitPrinter() *JunitPrinter {
	return &JunitPrinter{}
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
	junitResult, err := convertPostureReportToJunitResult(opaSessionObj.Report)
	if err != nil {
		fmt.Println("Failed to convert posture report object!")
		os.Exit(1)
	}
	postureReportStr, err := xml.Marshal(junitResult)
	if err != nil {
		fmt.Println("Failed to convert posture report object!")
		os.Exit(1)
	}
	junitPrinter.writer.Write(postureReportStr)
}

type JUnitTestSuites struct {
	XMLName xml.Name         `xml:"testsuites"`
	Suites  []JUnitTestSuite `xml:"testsuite"`
}

// JUnitTestSuite is a single JUnit test suite which may contain many
// testcases.
type JUnitTestSuite struct {
	XMLName    xml.Name        `xml:"testsuite"`
	Tests      int             `xml:"tests,attr"`
	Time       string          `xml:"time,attr"`
	Name       string          `xml:"name,attr"`
	Resources  int             `xml:"resources,attr"`
	Excluded   int             `xml:"excluded,attr"`
	Failed     int             `xml:"filed,attr"`
	Properties []JUnitProperty `xml:"properties>property,omitempty"`
	TestCases  []JUnitTestCase `xml:"testcase"`
}

// JUnitTestCase is a single test case with its result.
type JUnitTestCase struct {
	XMLName     xml.Name          `xml:"testcase"`
	Classname   string            `xml:"classname,attr"`
	Name        string            `xml:"name,attr"`
	Time        string            `xml:"time,attr"`
	Resources   int               `xml:"resources,attr"`
	Excluded    int               `xml:"excluded,attr"`
	Failed      int               `xml:"filed,attr"`
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

func convertPostureReportToJunitResult(postureResult *reporthandlingv2.PostureReport) (*JUnitTestSuites, error) {
	juResult := JUnitTestSuites{XMLName: xml.Name{Local: "Kubescape scan results"}}
	for _, framework := range postureResult.ListFrameworks().All() {
		suite := JUnitTestSuite{
			Name:      framework.GetName(),
			Resources: framework.NumberOfResources().All(),
			Excluded:  framework.NumberOfResources().Excluded(),
			Failed:    framework.NumberOfResources().Failed(),
		}
		for _, controlReports := range postureResult.ListControls().All() {
			suite.Tests = suite.Tests + 1
			testCase := JUnitTestCase{}
			testCase.Name = controlReports.GetName()
			testCase.Classname = "Kubescape"
			testCase.Time = postureResult.ReportGenerationTime.String()
			// if 0 < len(controlReports.RuleReports[0].RuleResponses) {

			// 	testCase.Resources = controlReports.NumberOfResources().All()
			// 	testCase.Excluded = controlReports.NumberOfResources().Excluded()
			// 	testCase.Failed = controlReports.NumberOfResources().Failed()
			// 	failure := JUnitFailure{}
			// 	failure.Message = fmt.Sprintf("%d resources failed", testCase.Failed)
			// 	for _, ruleResponses := range controlReports.RuleReports[0].RuleResponses {
			// 		failure.Contents = fmt.Sprintf("%s\n%s", failure.Contents, ruleResponses.AlertMessage)
			// 	}
			// 	testCase.Failure = &failure
			// }
			suite.TestCases = append(suite.TestCases, testCase)
		}
		juResult.Suites = append(juResult.Suites, suite)
	}
	return &juResult, nil
}
