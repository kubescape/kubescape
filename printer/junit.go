package printer

import (
	"encoding/xml"
	"fmt"
	"kube-escape/cautils/opapolicy"
)

type JUnitTestSuites struct {
	XMLName xml.Name         `xml:"testsuites"`
	Suites  []JUnitTestSuite `xml:"testsuite"`
}

// JUnitTestSuite is a single JUnit test suite which may contain many
// testcases.
type JUnitTestSuite struct {
	XMLName    xml.Name        `xml:"testsuite"`
	Tests      int             `xml:"tests,attr"`
	Failures   int             `xml:"failures,attr"`
	Time       string          `xml:"time,attr"`
	Name       string          `xml:"name,attr"`
	Properties []JUnitProperty `xml:"properties>property,omitempty"`
	TestCases  []JUnitTestCase `xml:"testcase"`
}

// JUnitTestCase is a single test case with its result.
type JUnitTestCase struct {
	XMLName     xml.Name          `xml:"testcase"`
	Classname   string            `xml:"classname,attr"`
	Name        string            `xml:"name,attr"`
	Time        string            `xml:"time,attr"`
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

func convertPostureReportToJunitResult(postureResult *opapolicy.PostureReport) (*JUnitTestSuites, error) {
	juResult := JUnitTestSuites{XMLName: xml.Name{Local: "Kubescape scan results"}}
	for _, framework := range postureResult.FrameworkReports {
		suite := JUnitTestSuite{Name: framework.Name}
		for _, controlReports := range framework.ControlReports {
			suite.Tests = suite.Tests + 1
			testCase := JUnitTestCase{}
			testCase.Name = controlReports.Name
			testCase.Classname = "Kubescape"
			testCase.Time = "0"
			if 0 < len(controlReports.RuleReports[0].RuleResponses) {
				suite.Failures = suite.Failures + 1
				failure := JUnitFailure{}
				failure.Message = fmt.Sprintf("%d resources failed", len(controlReports.RuleReports[0].RuleResponses))
				for _, ruleResponses := range controlReports.RuleReports[0].RuleResponses {
					failure.Contents = fmt.Sprintf("%s\n%s", failure.Contents, ruleResponses.AlertMessage)
				}
				testCase.Failure = &failure
			}
			suite.TestCases = append(suite.TestCases, testCase)
		}
		juResult.Suites = append(juResult.Suites, suite)
	}
	return &juResult, nil
}
