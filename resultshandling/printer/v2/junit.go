package v2

import (
	"encoding/xml"
	"fmt"
	"os"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/logger"
	"github.com/armosec/kubescape/cautils/logger/helpers"
	"github.com/armosec/kubescape/resultshandling/printer"
	"github.com/armosec/opa-utils/reporthandling/results/v1/reportsummary"
)

type JunitPrinter struct {
	writer  *os.File
	verbose bool
}

type JUnitTestSuites struct {
	XMLName    xml.Name          `xml:"testsuite"`
	Suites     []JUnitTestCase   `xml:"testsuites"`
	Frameworks []JUnitFrameworks `xml:"framework"`
	RiskScore  float32           `xml:"riskScore,attr"` // test risk score
	Time       string            `xml:"time,attr"`      // scanning time
	Controls   int               `xml:"testcases,attr"` // number of controls
}

type JUnitFrameworks struct { // Frameworks
	Name      string  `xml:"name,attr"`
	RiskScore float32 `xml:"riskscore,attr"`
	Status    string  `xml:"status,attr"`
}

// JUnitTestCase is a single test case with its result.
type JUnitTestCase struct { // Control
	XMLName      xml.Name        `xml:"testcase"`
	Name         string          `xml:"name,attr"`
	ID           string          `xml:"id,attr"`
	Url          string          `xml:"url,attr"`
	RiskScore    float32         `xml:"riskScore,attr"`
	Status       string          `xml:"status,attr"`
	Info         string          `xml:"info,attr"`
	AllResources int             `xml:"allResources,attr"`
	Excluded     int             `xml:"excludedResources,attr"`
	Failed       int             `xml:"filedResources,attr"`
	Resources    []JUnitResource `xml:"resource"`
}

type JUnitResource struct { // Single resource
	Name        string                   `xml:"name,attr"`
	Namespace   string                   `xml:"namespace,attr"`
	Kind        string                   `xml:"kind,attr"`
	ApiVersion  string                   `xml:"apiVersion,attr"`
	FailedPaths []armotypes.PosturePaths `xml:"jsonpath"`
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
	juResult := JUnitTestSuites{
		XMLName: xml.Name{
			Local: "Kubescape scan results",
		},
		RiskScore:  results.Report.SummaryDetails.Score,
		Time:       results.Report.GetTimestamp().String(),
		Controls:   len(results.Report.ListControls().All()),
		Frameworks: []JUnitFrameworks{},
	}

	// Frameworks
	for _, frameworksReports := range results.Report.ListFrameworks().All() {
		fw := JUnitFrameworks{}
		fw.Name = frameworksReports.GetName()
		fw.RiskScore = frameworksReports.GetScore()
		fw.Status = string(frameworksReports.GetStatus().Status())
		juResult.Frameworks = append(juResult.Frameworks, fw)
	}

	// controls
	for _, controlIDs := range results.Report.ListControlsIDs().All() {
		controlReport := results.Report.SummaryDetails.Controls.GetControl(reportsummary.EControlCriteriaID, controlIDs)

		// control data
		testCase := JUnitTestCase{}
		testCase.Name = controlReport.GetName()
		testCase.ID = controlReport.GetID()
		testCase.Url = getControlURL(controlReport.GetID())
		testCase.Name = controlReport.GetName()
		testCase.Status = string(controlReport.GetStatus().Status())

		// resources counters
		testCase.AllResources = controlReport.NumberOfResources().All()
		testCase.Excluded = controlReport.NumberOfResources().Excluded()
		testCase.Failed = controlReport.NumberOfResources().Failed()

		// resources
		var jUnitResources []JUnitResource
		for _, resourceID := range controlReport.ListResourcesIDs().All() {
			result, ok := results.ResourcesResult[resourceID]
			if !ok {
				continue
			}
			if result.GetStatus(nil).IsPassed() && !junitPrinter.verbose { // add passed resources only in verbose mode
				continue
			}

			jUnitResource := JUnitResource{}
			rules := result.ListRulesOfControl(controlReport.GetID(), "")
			for _, rule := range rules {
				jUnitResource.FailedPaths = append(jUnitResource.FailedPaths, rule.Paths...)
			}
			if resource, ok := results.AllResources[resourceID]; ok {
				jUnitResource.Name = resource.GetName()
				jUnitResource.Namespace = resource.GetNamespace()
				jUnitResource.Kind = resource.GetKind()
				jUnitResource.ApiVersion = resource.GetApiVersion()
			}

			jUnitResources = append(jUnitResources, jUnitResource)
		}
		testCase.Resources = jUnitResources
		juResult.Suites = append(juResult.Suites, testCase)
	}

	return &juResult, nil
}
