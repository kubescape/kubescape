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
)

type JunitPrinter struct {
	writer  *os.File
	verbose bool
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

type JUnitTestSuites struct {
	XMLName   xml.Name        `xml:"testsuite"`
	Suites    []JUnitTestCase `xml:"testsuites"`
	RiskScore float32         `xml:"riskScore,attr"` // test risk score
	Time      string          `xml:"time,attr"`      // scanning time
	Controls  int             `xml:"tests,attr"`     // number of controls
}

// JUnitTestCase is a single test case with its result.
type JUnitTestCase struct { // Control
	XMLName      xml.Name        `xml:"testcase"`
	RiskScore    float32         `xml:"riskScore,attr"`
	Status       string          `xml:"status,attr"`
	Name         string          `xml:"name,attr"`
	AllResources int             `xml:"allResources,attr"`
	Excluded     int             `xml:"excludedResources,attr"`
	Failed       int             `xml:"filedResources,attr"`
	Resources    []JUnitResource `xml:"resources"`
}

type JUnitResource struct { // Single resource
	Name        string                   `xml:"name,attr"`
	Namespace   string                   `xml:"namespace,attr"`
	Kind        string                   `xml:"kind,attr"`
	ApiVersion  string                   `xml:"apiVersion,attr"`
	FailedPaths []armotypes.PosturePaths `xml:"jsonPaths"`
}

func (junitPrinter *JunitPrinter) convertPostureReportToJunitResult(results *cautils.OPASessionObj) (*JUnitTestSuites, error) {
	juResult := JUnitTestSuites{
		XMLName: xml.Name{
			Local: "Kubescape scan results",
		},
		RiskScore: results.Report.SummaryDetails.Score,
		Time:      results.Report.GetTimestamp().String(),
		Controls:  len(results.Report.ListControls().All()),
	}

	// controls
	for _, controlReports := range results.Report.ListControls().All() {
		testCase := JUnitTestCase{}
		testCase.Name = controlReports.GetName()
		testCase.Status = string(controlReports.GetStatus().Status())

		// resources
		testCase.AllResources = controlReports.NumberOfResources().All()
		testCase.Excluded = controlReports.NumberOfResources().Excluded()
		testCase.Failed = controlReports.NumberOfResources().Failed()

		var jUnitResources []JUnitResource
		for _, resourceID := range controlReports.ListResourcesIDs().All() {
			if !junitPrinter.verbose {
				continue
			}
			jUnitResource := JUnitResource{}
			if resource, ok := results.AllResources[resourceID]; ok {
				jUnitResource.Name = resource.GetName()
				jUnitResource.Namespace = resource.GetNamespace()
				jUnitResource.Kind = resource.GetKind()
				jUnitResource.ApiVersion = resource.GetApiVersion()
			}
			if result, ok := results.ResourcesResult[resourceID]; ok {
				rules := result.ListRulesOfControl("", controlReports.GetName())
				for _, rule := range rules {
					jUnitResource.FailedPaths = append(jUnitResource.FailedPaths, rule.Paths...)
				}
			}
			jUnitResources = append(jUnitResources, jUnitResource)
		}
		testCase.Resources = jUnitResources
		juResult.Suites = append(juResult.Suites, testCase)
	}

	return &juResult, nil
}
