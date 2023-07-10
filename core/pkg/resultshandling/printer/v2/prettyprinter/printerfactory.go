package prettyprinter

import (
	"fmt"
	"os"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/olekukonko/tablewriter"
)

type MainPrinterImpl struct {
	VerboseMode     bool
	SummaryPrint    bool
	CompliancePrint bool
	NextSteps       []string

	CategoriesConfig  *CategoriesConfiguration
	TopXWorkloadsFunc func(writer *os.File, TopXWorkloads []reportsummary.TopWorkload)
}

var _ MainPrinter = &MainPrinterImpl{}

func (mpi *MainPrinterImpl) GetCompliancePrint() bool {
	return mpi.CompliancePrint
}

func (mpi *MainPrinterImpl) SetVerboseMode(value bool) {
	mpi.VerboseMode = value
}

func (mpi *MainPrinterImpl) GetVerboseMode() bool {
	return mpi.VerboseMode
}

func (mpi *MainPrinterImpl) SetSummaryPrint(value bool) {
	mpi.SummaryPrint = value
}

func (mpi *MainPrinterImpl) GetSummaryPrint() bool {
	return mpi.SummaryPrint
}

func (mpi *MainPrinterImpl) SetCompliancePrint(value bool) {
	mpi.CompliancePrint = value
}

type CategoriesConfiguration struct {
	Headers           []string
	ColumnsAlignments []int
}

func NewCategoriesConfiguration(headers []string, columnsAlignments []int) *CategoriesConfiguration {
	return &CategoriesConfiguration{
		Headers:           headers,
		ColumnsAlignments: columnsAlignments,
	}
}

func (cc *CategoriesConfiguration) GetCategoriesHeaders() []string {
	return cc.Headers
}

func (cc *CategoriesConfiguration) GetCategoriesColumnsAlignments() []int {
	return cc.ColumnsAlignments
}

func NewMainPrinter(scanType cautils.ScanTypes) MainPrinter {
	switch scanType {
	case cautils.ScanTypeCluster:
		return NewClusterPrinter()
	case cautils.ScanTypeRepo:
		return NewRepoPrinter()
	default:
		return NewSummaryPrinter()
	}
}

func (mpi *MainPrinterImpl) Print(writer *os.File, summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) {
	if mpi.CategoriesConfig != nil {
		mpi.printCategories(writer, summaryDetails, sortedControlIDs)
	}

	if mpi.GetSummaryPrint() {
		mpi.printSummary(writer, summaryDetails, sortedControlIDs)
	}

	if mpi.TopXWorkloadsFunc != nil {
		// if number of workloads is less than 3, don't use the word "most"
		if len(summaryDetails.TopWorkloadsByScore) < 3 {
			cautils.InfoTextDisplay(writer, "Your risky workloads:\n")
		} else if len(summaryDetails.TopWorkloadsByScore) > 0 {
			cautils.InfoTextDisplay(writer, "Your most risky workloads:\n")
		}

		mpi.TopXWorkloadsFunc(writer, summaryDetails.TopWorkloadsByScore)
	}

	if mpi.GetCompliancePrint() {
		printComplianceScore(writer, filterComplianceFrameworks(summaryDetails.ListFrameworks()))
	}

	if len(mpi.NextSteps) > 0 {
		mpi.printNextSteps(writer)
	}

	fmt.Println("")
}

func (mpi *MainPrinterImpl) printNextSteps(writer *os.File) {
	cautils.InfoTextDisplay(writer, "Follow-up Steps:\n")
	for _, ns := range mpi.NextSteps {
		cautils.InfoTextDisplay(writer, "- "+ns+"\n")
	}
}

func (mpi *MainPrinterImpl) printCategories(writer *os.File, summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) {
	categoriesToControlSummariesMap := mapCategoryToControlSummaries(*summaryDetails, sortedControlIDs)

	categoriesTable := tablewriter.NewWriter(writer)
	categoriesTable.SetHeader(mpi.CategoriesConfig.GetCategoriesHeaders())
	categoriesTable.SetHeaderLine(true)
	categoriesTable.SetColumnAlignment(mpi.CategoriesConfig.GetCategoriesColumnsAlignments())

	for category, ctrls := range categoriesToControlSummariesMap {
		renderSingleCategory(writer, category, ctrls, categoriesTable)
	}
}

func (mpi *MainPrinterImpl) printSummary(writer *os.File, summaryDetails *reportsummary.SummaryDetails, sortedControlIDs [][]string) {
	if summaryDetails.NumberOfControls().All() == 0 {
		fmt.Fprintf(writer, "\nKubescape did not scan any of the resources, make sure you are scanning valid kubernetes manifests (Deployments, Pods, etc.)\n")
		return
	}
	cautils.InfoTextDisplay(writer, "\n"+ControlCountersForSummary(summaryDetails.NumberOfControls())+"\n")
	cautils.InfoTextDisplay(writer, renderSeverityCountersSummary(summaryDetails.GetResourcesSeverityCounters())+"\n\n")

	summaryTable := tablewriter.NewWriter(writer)
	summaryTable.SetAutoWrapText(false)
	summaryTable.SetHeader(getControlTableHeaders())
	summaryTable.SetHeaderLine(true)
	summaryTable.SetColumnAlignment(getColumnsAlignments())

	printAll := mpi.GetVerboseMode()
	if summaryDetails.NumberOfResources().Failed() == 0 {
		// if there are no failed controls, print the resource table and detailed information
		printAll = true
	}

	infoToPrintInfo := mapInfoToPrintInfo(summaryDetails.Controls)
	for i := len(sortedControlIDs) - 1; i >= 0; i-- {
		for _, c := range sortedControlIDs[i] {
			row := generateRow(summaryDetails.Controls.GetControl(reportsummary.EControlCriteriaID, c), infoToPrintInfo, printAll)
			if len(row) > 0 {
				summaryTable.Append(row)
			}
		}
	}

	summaryTable.SetFooter(generateFooter(summaryDetails))

	summaryTable.Render()

	// When scanning controls the framework list will be empty
	cautils.InfoTextDisplay(writer, frameworksScoresToString(summaryDetails.ListFrameworks()))

	printInfo(writer, infoToPrintInfo)
}
