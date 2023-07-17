package configurationprinter

import (
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

const (
	categoriesColumnSeverity  = iota
	categoriesColumnName      = iota
	categoriesColumnFailed    = iota
	categoriesColumnNextSteps = iota
)

func setCategoryStatusRow(controlSummary reportsummary.IControlSummary, row []string) {
	status := controlSummary.GetStatus().Status()
	if status == apis.StatusSkipped {
		status = "action required"
	}
	row[categoriesColumnFailed] = string(status)
}

func getCommonCategoriesTableHeaders() []string {
	headers := make([]string, 4)
	headers[categoriesColumnSeverity] = "SEVERITY"
	headers[categoriesColumnName] = "CONTROL NAME"
	headers[categoriesColumnFailed] = "STATUS"
	headers[categoriesColumnNextSteps] = "NEXT STEP"

	return headers
}
