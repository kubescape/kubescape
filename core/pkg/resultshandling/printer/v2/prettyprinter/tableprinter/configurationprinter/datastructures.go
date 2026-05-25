package configurationprinter

import (
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

type CategoryControls struct {
	CategoryName     string
	controlSummaries []reportsummary.IControlSummary
	Status           apis.ScanningStatus
}

type CategoryType string

const (
	TypeCounting CategoryType = "COUNTING"
	TypeStatus   CategoryType = "STATUS"

	// The lists below pin the preferred *render order* for well-known
	// categories. Any category present in the report but absent here is still
	// rendered (appended after the known ones, alphabetically) so controls
	// added to the rego library are never silently dropped from the table.

	// cluster scan categories
	controlPlaneCategoryID  = "Cat-1"
	accessControlCategoryID = "Cat-2"
	secretsCategoryID       = "Cat-3"
	networkCategoryID       = "Cat-4"
	workloadsCategoryID     = "Cat-5"

	// workload scan categories
	supplyChainCategoryID        = "Cat-6"
	resourceManagementCategoryID = "Cat-7"
	storageCategoryID            = "Cat-8"
	nodeEscapeCategoryID         = "Cat-9"
)

var clusterCategoriesDisplayOrder = []string{
	controlPlaneCategoryID,
	accessControlCategoryID,
	secretsCategoryID,
	networkCategoryID,
	workloadsCategoryID,
}

var repoCategoriesDisplayOrder = []string{
	workloadsCategoryID,
	accessControlCategoryID,
	secretsCategoryID,
	networkCategoryID,
}

var workloadCategoriesDisplayOrder = []string{
	supplyChainCategoryID,
	resourceManagementCategoryID,
	storageCategoryID,
	secretsCategoryID,
	networkCategoryID,
	nodeEscapeCategoryID,
}

// map categories to table type. Each table type has a different display
var mapCategoryToType = map[string]CategoryType{
	controlPlaneCategoryID:  TypeStatus,
	accessControlCategoryID: TypeCounting,
	secretsCategoryID:       TypeCounting,
	networkCategoryID:       TypeCounting,
	workloadsCategoryID:     TypeCounting,
}

