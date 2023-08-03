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

	// Categories to show are hardcoded by ID, so their names are not important. We also want full control over the categories and their order, so a new release of the security checks will not affect the output

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

var mapClusterControlsToCategories = map[string]string{
	"C-0066": controlPlaneCategoryID,
	"C-0088": controlPlaneCategoryID,
	"C-0067": controlPlaneCategoryID,
	"C-0005": controlPlaneCategoryID,
	"C-0262": controlPlaneCategoryID,

	"C-0015": accessControlCategoryID,
	"C-0002": accessControlCategoryID,
	"C-0007": accessControlCategoryID,
	"C-0063": accessControlCategoryID,
	"C-0036": accessControlCategoryID,
	"C-0039": accessControlCategoryID,
	"C-0035": accessControlCategoryID,
	"C-0188": accessControlCategoryID,
	"C-0187": accessControlCategoryID,

	"C-0012": secretsCategoryID,

	"C-0260": networkCategoryID,
	"C-0256": networkCategoryID,

	"C-0038": workloadsCategoryID,
	"C-0041": workloadsCategoryID,
	"C-0048": workloadsCategoryID,
	"C-0057": workloadsCategoryID,
	"C-0013": workloadsCategoryID,
}

var mapWorkloadControlsToCategories = map[string]string{
	"C-0078": supplyChainCategoryID,
	"C-0236": supplyChainCategoryID,
	"C-0237": supplyChainCategoryID,

	"C-0004": resourceManagementCategoryID,
	"C-0050": resourceManagementCategoryID,

	"C-0045": storageCategoryID,
	"C-0048": storageCategoryID,
	"C-0257": storageCategoryID,

	"C-0207": secretsCategoryID,
	"C-0034": secretsCategoryID,
	"C-0012": secretsCategoryID,

	"C-0041": networkCategoryID,
	"C-0260": networkCategoryID,
	"C-0044": networkCategoryID,

	"C-0038": nodeEscapeCategoryID,
	"C-0046": nodeEscapeCategoryID,
	"C-0013": nodeEscapeCategoryID,
	"C-0016": nodeEscapeCategoryID,
	"C-0017": nodeEscapeCategoryID,
	"C-0055": nodeEscapeCategoryID,
	"C-0057": nodeEscapeCategoryID,
}

var mapRepoControlsToCategories = map[string]string{
	"C-0015": accessControlCategoryID,
	"C-0002": accessControlCategoryID,
	"C-0007": accessControlCategoryID,
	"C-0063": accessControlCategoryID,
	"C-0036": accessControlCategoryID,
	"C-0039": accessControlCategoryID,
	"C-0035": accessControlCategoryID,
	"C-0188": accessControlCategoryID,
	"C-0187": accessControlCategoryID,

	"C-0012": secretsCategoryID,

	"C-0260": networkCategoryID,
	"C-0256": networkCategoryID,

	"C-0038": workloadsCategoryID,
	"C-0041": workloadsCategoryID,
	"C-0048": workloadsCategoryID,
	"C-0057": workloadsCategoryID,
	"C-0013": workloadsCategoryID,
}
