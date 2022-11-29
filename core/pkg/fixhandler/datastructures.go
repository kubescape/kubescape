package fixhandler

import (
	"github.com/armosec/armoapi-go/armotypes"
	metav1 "github.com/kubescape/kubescape/v2/core/meta/datastructures/v1"
	"github.com/kubescape/opa-utils/reporthandling"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

// FixHandler is a struct that holds the information of the report to be fixed
type FixHandler struct {
	fixInfo       *metav1.FixInfo
	reportObj     *reporthandlingv2.PostureReport
	localBasePath string
}

// ResourceFixInfo is a struct that holds the information about the resource that needs to be fixed
type ResourceFixInfo struct {
	YamlExpressions map[string]*armotypes.FixPath
	Resource        *reporthandling.Resource
	FilePath        string
}

// LineAndContentToAdd holds the information about where to insert the new changes in the existing yaml file
type LineAndContentToAdd struct {
	Line    int
	Content string
}
