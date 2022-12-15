package fixhandler

import (
	"github.com/armosec/armoapi-go/armotypes"
	metav1 "github.com/kubescape/kubescape/v2/core/meta/datastructures/v1"
	"github.com/kubescape/opa-utils/reporthandling"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"gopkg.in/yaml.v3"
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
	DocumentIndex   int
}

// NodeInfo holds extra information about the node
type nodeInfo struct {
	node   *yaml.Node
	parent *yaml.Node

	// position of the node among siblings
	index int
}

// FixInfoMetadata holds the arguments "getFixInfo" function needs to pass to the
// functions it uses
type fixInfoMetadata struct {
	originalList        *[]nodeInfo
	fixedList           *[]nodeInfo
	originalListTracker int
	fixedListTracker    int
	contentToAdd        *[]contentToAdd
	linesToRemove       *[]linesToRemove
}

// ContentToAdd holds the information about where to insert the new changes in the existing yaml file
type contentToAdd struct {
	// Line where the fix should be applied to
	line int
	// Content is a string representation of the YAML node that describes a suggested fix
	content string
}

// LinesToRemove holds the line numbers to remove from the existing yaml file
type linesToRemove struct {
	startLine int
	endLine   int
}

type fileFixInfo struct {
	contentToAdd  []contentToAdd
	linesToRemove []linesToRemove
}

func (fileFixInfo *fileFixInfo) addContent(content contentToAdd) {
	fileFixInfo.contentToAdd = append(fileFixInfo.contentToAdd, content)
}

func (fileFixInfo *fileFixInfo) addLinesToRemove(linesToRemove linesToRemove) {
	fileFixInfo.linesToRemove = append(fileFixInfo.linesToRemove, linesToRemove)
}
