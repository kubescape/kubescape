package fixhandler

import (
	"sort"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
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
	YamlExpressions map[string]armotypes.FixPath
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

// contentToAdd holds the information about where to insert the new changes in the existing yaml file
type contentToAdd struct {
	// Line where the fix should be applied to
	line int
	// Content is a string representation of the YAML node that describes a suggested fix
	content string
}

func withNewline(content, targetNewline string) string {
	replaceNewlines := map[string]bool{
		unixNewline:    true,
		windowsNewline: true,
		oldMacNewline:  true,
	}
	replaceNewlines[targetNewline] = false

	newlinesToReplace := make([]string, len(replaceNewlines))
	i := 0
	for k := range replaceNewlines {
		newlinesToReplace[i] = k
		i++
	}

	// To ensure that we fully replace Windows newlines (CR LF), and not
	// corrupt them into two new newlines (CR CR or LF LF) by partially
	// replacing either CR or LF, we have to ensure we replace longer
	// Windows newlines first
	sort.Slice(newlinesToReplace, func(i int, j int) bool {
		return len(newlinesToReplace[i]) > len(newlinesToReplace[j])
	})

	// strings.Replacer takes a flat list of (oldVal, newVal) pairs, so we
	// need to allocate twice the space and assign accordingly
	newlinesOldNew := make([]string, 2*len(replaceNewlines))
	i = 0
	for _, nl := range newlinesToReplace {
		newlinesOldNew[2*i] = nl
		newlinesOldNew[2*i+1] = targetNewline
		i++
	}

	replacer := strings.NewReplacer(newlinesOldNew...)
	return replacer.Replace(content)
}

// Content returns the content that will be added, separated by the explicitly
// provided `targetNewline`
func (c *contentToAdd) Content(targetNewline string) string {
	return withNewline(c.content, targetNewline)
}

// LinesToRemove holds the line numbers to remove from the existing yaml file
type linesToRemove struct {
	startLine int
	endLine   int
}

type fileFixInfo struct {
	contentsToAdd *[]contentToAdd
	linesToRemove *[]linesToRemove
}
