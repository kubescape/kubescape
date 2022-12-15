package fixhandler

import (
	"container/list"
	"errors"
	"fmt"
	"io"
	"strings"

	logger "github.com/kubescape/go-logger"
	"github.com/mikefarah/yq/v4/pkg/yqlib"

	"gopkg.in/yaml.v3"
)

func constructDecodedYaml(yamlString string) *[]yaml.Node {
	fileReader := strings.NewReader(yamlString)
	dec := yaml.NewDecoder(fileReader)

	nodes := make([]yaml.Node, 0)
	for {
		var node yaml.Node
		err := dec.Decode(&node)

		nodes = append(nodes, node)

		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			logger.L().Fatal("Cannot decode given document")
		}
	}

	return &nodes
}

func constructFixedYamlNodes(yamlString, yamlExpression string) (*[]yaml.Node, error) {
	preferences := yqlib.ConfiguredYamlPreferences
	preferences.EvaluateTogether = true
	decoder := yqlib.NewYamlDecoder(preferences)

	var allDocuments = list.New()
	reader := strings.NewReader(yamlString)

	fileDocuments, err := readDocuments(reader, decoder)
	if err != nil {
		return nil, err
	}
	allDocuments.PushBackList(fileDocuments)

	allAtOnceEvaluator := yqlib.NewAllAtOnceEvaluator()

	fixedCandidateNodes, err := allAtOnceEvaluator.EvaluateCandidateNodes(yamlExpression, allDocuments)

	if err != nil {
		logger.L().Fatal(fmt.Sprintf("Error fixing YAML, %v", err.Error()))
	}

	fixedNodes := make([]yaml.Node, 0)
	var fixedNode *yaml.Node
	for fixedCandidateNode := fixedCandidateNodes.Front(); fixedCandidateNode != nil; fixedCandidateNode = fixedCandidateNode.Next() {
		fixedNode = fixedCandidateNode.Value.(*yqlib.CandidateNode).Node
		fixedNodes = append(fixedNodes, *fixedNode)
	}

	return &fixedNodes, nil
}

func constructDFSOrder(node *yaml.Node) *[]nodeInfo {
	dfsOrder := make([]nodeInfo, 0)
	constructDFSOrderHelper(node, nil, &dfsOrder, 0)
	return &dfsOrder
}

func matchNodes(nodeOne, nodeTwo *yaml.Node) int {

	isNewNode := nodeTwo.Line == 0 && nodeTwo.Column == 0
	sameLines := nodeOne.Line == nodeTwo.Line
	sameColumns := nodeOne.Column == nodeTwo.Column

	isSameNode := isSameNode(nodeOne, nodeTwo)

	switch {
	case isSameNode:
		return int(sameNodes)
	case isNewNode:
		return int(insertedNode)
	case sameLines && sameColumns:
		return int(replacedNode)
	default:
		return int(removedNode)
	}
}

func getFixInfo(originalRootNodes, fixedRootNodes *[]yaml.Node) (*[]contentToAdd, *[]linesToRemove) {
	contentToAdd := make([]contentToAdd, 0)
	linesToRemove := make([]linesToRemove, 0)

	for idx, _ := range *fixedRootNodes {
		originalList := constructDFSOrder(&(*originalRootNodes)[idx])
		fixedList := constructDFSOrder(&(*fixedRootNodes)[idx])
		nodeContentToAdd, nodeLinesToRemove := getFixInfoHelper(originalList, fixedList)
		contentToAdd = append(contentToAdd, *nodeContentToAdd...)
		linesToRemove = append(linesToRemove, *nodeLinesToRemove...)
	}

	return &contentToAdd, &linesToRemove
}

func getFixInfoHelper(originalList, fixedList *[]nodeInfo) (*[]contentToAdd, *[]linesToRemove) {

	// While obtaining fixedYamlNode, comments and empty lines at the top are ignored.
	// This causes a difference in Line numbers across the tree structure. In order to
	// counter this, line numbers are adjusted in fixed list.
	adjustFixedListLines(originalList, fixedList)

	contentToAdd := make([]contentToAdd, 0)
	linesToRemove := make([]linesToRemove, 0)

	originalListTracker, fixedListTracker := 0, 0

	fixInfoMetadata := &fixInfoMetadata{
		originalList:        originalList,
		fixedList:           fixedList,
		originalListTracker: originalListTracker,
		fixedListTracker:    fixedListTracker,
		contentToAdd:        &contentToAdd,
		linesToRemove:       &linesToRemove,
	}

	for originalListTracker < len(*originalList) && fixedListTracker < len(*fixedList) {
		matchNodeResult := matchNodes((*originalList)[originalListTracker].node, (*fixedList)[fixedListTracker].node)

		fixInfoMetadata.originalListTracker = originalListTracker
		fixInfoMetadata.fixedListTracker = fixedListTracker

		switch matchNodeResult {
		case int(sameNodes):
			originalListTracker += 1
			fixedListTracker += 1

		case int(removedNode):
			originalListTracker, fixedListTracker = addLinesToRemove(fixInfoMetadata)

		case int(insertedNode):
			originalListTracker, fixedListTracker = addLinesToInsert(fixInfoMetadata)

		case int(replacedNode):
			originalListTracker, fixedListTracker = updateLinesToReplace(fixInfoMetadata)
		}
	}

	// Some nodes are still not visited if they are removed at the end of the list
	for originalListTracker < len(*originalList) {
		fixInfoMetadata.originalListTracker = originalListTracker
		originalListTracker, _ = addLinesToRemove(fixInfoMetadata)
	}

	// Some nodes are still not visited if they are inserted at the end of the list
	for fixedListTracker < len(*fixedList) {
		// Use negative index of last node in original list as a placeholder to determine the last line number later
		fixInfoMetadata.originalListTracker = -(len(*originalList) - 1)
		fixInfoMetadata.fixedListTracker = fixedListTracker
		_, fixedListTracker = addLinesToInsert(fixInfoMetadata)
	}

	return &contentToAdd, &linesToRemove

}

// Adds the lines to remove and returns the updated originalListTracker
func addLinesToRemove(fixInfoMetadata *fixInfoMetadata) (int, int) {
	isOneLine, line := isOneLineSequenceNode(fixInfoMetadata.originalList, fixInfoMetadata.originalListTracker)

	if isOneLine {
		// Remove the entire line and replace it with the sequence node in fixed info. This way,
		// the original formatting is lost.
		return replaceSingleLineSequence(fixInfoMetadata, line)
	}

	currentDFSNode := (*fixInfoMetadata.originalList)[fixInfoMetadata.originalListTracker]

	newOriginalListTracker := updateTracker(fixInfoMetadata.originalList, fixInfoMetadata.originalListTracker)
	*fixInfoMetadata.linesToRemove = append(*fixInfoMetadata.linesToRemove, linesToRemove{
		startLine: currentDFSNode.node.Line,
		endLine:   getNodeLine(fixInfoMetadata.originalList, newOriginalListTracker),
	})

	return newOriginalListTracker, fixInfoMetadata.fixedListTracker
}

// Adds the lines to insert and returns the updated fixedListTracker
func addLinesToInsert(fixInfoMetadata *fixInfoMetadata) (int, int) {

	isOneLine, line := isOneLineSequenceNode(fixInfoMetadata.fixedList, fixInfoMetadata.fixedListTracker)

	if isOneLine {
		return replaceSingleLineSequence(fixInfoMetadata, line)
	}

	currentDFSNode := (*fixInfoMetadata.fixedList)[fixInfoMetadata.fixedListTracker]

	lineToInsert := getLineToInsert(fixInfoMetadata)
	contentToInsert := constructContent(currentDFSNode.parent, fixInfoMetadata.fixedList, fixInfoMetadata.fixedListTracker)

	newFixedTracker := updateTracker(fixInfoMetadata.fixedList, fixInfoMetadata.fixedListTracker)

	*fixInfoMetadata.contentToAdd = append(*fixInfoMetadata.contentToAdd, contentToAdd{
		line:    lineToInsert,
		content: contentToInsert,
	})

	return fixInfoMetadata.originalListTracker, newFixedTracker
}

// Adds the lines to remove and insert and updates the fixedListTracker and originalListTracker
func updateLinesToReplace(fixInfoMetadata *fixInfoMetadata) (int, int) {

	isOneLine, line := isOneLineSequenceNode(fixInfoMetadata.fixedList, fixInfoMetadata.fixedListTracker)

	if isOneLine {
		return replaceSingleLineSequence(fixInfoMetadata, line)
	}

	currentDFSNode := (*fixInfoMetadata.fixedList)[fixInfoMetadata.fixedListTracker]

	// If only the value node is changed, entire "key-value" pair is replaced
	if isValueNodeinMapping(&currentDFSNode) {
		fixInfoMetadata.originalListTracker -= 1
		fixInfoMetadata.fixedListTracker -= 1
	}

	addLinesToRemove(fixInfoMetadata)
	updatedOriginalTracker, updatedFixedTracker := addLinesToInsert(fixInfoMetadata)

	return updatedOriginalTracker, updatedFixedTracker
}

func removeNewLinesAtTheEnd(yamlLines []string) []string {
	for idx := 1; idx < len(yamlLines); idx++ {
		if yamlLines[len(yamlLines)-idx] != "\n" {
			yamlLines = yamlLines[:len(yamlLines)-idx+1]
			break
		}
	}
	return yamlLines
}

func getFixedYamlLines(yamlLines []string, contentToAdd *[]contentToAdd, linesToRemove *[]linesToRemove) (fixedYamlLines []string) {

	// Determining last line requires original yaml lines slice. The placeholder for last line is replaced with the real last line
	assignLastLine(contentToAdd, linesToRemove, &yamlLines)

	removeLines(linesToRemove, &yamlLines)

	fixedYamlLines = make([]string, 0)
	lineIdx, lineToAddIdx := 1, 0

	// Ideally, new node is inserted at line before the next node in DFS order. But, when the previous line contains a
	// comment or empty line, we need to insert new nodes before them.
	adjustContentLines(contentToAdd, &yamlLines)

	for lineToAddIdx < len(*contentToAdd) {
		for lineIdx <= (*contentToAdd)[lineToAddIdx].line {
			// Check if the current line is not removed
			if yamlLines[lineIdx-1] != "*" {
				fixedYamlLines = append(fixedYamlLines, yamlLines[lineIdx-1])
			}
			lineIdx += 1
		}

		content := (*contentToAdd)[lineToAddIdx].content
		fixedYamlLines = append(fixedYamlLines, content)

		lineToAddIdx += 1
	}

	for lineIdx <= len(yamlLines) {
		if yamlLines[lineIdx-1] != "*" {
			fixedYamlLines = append(fixedYamlLines, yamlLines[lineIdx-1])
		}
		lineIdx += 1
	}

	fixedYamlLines = removeNewLinesAtTheEnd(fixedYamlLines)

	return fixedYamlLines
}
