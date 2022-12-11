package fixhandler

import (
	"bufio"
	"bytes"
	"container/list"
	"fmt"
	"io/ioutil"
	"math"
	"os"

	logger "github.com/kubescape/go-logger"
	"github.com/mikefarah/yq/v4/pkg/yqlib"

	"gopkg.in/yaml.v3"
)

func getDecodedYaml(filepath string) *yaml.Node {
	file, err := ioutil.ReadFile(filepath)
	if err != nil {
		logger.L().Fatal("Cannot read file")
	}
	fileReader := bytes.NewReader(file)
	dec := yaml.NewDecoder(fileReader)

	var node yaml.Node
	err = dec.Decode(&node)

	if err != nil {
		logger.L().Fatal("Cannot Decode Yaml")
	}

	return &node
}

func getFixedYamlNode(filePath, yamlExpression string) *yaml.Node {
	preferences := yqlib.ConfiguredYamlPreferences
	preferences.EvaluateTogether = true
	decoder := yqlib.NewYamlDecoder(preferences)

	var allDocuments = list.New()
	reader, err := getNewReader(filePath)
	if err != nil {
		return &yaml.Node{}
	}

	fileDocuments, err := readDocuments(reader, filePath, 0, decoder)
	if err != nil {
		return &yaml.Node{}
	}
	allDocuments.PushBackList(fileDocuments)

	allAtOnceEvaluator := yqlib.NewAllAtOnceEvaluator()

	matches, err := allAtOnceEvaluator.EvaluateCandidateNodes(yamlExpression, allDocuments)

	if err != nil {
		logger.L().Fatal(fmt.Sprintf("Error fixing YAML, %v", err.Error()))
	}

	return matches.Front().Value.(*yqlib.CandidateNode).Node
}

func getDFSOrder(node *yaml.Node) *[]NodeInfo {
	dfsOrder := make([]NodeInfo, 0)
	getDFSOrderHelper(node, nil, &dfsOrder, 0)
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

func getFixInfo(originalList, fixedList *[]NodeInfo) (*[]ContentToAdd, *[]ContentToRemove) {
	contentToAdd := make([]ContentToAdd, 0)
	linesToRemove := make([]ContentToRemove, 0)

	originalListTracker, fixedListTracker := 0, 0

	fixInfoMetadata := &FixInfoMetadata{
		originalList:        originalList,
		fixedList:           fixedList,
		originalListTracker: originalListTracker,
		fixedListTracker:    fixedListTracker,
		contentToAdd:        &contentToAdd,
		contentToRemove:     &linesToRemove,
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

	for originalListTracker < len(*originalList) {
		fixInfoMetadata.originalListTracker = originalListTracker
		fixInfoMetadata.fixedListTracker = len(*fixedList) - 1
		originalListTracker, _ = addLinesToRemove(fixInfoMetadata)
	}

	for fixedListTracker < len(*fixedList) {
		fixInfoMetadata.originalListTracker = int(math.Inf(1))
		fixInfoMetadata.fixedListTracker = fixedListTracker
		_, fixedListTracker = addLinesToInsert(fixInfoMetadata)
	}

	return &contentToAdd, &linesToRemove

}

// Adds the lines to remove and returns the updated originalListTracker
func addLinesToRemove(fixInfoMetadata *FixInfoMetadata) (int, int) {
	currentDFSNode := (*fixInfoMetadata.originalList)[fixInfoMetadata.originalListTracker]

	isOneLine, line := isOneLineSequenceNode(fixInfoMetadata.originalList, fixInfoMetadata.originalListTracker)

	if isOneLine {
		// Remove the entire line and replace it with the sequence node in fixed info. This way,
		// the original formatting is lost.
		return replaceSingleLineSequence(fixInfoMetadata, line)
	}

	newTracker := updateTracker(fixInfoMetadata.originalList, fixInfoMetadata.originalListTracker)
	*fixInfoMetadata.contentToRemove = append(*fixInfoMetadata.contentToRemove, ContentToRemove{
		startLine: currentDFSNode.node.Line,
		endLine:   getNodeLine(fixInfoMetadata.originalList, newTracker) - 1,
	})

	return newTracker, fixInfoMetadata.fixedListTracker
}

// Adds the lines to insert and returns the updated fixedListTracker
func addLinesToInsert(fixInfoMetadata *FixInfoMetadata) (int, int) {
	currentDFSNode := (*fixInfoMetadata.fixedList)[fixInfoMetadata.fixedListTracker]

	isOneLine, line := isOneLineSequenceNode(fixInfoMetadata.fixedList, fixInfoMetadata.fixedListTracker)

	if isOneLine {
		return replaceSingleLineSequence(fixInfoMetadata, line)
	}

	var lineToInsert int
	if fixInfoMetadata.originalListTracker == int(math.Inf(1)) {
		lineToInsert = int(math.Inf(1))
	} else {
		lineToInsert = (*fixInfoMetadata.originalList)[fixInfoMetadata.originalListTracker].node.Line - 1
	}

	contentToInsert := getContent(currentDFSNode.parent, fixInfoMetadata.fixedList, fixInfoMetadata.fixedListTracker)

	newFixedTracker := updateTracker(fixInfoMetadata.fixedList, fixInfoMetadata.fixedListTracker)

	*fixInfoMetadata.contentToAdd = append(*fixInfoMetadata.contentToAdd, ContentToAdd{
		Line:    lineToInsert,
		Content: contentToInsert,
	})

	return fixInfoMetadata.originalListTracker, newFixedTracker
}

// Adds the lines to remove and insert and updates the fixedListTracker and originalListTracker
func updateLinesToReplace(fixInfoMetadata *FixInfoMetadata) (int, int) {
	currentDFSNode := (*fixInfoMetadata.fixedList)[fixInfoMetadata.fixedListTracker]

	isOneLine, line := isOneLineSequenceNode(fixInfoMetadata.fixedList, fixInfoMetadata.fixedListTracker)

	if isOneLine {
		return replaceSingleLineSequence(fixInfoMetadata, line)
	}

	if isValueNodeinMapping(&currentDFSNode) {
		fixInfoMetadata.originalListTracker -= 1
		fixInfoMetadata.fixedListTracker -= 1
	}

	updatedOriginalTracker, updatedFixedTracker := addLinesToRemove(fixInfoMetadata)
	updatedOriginalTracker, updatedFixedTracker = addLinesToInsert(fixInfoMetadata)

	return updatedOriginalTracker, updatedFixedTracker
}

func applyFixesToFile(filePath string, contentToAdd *[]ContentToAdd, linesToRemove *[]ContentToRemove, contentAtHead string) error {
	linesSlice, err := getLinesSlice(filePath)

	if err != nil {
		return err
	}

	if err := os.Truncate(filePath, 0); err != nil {
		return err
	}

	file, err := os.OpenFile(filePath, os.O_RDWR, 0644)
	if err != nil {
		return err
	}

	defer func() error {
		if err := file.Close(); err != nil {
			return err
		}
		return nil
	}()

	removeLines(linesToRemove, &linesSlice)

	writer := bufio.NewWriter(file)
	lineIdx, lineToAddIdx := 1, 0

	// Insert the comments and lines at the head removed initially.
	writer.WriteString(contentAtHead)

	// Ideally, new node is inserted at line before the next node in DFS order. But, when the previous line contains a
	// comment or empty line, we need to insert new nodes before them.
	adjustContentLines(contentToAdd, &linesSlice)

	for lineToAddIdx < len(*contentToAdd) {
		for lineIdx <= (*contentToAdd)[lineToAddIdx].Line {
			if linesSlice[lineIdx-1] != "*" {
				_, err := writer.WriteString(linesSlice[lineIdx-1] + "\n")
				if err != nil {
					return err
				}
			}
			lineIdx += 1
		}

		writeContentToAdd(writer, (*contentToAdd)[lineToAddIdx].Content)
		lineToAddIdx += 1
	}

	for lineIdx <= len(linesSlice) {
		if linesSlice[lineIdx-1] != "*" {
			_, err := writer.WriteString(linesSlice[lineIdx-1] + "\n")
			if err != nil {
				return err
			}
		}
		lineIdx += 1
	}

	writer.Flush()
	return nil
}
