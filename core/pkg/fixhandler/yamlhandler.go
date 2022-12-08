package fixhandler

import (
	"bufio"
	"bytes"
	"container/list"
	"fmt"
	"io/ioutil"
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
	sameKinds := nodeOne.Kind == nodeTwo.Kind
	sameValues := nodeOne.Value == nodeTwo.Value

	isSameNode := sameKinds && sameValues && sameLines && sameColumns

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
			originalListTracker = addLinesToRemove(fixInfoMetadata)

		case int(insertedNode):
			fixedListTracker = addLinesToInsert(fixInfoMetadata)

		case int(replacedNode):
			originalListTracker, fixedListTracker = updateLinesToReplace(fixInfoMetadata)
		}
	}

	for originalListTracker < len(*originalList) {
		fixInfoMetadata.originalListTracker = originalListTracker
		fixInfoMetadata.fixedListTracker = len(*fixedList) - 1
		originalListTracker = addLinesToRemove(fixInfoMetadata)
	}

	for fixedListTracker < len(*fixedList) {
		fixInfoMetadata.originalListTracker = len(*originalList) - 1
		fixInfoMetadata.fixedListTracker = fixedListTracker
		fixedListTracker = addLinesToInsert(fixInfoMetadata)
	}

	return &contentToAdd, &linesToRemove

}

// Adds the lines to remove and returns the updated originalListTracker
func addLinesToRemove(fixInfoMetadata *FixInfoMetadata) int {
	currentDFSNode := (*fixInfoMetadata.originalList)[fixInfoMetadata.originalListTracker]
	newTracker := updateTracker(fixInfoMetadata.originalList, fixInfoMetadata.originalListTracker)
	*fixInfoMetadata.contentToRemove = append(*fixInfoMetadata.contentToRemove, ContentToRemove{
		startLine: currentDFSNode.node.Line,
		endLine:   getNodeLine(fixInfoMetadata.originalList, newTracker) - 1,
	})

	return newTracker
}

// Adds the lines to insert and returns the updated fixedListTracker
func addLinesToInsert(fixInfoMetadata *FixInfoMetadata) int {
	currentDFSNode := (*fixInfoMetadata.fixedList)[fixInfoMetadata.fixedListTracker]
	lineToInsert := (*fixInfoMetadata.originalList)[fixInfoMetadata.originalListTracker].node.Line - 1
	contentToInsert := getContent(currentDFSNode.parent, fixInfoMetadata.fixedList, fixInfoMetadata.fixedListTracker)

	newTracker := updateTracker(fixInfoMetadata.fixedList, fixInfoMetadata.fixedListTracker)

	*fixInfoMetadata.contentToAdd = append(*fixInfoMetadata.contentToAdd, ContentToAdd{
		Line:    lineToInsert,
		Content: contentToInsert,
	})

	return newTracker
}

// Adds the lines to remove and insert and updates the fixedListTracker and originalListTracker
func updateLinesToReplace(fixInfoMetadata *FixInfoMetadata) (int, int) {
	currentDFSNode := (*fixInfoMetadata.fixedList)[fixInfoMetadata.fixedListTracker]

	if isValueNodeinMapping(&currentDFSNode) {
		fixInfoMetadata.originalListTracker -= 1
		fixInfoMetadata.fixedListTracker -= 1
	}

	updatedOriginalTracker := addLinesToRemove(fixInfoMetadata)
	updatedFixedTracker := addLinesToInsert(fixInfoMetadata)

	return updatedOriginalTracker, updatedFixedTracker
}

func applyFixesToFile(filePath string, lineAndContentsToAdd *[]ContentToAdd, linesToRemove *[]ContentToRemove) (cmdError error) {
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
	lineIdx, lineToAddIdx := 0, 0

	for lineToAddIdx < len(*lineAndContentsToAdd) {
		for lineIdx <= (*lineAndContentsToAdd)[lineToAddIdx].Line {
			if linesSlice[lineIdx] == "*" {
				continue
			}
			_, err := writer.WriteString(linesSlice[lineIdx] + "\n")
			if err != nil {
				return err
			}
			lineIdx += 1
		}

		writeContentToAdd(writer, (*lineAndContentsToAdd)[lineToAddIdx].Content)
		lineToAddIdx += 1
	}

	for lineIdx < len(linesSlice) {
		if linesSlice[lineIdx] == "*" {
			continue
		}
		_, err := writer.WriteString(linesSlice[lineIdx] + "\n")
		if err != nil {
			return err
		}
		lineIdx += 1
	}

	writer.Flush()
	return nil
}
