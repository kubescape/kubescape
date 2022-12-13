package fixhandler

import (
	"bufio"
	"bytes"
	"container/list"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	logger "github.com/kubescape/go-logger"
	"github.com/mikefarah/yq/v4/pkg/yqlib"

	"gopkg.in/yaml.v3"
)

func constructDecodedYaml(filepath string) *[]yaml.Node {
	file, err := ioutil.ReadFile(filepath)
	if err != nil {
		logger.L().Fatal("Cannot read file")
	}
	fileReader := bytes.NewReader(file)
	dec := yaml.NewDecoder(fileReader)

	nodes := make([]yaml.Node, 0)
	for {
		var node yaml.Node
		err = dec.Decode(&node)
		nodes = append(nodes, node)

		// break the loop in case of EOF
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			panic(err)
		}
	}

	return &nodes
}

func constructFixedYamlNodes(filePath, yamlExpression string) (*[]yaml.Node, error) {
	preferences := yqlib.ConfiguredYamlPreferences
	preferences.EvaluateTogether = true
	decoder := yqlib.NewYamlDecoder(preferences)

	var allDocuments = list.New()
	reader, err := constructNewReader(filePath)
	if err != nil {
		return nil, err
	}

	fileDocuments, err := readDocuments(reader, filePath, 0, decoder)
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

func constructDFSOrder(node *yaml.Node) *[]NodeInfo {
	dfsOrder := make([]NodeInfo, 0)
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

func getFixInfo(originalList, fixedList *[]NodeInfo) (*[]ContentToAdd, *[]LinesToRemove) {

	// While obtaining fixedYamlNode, comments and empty lines at the top are ignored.
	// This causes a difference in Line numbers across the tree structure. In order to
	// counter this, line numbers are adjusted in fixed list.
	adjustFixedListLines(originalList, fixedList)

	contentToAdd := make([]ContentToAdd, 0)
	linesToRemove := make([]LinesToRemove, 0)

	originalListTracker, fixedListTracker := 0, 0

	fixInfoMetadata := &FixInfoMetadata{
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
func addLinesToRemove(fixInfoMetadata *FixInfoMetadata) (int, int) {
	isOneLine, line := isOneLineSequenceNode(fixInfoMetadata.originalList, fixInfoMetadata.originalListTracker)

	if isOneLine {
		// Remove the entire line and replace it with the sequence node in fixed info. This way,
		// the original formatting is lost.
		return replaceSingleLineSequence(fixInfoMetadata, line)
	}

	currentDFSNode := (*fixInfoMetadata.originalList)[fixInfoMetadata.originalListTracker]

	newOriginalListTracker := updateTracker(fixInfoMetadata.originalList, fixInfoMetadata.originalListTracker)
	*fixInfoMetadata.linesToRemove = append(*fixInfoMetadata.linesToRemove, LinesToRemove{
		StartLine: currentDFSNode.node.Line,
		EndLine:   getNodeLine(fixInfoMetadata.originalList, newOriginalListTracker),
	})

	return newOriginalListTracker, fixInfoMetadata.fixedListTracker
}

// Adds the lines to insert and returns the updated fixedListTracker
func addLinesToInsert(fixInfoMetadata *FixInfoMetadata) (int, int) {

	isOneLine, line := isOneLineSequenceNode(fixInfoMetadata.fixedList, fixInfoMetadata.fixedListTracker)

	if isOneLine {
		return replaceSingleLineSequence(fixInfoMetadata, line)
	}

	currentDFSNode := (*fixInfoMetadata.fixedList)[fixInfoMetadata.fixedListTracker]

	lineToInsert := getLineToInsert(fixInfoMetadata)
	contentToInsert := constructContent(currentDFSNode.parent, fixInfoMetadata.fixedList, fixInfoMetadata.fixedListTracker)

	newFixedTracker := updateTracker(fixInfoMetadata.fixedList, fixInfoMetadata.fixedListTracker)

	*fixInfoMetadata.contentToAdd = append(*fixInfoMetadata.contentToAdd, ContentToAdd{
		Line:    lineToInsert,
		Content: contentToInsert,
	})

	return fixInfoMetadata.originalListTracker, newFixedTracker
}

// Adds the lines to remove and insert and updates the fixedListTracker and originalListTracker
func updateLinesToReplace(fixInfoMetadata *FixInfoMetadata) (int, int) {

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

func applyFixesToFile(filePath string, contentToAdd *[]ContentToAdd, linesToRemove *[]LinesToRemove) error {
	// Read contents of the file line by line and store in a list
	linesSlice, err := getLinesSlice(filePath)

	if err != nil {
		return err
	}

	// Determining last line required lineSlice. The placeholder for last line is replaced with the real last line
	assignLastLine(contentToAdd, linesToRemove, &linesSlice)

	// Clear the current content of file
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

	// Ideally, new node is inserted at line before the next node in DFS order. But, when the previous line contains a
	// comment or empty line, we need to insert new nodes before them.
	adjustContentLines(contentToAdd, &linesSlice)

	for lineToAddIdx < len(*contentToAdd) {
		for lineIdx <= (*contentToAdd)[lineToAddIdx].Line {
			// Check if the current line is not removed
			if linesSlice[lineIdx-1] != "*" {
				_, err := writer.WriteString(linesSlice[lineIdx-1] + "\n")
				if err != nil {
					return err
				}
			}
			lineIdx += 1
		}

		content := (*contentToAdd)[lineToAddIdx].Content
		writer.WriteString(content)

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
