package fixhandler

import (
	"bufio"
	"bytes"
	"container/list"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strings"

	logger "github.com/kubescape/go-logger"
	"github.com/mikefarah/yq/v4/pkg/yqlib"
	"gopkg.in/yaml.v3"
)

type NodeRelation int

const (
	sameNodes NodeRelation = iota
	insertedNode
	removedNode
	replacedNode
)

func matchNodes(nodeOne, nodeTwo *yaml.Node) NodeRelation {

	isNewNode := nodeTwo.Line == 0 && nodeTwo.Column == 0
	sameLines := nodeOne.Line == nodeTwo.Line
	sameColumns := nodeOne.Column == nodeTwo.Column

	isSameNode := isSameNode(nodeOne, nodeTwo)

	switch {
	case isSameNode:
		return sameNodes
	case isNewNode:
		return insertedNode
	case sameLines && sameColumns:
		return replacedNode
	default:
		return removedNode
	}
}

func adjustContentLines(contentToAdd *[]contentToAdd, linesSlice *[]string) {
	for contentIdx, content := range *contentToAdd {
		line := content.line

		// Adjust line numbers such that there are no "empty lines or comment lines of next nodes" before them
		for idx := line - 1; idx >= 0; idx-- {
			if isEmptyLineOrComment((*linesSlice)[idx]) {
				(*contentToAdd)[contentIdx].line -= 1
			} else {
				break
			}
		}
	}
}

func adjustFixedListLines(originalList, fixedList *[]nodeInfo) {
	differenceAtTop := (*originalList)[0].node.Line - (*fixedList)[0].node.Line

	if differenceAtTop <= 0 {
		return
	}

	for _, node := range *fixedList {
		// line numbers should not be changed for new nodes.
		if node.node.Line != 0 {
			node.node.Line += differenceAtTop
		}
	}

	return

}

func enocodeIntoYaml(parentNode *yaml.Node, nodeList *[]nodeInfo, tracker int) (string, error) {
	content := make([]*yaml.Node, 0)
	currentNode := (*nodeList)[tracker].node
	content = append(content, currentNode)

	// Add the value in "key-value" pair to construct if the parent is mapping node
	if parentNode.Kind == yaml.MappingNode {
		valueNode := (*nodeList)[tracker+1].node
		content = append(content, valueNode)
	}

	// The parent is added at the top to encode into YAML
	parentForContent := yaml.Node{
		Kind:    parentNode.Kind,
		Content: content,
	}

	buf := new(bytes.Buffer)

	encoder := yaml.NewEncoder(buf)
	encoder.SetIndent(2)

	errorEncoding := encoder.Encode(parentForContent)
	if errorEncoding != nil {
		return "", fmt.Errorf("Error debugging node, %v", errorEncoding.Error())
	}
	errorClosingEncoder := encoder.Close()
	if errorClosingEncoder != nil {
		return "", fmt.Errorf("Error closing encoder: %v", errorClosingEncoder.Error())
	}
	return fmt.Sprintf(`%v`, buf.String()), nil
}

func getContent(parentNode *yaml.Node, nodeList *[]nodeInfo, tracker int) string {
	content, err := enocodeIntoYaml(parentNode, nodeList, tracker)
	if err != nil {
		logger.L().Fatal("Cannot Encode into YAML")
	}

	indentationSpaces := parentNode.Column - 1

	content = indentContent(content, indentationSpaces)

	return strings.TrimSuffix(content, "\n")
}

func indentContent(content string, indentationSpaces int) string {
	indentedContent := ""
	indentSpaces := strings.Repeat(" ", indentationSpaces)

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		indentedContent += (indentSpaces + line + "\n")
	}
	return indentedContent
}

func getLineToInsert(fixInfoMetadata *fixInfoMetadata) int {
	var lineToInsert int
	// Check if lineToInsert is last line
	if fixInfoMetadata.originalListTracker < 0 {
		originalListTracker := int(math.Abs(float64(fixInfoMetadata.originalListTracker)))
		// Storing the negative value of line of last node as a placeholder to determine the last line later.
		lineToInsert = -(*fixInfoMetadata.originalList)[originalListTracker].node.Line
	} else {
		lineToInsert = (*fixInfoMetadata.originalList)[fixInfoMetadata.originalListTracker].node.Line - 1
	}
	return lineToInsert
}

func assignLastLine(contentsToAdd *[]contentToAdd, linesToRemove *[]linesToRemove, linesSlice *[]string) {
	for idx, contentToAdd := range *contentsToAdd {
		if contentToAdd.line < 0 {
			currentLine := int(math.Abs(float64(contentToAdd.line)))
			(*contentsToAdd)[idx].line, _ = getLastLineOfResource(linesSlice, currentLine)
		}
	}

	for idx, lineToRemove := range *linesToRemove {
		if lineToRemove.endLine < 0 {
			endLine, _ := getLastLineOfResource(linesSlice, lineToRemove.startLine)
			(*linesToRemove)[idx].endLine = endLine
		}
	}
}

func getLastLineOfResource(linesSlice *[]string, currentLine int) (int, error) {
	// Get lastlines of all resources...
	lastLinesOfResources := make([]int, 0)
	for lineNumber, lineContent := range *linesSlice {
		if lineContent == "---" {
			for lastLine := lineNumber - 1; lastLine >= 0; lastLine-- {
				if !isEmptyLineOrComment((*linesSlice)[lastLine]) {
					lastLinesOfResources = append(lastLinesOfResources, lastLine+1)
					break
				}
			}
		}
	}

	lastLine := len(*linesSlice)
	for lastLine >= 0 {
		if !isEmptyLineOrComment((*linesSlice)[lastLine-1]) {
			lastLinesOfResources = append(lastLinesOfResources, lastLine)
			break
		} else {
			lastLine--
		}
	}

	// Get last line of the resource we need
	for _, endLine := range lastLinesOfResources {
		if currentLine <= endLine {
			return endLine, nil
		}
	}

	return 0, fmt.Errorf("Provided line is greater than the length of YAML file")
}

func getNodeLine(nodeList *[]nodeInfo, tracker int) int {
	if tracker < len(*nodeList) {
		return (*nodeList)[tracker].node.Line
	} else {
		return -1
	}
}

// Checks if the node is value node in "key-value" pairs of mapping node
func isValueNodeinMapping(node *nodeInfo) bool {
	if node.parent.Kind == yaml.MappingNode && node.index%2 != 0 {
		return true
	}
	return false
}

// Checks if the node is part of single line sequence node and returns the line
func isOneLineSequenceNode(list *[]nodeInfo, currentTracker int) (bool, int) {
	parentNode := (*list)[currentTracker].parent
	if parentNode.Kind != yaml.SequenceNode {
		return false, -1
	}

	var currentNode, prevNode nodeInfo
	currentTracker -= 1

	for (*list)[currentTracker].node != parentNode {
		currentNode = (*list)[currentTracker]
		prevNode = (*list)[currentTracker-1]

		if currentNode.node.Line != prevNode.node.Line {
			return false, -1
		}
		currentTracker -= 1
	}

	parentNodeInfo := (*list)[currentTracker]

	if parentNodeInfo.parent.Kind == yaml.MappingNode {
		keyNodeInfo := (*list)[currentTracker-1]
		if keyNodeInfo.node.Line == parentNode.Line {
			return true, parentNode.Line
		} else {
			return false, -1
		}
	} else {
		if parentNodeInfo.parent.Line == parentNode.Line {
			return true, parentNode.Line
		} else {
			return false, -1
		}
	}
}

// Checks if nodes are of same kind, value, line and column
func isSameNode(nodeOne, nodeTwo *yaml.Node) bool {
	sameLines := nodeOne.Line == nodeTwo.Line
	sameColumns := nodeOne.Column == nodeTwo.Column
	sameKinds := nodeOne.Kind == nodeTwo.Kind
	sameValues := nodeOne.Value == nodeTwo.Value

	return sameKinds && sameValues && sameLines && sameColumns
}

// Checks if the line is empty or a comment
func isEmptyLineOrComment(lineContent string) bool {
	lineContent = strings.TrimSpace(lineContent)
	if lineContent == "" {
		return true
	} else if lineContent[0:1] == "#" {
		return true
	}
	return false
}

func readDocuments(reader io.Reader, decoder yqlib.Decoder) (*list.List, error) {
	err := decoder.Init(reader)
	if err != nil {
		return nil, err
	}
	inputList := list.New()

	var currentIndex uint

	for {
		candidateNode, errorReading := decoder.Decode()

		if errors.Is(errorReading, io.EOF) {
			switch reader := reader.(type) {
			case *os.File:
				safelyCloseFile(reader)
			}
			return inputList, nil
		} else if errorReading != nil {
			return nil, fmt.Errorf("Error Decoding YAML file")
		}

		candidateNode.Document = currentIndex
		candidateNode.EvaluateTogether = true

		inputList.PushBack(candidateNode)

		currentIndex = currentIndex + 1
	}
}

func safelyCloseFile(file *os.File) {
	err := file.Close()
	if err != nil {
		logger.L().Error("Error Closing File")
	}
}

// Remove the entire line and replace it with the sequence node in fixed info. This way,
// the original formatting is lost.
func replaceSingleLineSequence(fixInfoMetadata *fixInfoMetadata, line int) (int, int) {
	originalListTracker := getFirstNodeInLine(fixInfoMetadata.originalList, line)
	fixedListTracker := getFirstNodeInLine(fixInfoMetadata.fixedList, line)

	currentDFSNode := (*fixInfoMetadata.fixedList)[fixedListTracker]
	contentToInsert := getContent(currentDFSNode.parent, fixInfoMetadata.fixedList, fixedListTracker)

	// Remove the Single line
	*fixInfoMetadata.linesToRemove = append(*fixInfoMetadata.linesToRemove, linesToRemove{
		startLine: line,
		endLine:   line,
	})

	// Encode entire Sequence Node and Insert
	*fixInfoMetadata.contentToAdd = append(*fixInfoMetadata.contentToAdd, contentToAdd{
		line:    line,
		content: contentToInsert,
	})

	originalListTracker = updateTracker(fixInfoMetadata.originalList, originalListTracker)
	fixedListTracker = updateTracker(fixInfoMetadata.fixedList, fixedListTracker)

	return originalListTracker, fixedListTracker
}

// Returns the first node in the given line that is not mapping node
func getFirstNodeInLine(list *[]nodeInfo, line int) int {
	tracker := 0

	currentNode := (*list)[tracker].node
	for currentNode.Line != line || currentNode.Kind == yaml.MappingNode {
		tracker += 1
		currentNode = (*list)[tracker].node
	}

	return tracker
}

// To not mess with the line number while inserting, removed lines are not deleted but replaced with "*"
func removeLines(linesToRemove *[]linesToRemove, linesSlice *[]string) {
	var startLine, endLine int
	for _, lineToRemove := range *linesToRemove {
		startLine = lineToRemove.startLine - 1
		endLine = lineToRemove.endLine - 1

		for line := startLine; line <= endLine; line++ {
			lineContent := (*linesSlice)[line]
			// When determining the endLine, empty lines and comments which are not intended to be removed are included.
			// To deal with that, we need to refrain from removing empty lines and comments
			if isEmptyLineOrComment(lineContent) {
				break
			}
			(*linesSlice)[line] = "*"
		}
	}
}

// Skips the current node including it's children in DFS order and returns the new tracker.
func skipCurrentNode(node *yaml.Node, currentTracker int) int {
	updatedTracker := currentTracker + getChildrenCount(node)
	return updatedTracker
}

func getChildrenCount(node *yaml.Node) int {
	totalChildren := 1
	for _, child := range node.Content {
		totalChildren += getChildrenCount(child)
	}
	return totalChildren
}

// The current node along with it's children is skipped and the tracker is moved to next sibling
// of current node. If parent is mapping node, "value" in "key-value" pairs is also skipped.
func updateTracker(nodeList *[]nodeInfo, tracker int) int {
	currentNode := (*nodeList)[tracker]
	var updatedTracker int

	if currentNode.parent.Kind == yaml.MappingNode {
		valueNode := (*nodeList)[tracker+1]
		updatedTracker = skipCurrentNode(valueNode.node, tracker+1)
	} else {
		updatedTracker = skipCurrentNode(currentNode.node, tracker)
	}

	return updatedTracker
}

func getStringFromSlice(yamlLines []string) (fixedYamlString string) {
	return strings.Join(yamlLines, "\n")
}
