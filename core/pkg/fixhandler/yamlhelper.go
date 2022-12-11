package fixhandler

import (
	"bufio"
	"bytes"
	"container/list"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"strings"

	logger "github.com/kubescape/go-logger"
	"github.com/mikefarah/yq/v4/pkg/yqlib"
	"gopkg.in/yaml.v3"
)

const (
	sameNodes = iota
	insertedNode
	removedNode
	replacedNode
)

func adjustContentLines(contentToAdd *[]ContentToAdd, linesSlice *[]string) {
	for contentIdx, content := range *contentToAdd {
		line := content.Line

		// Update Line number to last line if their value is math.Inf
		if line == int(math.Inf(1)) {
			(*contentToAdd)[contentIdx].Line = len(*linesSlice)
			continue
		}

		// Adjust line numbers such that there are no "empty lines or comment lines of next nodes" before them
		for idx := line - 1; idx >= 0; idx-- {
			if isEmptyLineOrComment((*linesSlice)[idx]) {
				(*contentToAdd)[contentIdx].Line -= 1
			} else {
				break
			}
		}
	}
}

func constructDFSOrderHelper(node *yaml.Node, parent *yaml.Node, dfsOrder *[]NodeInfo, index int) {
	dfsNode := NodeInfo{
		node:   node,
		parent: parent,
		index:  index,
	}
	*dfsOrder = append(*dfsOrder, dfsNode)

	for idx, child := range node.Content {
		constructDFSOrderHelper(child, node, dfsOrder, idx)
	}
}

func constructNewReader(filename string) (io.Reader, error) {
	var reader *bufio.Reader
	if filename == "-" {
		reader = bufio.NewReader(os.Stdin)
	} else {
		// ignore CWE-22 gosec issue - that's more targeted for http based apps that run in a public directory,
		// and ensuring that it's not possible to give a path to a file outside thar directory.
		file, err := os.Open(filename) // #nosec
		if err != nil {
			return nil, err
		}
		reader = bufio.NewReader(file)
	}
	return reader, nil
}

func enocodeIntoYaml(parentNode *yaml.Node, nodeList *[]NodeInfo, tracker int) (string, error) {
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

func constructContent(parentNode *yaml.Node, nodeList *[]NodeInfo, tracker int) string {
	content, err := enocodeIntoYaml(parentNode, nodeList, tracker)
	if err != nil {
		logger.L().Fatal("Cannot Encode into YAML")
	}

	indentationSpaces := parentNode.Column - 1

	content = indentContent(content, indentationSpaces)

	return content
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

// Get the lines of existing yaml in a slice
func getLinesSlice(filePath string) ([]string, error) {
	lineSlice := make([]string, 0)

	file, err := os.Open(filePath)
	if err != nil {
		logger.L().Fatal(fmt.Sprintf("Cannot open file %s", filePath))
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		lineSlice = append(lineSlice, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
		return nil, err
	}

	return lineSlice, err
}

func getLineToInsert(fixInfoMetadata *FixInfoMetadata) int {
	var lineToInsert int
	if fixInfoMetadata.originalListTracker == int(math.Inf(1)) {
		lineToInsert = int(math.Inf(1))
	} else {
		lineToInsert = (*fixInfoMetadata.originalList)[fixInfoMetadata.originalListTracker].node.Line - 1
	}
	return lineToInsert
}

func getNodeLine(nodeList *[]NodeInfo, tracker int) int {
	if tracker < len(*nodeList) {
		return (*nodeList)[tracker].node.Line
	} else {
		return int(math.Inf(1))
	}
}

// Checks if the node is value node in "key-value" pairs of mapping node
func isValueNodeinMapping(node *NodeInfo) bool {
	if node.parent.Kind == yaml.MappingNode && node.index%2 != 0 {
		return true
	}
	return false
}

// Checks if the node is part of single line sequence node and returns the line
func isOneLineSequenceNode(list *[]NodeInfo, currentTracker int) (bool, int) {
	parentNode := (*list)[currentTracker].parent
	if parentNode.Kind != yaml.SequenceNode {
		return false, -1
	}

	var currentNode, prevNode NodeInfo
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

func readDocuments(reader io.Reader, filename string, fileIndex int, decoder yqlib.Decoder) (*list.List, error) {
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
			return nil, fmt.Errorf("bad file '%v': %w", filename, errorReading)
		}
		candidateNode.Document = currentIndex
		candidateNode.Filename = filename
		candidateNode.FileIndex = fileIndex
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
func replaceSingleLineSequence(fixInfoMetadata *FixInfoMetadata, line int) (int, int) {
	originalListTracker := getFirstNodeInLine(fixInfoMetadata.originalList, line)
	fixedListTracker := getFirstNodeInLine(fixInfoMetadata.fixedList, line)

	currentDFSNode := (*fixInfoMetadata.fixedList)[fixedListTracker]
	contentToInsert := constructContent(currentDFSNode.parent, fixInfoMetadata.fixedList, fixedListTracker)

	// Remove the Single line
	*fixInfoMetadata.linesToRemove = append(*fixInfoMetadata.linesToRemove, LinesToRemove{
		startLine: line,
		endLine:   line,
	})

	// Encode entire Sequence Node and Insert
	*fixInfoMetadata.contentToAdd = append(*fixInfoMetadata.contentToAdd, ContentToAdd{
		Line:    line,
		Content: contentToInsert,
	})

	originalListTracker = updateTracker(fixInfoMetadata.originalList, originalListTracker)
	fixedListTracker = updateTracker(fixInfoMetadata.fixedList, fixedListTracker)

	return originalListTracker, fixedListTracker
}

// Returns the first node in the given line that is not mapping node
func getFirstNodeInLine(list *[]NodeInfo, line int) int {
	tracker := 0

	currentNode := (*list)[tracker].node
	for currentNode.Line != line || currentNode.Kind == yaml.MappingNode {
		tracker += 1
		currentNode = (*list)[tracker].node
	}

	return tracker
}

// To not mess with the line number while inserting, removed lines are not deleted but replaced with "*"
func removeLines(linesToRemove *[]LinesToRemove, linesSlice *[]string) {
	var startLine, endLine int
	for _, lineToRemove := range *linesToRemove {
		startLine = lineToRemove.startLine - 1

		if lineToRemove.endLine < len(*linesSlice) {
			endLine = lineToRemove.endLine
		} else {
			// When removing until the end of file and unsure of length of file, endLine is set to Infinity.
			// In that case, endLine is read as last line of linesSlice
			endLine = len(*linesSlice) - 1
		}

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

// Truncates the comments and empty lines at the top of the file and
// returns the truncated content
func truncateContentAtHead(filePath string) (string, error) {
	var contentAtHead string

	linesSlice, err := getLinesSlice(filePath)

	if err != nil {
		return "", err
	}

	if err := os.Truncate(filePath, 0); err != nil {
		return "", err
	}

	file, err := os.OpenFile(filePath, os.O_RDWR, 0644)
	if err != nil {
		return "", err
	}

	defer func() error {
		if err := file.Close(); err != nil {
			return err
		}
		return nil
	}()

	lineIdx := 0

	for lineIdx < len(linesSlice) {
		if isEmptyLineOrComment(linesSlice[lineIdx]) {
			contentAtHead += (linesSlice[lineIdx] + "\n")
			lineIdx += 1
		} else {
			break
		}
	}

	writer := bufio.NewWriter(file)

	for lineIdx < len(linesSlice) {
		_, err = writer.WriteString(linesSlice[lineIdx] + "\n")
		if err != nil {
			return "", err
		}
		lineIdx += 1
	}

	writer.Flush()
	return contentAtHead, nil
}

// The current node along with it's children is skipped and the tracker is moved to next sibling
// of current node. If parent is mapping node, "value" in "key-value" pairs is also skipped.
func updateTracker(nodeList *[]NodeInfo, tracker int) int {
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
