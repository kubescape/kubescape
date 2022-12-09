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

func getNewReader(filename string) (io.Reader, error) {
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

func getDFSOrderHelper(node *yaml.Node, parent *yaml.Node, dfsOrder *[]NodeInfo, index int) {
	dfsNode := NodeInfo{
		node:   node,
		parent: parent,
		index:  index,
	}
	*dfsOrder = append(*dfsOrder, dfsNode)

	for idx, child := range node.Content {
		getDFSOrderHelper(child, node, dfsOrder, idx)
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

// Moves the tracker to the parent of given node
func traceBackToParent(dfsOrder *[]NodeInfo, currentTracker int) int {
	parentNode := (*dfsOrder)[currentTracker].parent
	parentIdx := currentTracker - 1
	for parentIdx >= 0 {
		if (*dfsOrder)[parentIdx].node == parentNode {
			return parentIdx
		}
		parentIdx -= 1
	}
	return 0
}

// Checks if the node is value node in "key-value" pairs of mapping node
func isValueNodeinMapping(dfsNode *NodeInfo) bool {
	if dfsNode.parent.Kind == yaml.MappingNode && dfsNode.index%2 != 0 {
		return true
	}
	return false
}

func updateTracker(dfsOrder *[]NodeInfo, tracker int) int {
	currentDFSNode := (*dfsOrder)[tracker]
	var newTracker int

	if currentDFSNode.parent.Kind == yaml.MappingNode {
		valueNode := (*dfsOrder)[tracker+1]
		newTracker = skipCurrentNode(valueNode.node, tracker+1)
	} else {
		newTracker = skipCurrentNode(currentDFSNode.node, tracker)
	}

	return newTracker
}

func getNodeLine(dfsOrder *[]NodeInfo, tracker int) int {
	if tracker < len(*dfsOrder) {
		return (*dfsOrder)[tracker].node.Line
	} else {
		return int(math.Inf(1))
	}
}

func isOneLineSequenceNode(node *yaml.Node) bool {
	if node.Kind != yaml.SequenceNode {
		return false
	}
	nodeLine := node.Line
	for _, child := range node.Content {
		if child.Line != nodeLine {
			return false
		}
	}
	return true
}

func enocodeIntoYaml(parentNode *yaml.Node, dfsOrder *[]NodeInfo, tracker int) (string, error) {
	content := make([]*yaml.Node, 0)
	currentNode := (*dfsOrder)[tracker].node
	content = append(content, currentNode)

	if parentNode.Kind == yaml.MappingNode {
		valueNode := (*dfsOrder)[tracker+1].node
		content = append(content, valueNode)
	}

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

func getContent(parentNode *yaml.Node, dfsOrder *[]NodeInfo, tracker int) string {
	content, err := enocodeIntoYaml(parentNode, dfsOrder, tracker)
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

func removeLines(linesToRemove *[]ContentToRemove, linesSlice *[]string) {
	for _, lineToRemove := range *linesToRemove {
		startLine := lineToRemove.startLine
		endLine := int(math.Min(float64(lineToRemove.endLine), float64(len(*linesSlice)-1)))

		for line := startLine; line <= endLine; line++ {
			lineContent := strings.ReplaceAll((*linesSlice)[line], " ", "")
			if isEmptyLineOrComment(lineContent) {
				break
			}
			(*linesSlice)[line] = "*"
		}
	}
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

func writeContentToAdd(writer *bufio.Writer, contentToAdd string) {
	scanner := bufio.NewScanner(strings.NewReader(contentToAdd))
	for scanner.Scan() {
		line := scanner.Text()
		writer.WriteString(line + "\n")
	}
}
