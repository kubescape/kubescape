package fixhandler

import (
	"bufio"
	"bytes"
	"container/list"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"github.com/mikefarah/yq/v4/pkg/yqlib"

	"gopkg.in/yaml.v3"
)

func getFixedYamlNode(filePath, yamlExpression string) yaml.Node {
	preferences := yqlib.ConfiguredYamlPreferences
	preferences.EvaluateTogether = true
	decoder := yqlib.NewYamlDecoder(preferences)

	var allDocuments = list.New()
	reader, err := readStream(filePath)
	if err != nil {
		return yaml.Node{}
	}

	fileDocuments, err := readDocuments(reader, filePath, 0, decoder)
	if err != nil {
		return yaml.Node{}
	}
	allDocuments.PushBackList(fileDocuments)

	if allDocuments.Len() == 0 {
		candidateNode := &yqlib.CandidateNode{
			Document:       0,
			Filename:       "",
			Node:           &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Tag: "!!null", Kind: yaml.ScalarNode}}},
			FileIndex:      0,
			LeadingContent: "",
		}
		allDocuments.PushBack(candidateNode)
	}

	allAtOnceEvaluator := yqlib.NewAllAtOnceEvaluator()

	matches, _ := allAtOnceEvaluator.EvaluateCandidateNodes(yamlExpression, allDocuments)

	return *matches.Front().Value.(*yqlib.CandidateNode).Node
}

func readStream(filename string) (io.Reader, error) {
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
		fmt.Println("Error Closing File")
	}
}

func getLineAndContentToAdd(node *yaml.Node) *[]LineAndContentToAdd {
	contentToAdd := make([]LineAndContentToAdd, 0)
	getLineAndContentToAddHelper(0, node, &contentToAdd)
	return &contentToAdd
}

func getLineAndContentToAddHelper(nodeIdx int, parentNode *yaml.Node, contentToAdd *[]LineAndContentToAdd) {
	node := parentNode.Content[nodeIdx]
	var content string
	var err error
	if node.Line == 0 && node.Column == 0 {
		if parentNode.Kind == yaml.MappingNode {
			if nodeIdx%2 != 0 {
				return
			}
		}
		content, err = enocodeIntoYaml(parentNode, nodeIdx)

		if err != nil {
			fmt.Println("Cannot Encode into YAML")
		}

		indentationSpacesBeforeContent := parentNode.Column - 1

		content = addIndentationToContent(content, indentationSpacesBeforeContent)

		// Getting the line to add content after. Add directly after the left Sibling.
		var lineToAddAfter int
		for idx := nodeIdx - 1; idx >= 0; idx-- {
			if parentNode.Content[idx].Line != 0 {
				lineToAddAfter = getEndingLine(idx, parentNode)
			}
		}
		lineAndContentToAdd := LineAndContentToAdd{
			Line:    lineToAddAfter,
			Content: content,
		}
		*contentToAdd = append(*contentToAdd, lineAndContentToAdd)
	}

	for index, _ := range node.Content {
		getLineAndContentToAddHelper(index, node, contentToAdd)
	}
}

func enocodeIntoYaml(parentNode *yaml.Node, nodeIdx int) (string, error) {
	if parentNode.Kind == yaml.MappingNode {
		content := make([]*yaml.Node, 0)
		content = append(content, parentNode.Content[nodeIdx], parentNode.Content[nodeIdx+1])
		parentForContent := yaml.Node{
			Kind:    yaml.MappingNode,
			Content: content,
		}
		buf := new(bytes.Buffer)
		encoder := yaml.NewEncoder(buf)
		errorEncoding := encoder.Encode(parentForContent)
		if errorEncoding != nil {
			return "", fmt.Errorf("Error debugging node, %v", errorEncoding.Error())
		}
		errorClosingEncoder := encoder.Close()
		if errorClosingEncoder != nil {
			return "", fmt.Errorf("Error closing encoder: ", errorClosingEncoder.Error())
		}
		return fmt.Sprintf(`%v`, buf.String()), nil
	}

	return "", nil
}

func addIndentationToContent(content string, indentationSpacesBeforeContent int) string {
	indentedContent := ""
	indentSpaces := strings.Repeat(" ", indentationSpacesBeforeContent)

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		indentedContent += (indentSpaces + line + "\n")
	}
	return indentedContent
}

func getEndingLine(nodeIdx int, parentNode *yaml.Node) int {
	node := parentNode.Content[nodeIdx]
	if node.Kind == yaml.ScalarNode {
		return node.Line
	}
	contentLen := len(node.Content)

	for idx := contentLen - 1; idx >= 0; idx-- {
		if node.Content[idx].Line != 0 {
			return getEndingLine(idx, node)
		}
	}

	return 0
}

func addFixesToFile(filePath string, lineAndContentsToAdd []LineAndContentToAdd) (cmdError error) {
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

	writer := bufio.NewWriter(file)
	lineIdx, lineToAddIdx := 0, 0

	for lineToAddIdx < len(lineAndContentsToAdd) {
		for lineIdx <= lineAndContentsToAdd[lineToAddIdx].Line {
			_, err := writer.WriteString(linesSlice[lineIdx] + "\n")
			if err != nil {
				return err
			}
			lineIdx += 1
		}

		writeContentToAdd(writer, lineAndContentsToAdd[lineToAddIdx].Content)
		lineToAddIdx += 1
	}

	for lineIdx < len(linesSlice) {
		_, err := writer.WriteString(linesSlice[lineIdx] + "\n")
		if err != nil {
			return err
		}
		lineIdx += 1
	}

	writer.Flush()
	return nil
}

// Get the lines of existing yaml in a slice
func getLinesSlice(filePath string) ([]string, error) {
	lineSlice := make([]string, 0)

	file, err := os.Open(filePath)
	if err != nil {
		log.Fatal(err)
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
