package fixhandler

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/mikefarah/yq/v4/pkg/yqlib"
	"gopkg.in/yaml.v3"
)

// decodeDocumentRoots decodes all YAML documents stored in a given `filepath` and returns a slice of their root nodes
func decodeDocumentRoots(yamlAsString string) ([]yaml.Node, error) {
	fileReader := strings.NewReader(yamlAsString)
	dec := yaml.NewDecoder(fileReader)

	nodes := make([]yaml.Node, 0)
	for {
		var node yaml.Node
		err := dec.Decode(&node)

		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("cannot decode file as YAML")

		}

		nodes = append(nodes, node)
	}

	return nodes, nil
}

func getFixedNodes(ctx context.Context, yamlAsString, yamlExpression string) ([]yaml.Node, error) {
	preferences := yqlib.ConfiguredYamlPreferences
	preferences.EvaluateTogether = true
	decoder := yqlib.NewYamlDecoder(preferences)

	var allDocuments = list.New()
	reader := strings.NewReader(yamlAsString)

	fileDocuments, err := readDocuments(ctx, reader, decoder)
	if err != nil {
		return nil, err
	}
	allDocuments.PushBackList(fileDocuments)

	allAtOnceEvaluator := yqlib.NewAllAtOnceEvaluator()

	fixedCandidateNodes, err := allAtOnceEvaluator.EvaluateCandidateNodes(yamlExpression, allDocuments)

	if err != nil {
		return nil, fmt.Errorf("error fixing YAML, %w", err)
	}

	fixedNodes := make([]yaml.Node, 0)
	var fixedNode *yaml.Node
	for fixedCandidateNode := fixedCandidateNodes.Front(); fixedCandidateNode != nil; fixedCandidateNode = fixedCandidateNode.Next() {
		fixedNode = fixedCandidateNode.Value.(*yqlib.CandidateNode).Node
		fixedNodes = append(fixedNodes, *fixedNode)
	}

	return fixedNodes, nil
}

func flattenWithDFS(node *yaml.Node) *[]nodeInfo {
	dfsOrder := make([]nodeInfo, 0)
	flattenWithDFSHelper(node, nil, &dfsOrder, 0)
	return &dfsOrder
}

func flattenWithDFSHelper(node *yaml.Node, parent *yaml.Node, dfsOrder *[]nodeInfo, index int) {
	dfsNode := nodeInfo{
		node:   node,
		parent: parent,
		index:  index,
	}
	*dfsOrder = append(*dfsOrder, dfsNode)

	for idx, child := range node.Content {
		flattenWithDFSHelper(child, node, dfsOrder, idx)
	}
}

func getFixInfo(ctx context.Context, originalRootNodes, fixedRootNodes []yaml.Node) (fileFixInfo, error) {
	contentToAdd := make([]contentToAdd, 0)
	linesToRemove := make([]linesToRemove, 0)

	for idx := range fixedRootNodes {
		// The two decoders can disagree on document count (e.g. an empty leading
		// document), so guard the paired index instead of panicking.
		if idx >= len(originalRootNodes) {
			break
		}
		originalList := flattenWithDFS(&originalRootNodes[idx])
		fixedList := flattenWithDFS(&fixedRootNodes[idx])
		nodeContentToAdd, nodeLinesToRemove, err := getFixInfoHelper(ctx, *originalList, *fixedList)
		if err != nil {
			return fileFixInfo{}, err
		}
		contentToAdd = append(contentToAdd, nodeContentToAdd...)
		linesToRemove = append(linesToRemove, nodeLinesToRemove...)
	}

	return fileFixInfo{
		contentsToAdd: &contentToAdd,
		linesToRemove: &linesToRemove,
	}, nil
}

func getFixInfoHelper(ctx context.Context, originalList, fixedList []nodeInfo) ([]contentToAdd, []linesToRemove, error) {

	// While obtaining fixedYamlNode, comments and empty lines at the top are ignored.
	// This causes a difference in Line numbers across the tree structure. In order to
	// counter this, line numbers are adjusted in fixed list.
	adjustFixedListLines(&originalList, &fixedList)

	contentToAdd := make([]contentToAdd, 0)
	linesToRemove := make([]linesToRemove, 0)

	originalListTracker, fixedListTracker := 0, 0

	fixInfoMetadata := &fixInfoMetadata{
		originalList:        &originalList,
		fixedList:           &fixedList,
		originalListTracker: originalListTracker,
		fixedListTracker:    fixedListTracker,
		contentToAdd:        &contentToAdd,
		linesToRemove:       &linesToRemove,
	}

	for originalListTracker < len(originalList) && fixedListTracker < len(fixedList) {
		matchNodeResult := matchNodes(originalList[originalListTracker].node, fixedList[fixedListTracker].node)

		fixInfoMetadata.originalListTracker = originalListTracker
		fixInfoMetadata.fixedListTracker = fixedListTracker

		var err error
		switch matchNodeResult {
		case sameNodes:
			originalListTracker += 1
			fixedListTracker += 1

		case removedNode:
			originalListTracker, fixedListTracker, err = addLinesToRemove(ctx, fixInfoMetadata)

		case insertedNode:
			originalListTracker, fixedListTracker, err = addLinesToInsert(ctx, fixInfoMetadata)

		case replacedNode:
			originalListTracker, fixedListTracker, err = updateLinesToReplace(ctx, fixInfoMetadata)
		}
		if err != nil {
			return nil, nil, err
		}
	}

	// Some nodes are still not visited if they are removed at the end of the list
	for originalListTracker < len(originalList) {
		fixInfoMetadata.originalListTracker = originalListTracker
		var err error
		originalListTracker, _, err = addLinesToRemove(ctx, fixInfoMetadata)
		if err != nil {
			return nil, nil, err
		}
	}

	// Some nodes are still not visited if they are inserted at the end of the list
	for fixedListTracker < len(fixedList) {
		// Use negative index of last node in original list as a placeholder to determine the last line number later
		fixInfoMetadata.originalListTracker = -(len(originalList) - 1)
		fixInfoMetadata.fixedListTracker = fixedListTracker
		var err error
		_, fixedListTracker, err = addLinesToInsert(ctx, fixInfoMetadata)
		if err != nil {
			return nil, nil, err
		}
	}

	return contentToAdd, linesToRemove, nil

}

// Adds the lines to remove and returns the updated originalListTracker
func addLinesToRemove(ctx context.Context, fixInfoMetadata *fixInfoMetadata) (int, int, error) {
	isOneLine, line := isOneLineSequenceNode(fixInfoMetadata.originalList, fixInfoMetadata.originalListTracker)

	if isOneLine {
		// Remove the entire line and replace it with the sequence node in fixed info. This way,
		// the original formatting is not lost.
		return replaceSingleLineSequence(ctx, fixInfoMetadata, line)
	}

	currentDFSNode := (*fixInfoMetadata.originalList)[fixInfoMetadata.originalListTracker]

	newOriginalListTracker := updateTracker(fixInfoMetadata.originalList, fixInfoMetadata.originalListTracker)
	*fixInfoMetadata.linesToRemove = append(*fixInfoMetadata.linesToRemove, linesToRemove{
		startLine: currentDFSNode.node.Line,
		endLine:   getNodeLine(fixInfoMetadata.originalList, newOriginalListTracker-1), // newOriginalListTracker is the next node
	})

	return newOriginalListTracker, fixInfoMetadata.fixedListTracker, nil
}

// Adds the lines to insert and returns the updated fixedListTracker
func addLinesToInsert(ctx context.Context, fixInfoMetadata *fixInfoMetadata) (int, int, error) {

	isOneLine, line := isOneLineSequenceNode(fixInfoMetadata.fixedList, fixInfoMetadata.fixedListTracker)

	if isOneLine {
		return replaceSingleLineSequence(ctx, fixInfoMetadata, line)
	}

	currentDFSNode := (*fixInfoMetadata.fixedList)[fixInfoMetadata.fixedListTracker]

	lineToInsert := getLineToInsert(fixInfoMetadata)
	contentToInsert, err := getContent(ctx, currentDFSNode.parent, fixInfoMetadata.fixedList, fixInfoMetadata.fixedListTracker)
	if err != nil {
		return 0, 0, err
	}

	newFixedTracker := updateTracker(fixInfoMetadata.fixedList, fixInfoMetadata.fixedListTracker)

	*fixInfoMetadata.contentToAdd = append(*fixInfoMetadata.contentToAdd, contentToAdd{
		line:    lineToInsert,
		content: contentToInsert,
	})

	return fixInfoMetadata.originalListTracker, newFixedTracker, nil
}

// Adds the lines to remove and insert and updates the fixedListTracker and originalListTracker
func updateLinesToReplace(ctx context.Context, fixInfoMetadata *fixInfoMetadata) (int, int, error) {

	isOneLine, line := isOneLineSequenceNode(fixInfoMetadata.fixedList, fixInfoMetadata.fixedListTracker)

	if isOneLine {
		return replaceSingleLineSequence(ctx, fixInfoMetadata, line)
	}

	currentDFSNode := (*fixInfoMetadata.fixedList)[fixInfoMetadata.fixedListTracker]

	// If only the value node is changed, entire "key-value" pair is replaced
	if isValueNodeinMapping(&currentDFSNode) {
		fixInfoMetadata.originalListTracker -= 1
		fixInfoMetadata.fixedListTracker -= 1
	}

	if _, _, err := addLinesToRemove(ctx, fixInfoMetadata); err != nil {
		return 0, 0, err
	}
	updatedOriginalTracker, updatedFixedTracker, err := addLinesToInsert(ctx, fixInfoMetadata)
	if err != nil {
		return 0, 0, err
	}

	return updatedOriginalTracker, updatedFixedTracker, nil
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

func getFixedYamlLines(yamlLines []string, fileFixInfo fileFixInfo, newline string) (fixedYamlLines []string) {

	// Determining last line requires original yaml lines slice. The placeholder for last line is replaced with the real last line
	assignLastLine(fileFixInfo.contentsToAdd, fileFixInfo.linesToRemove, &yamlLines)

	removeLines(fileFixInfo.linesToRemove, &yamlLines)

	fixedYamlLines = make([]string, 0)
	lineIdx, lineToAddIdx := 1, 0

	// Ideally, new node is inserted at line before the next node in DFS order. But, when the previous line contains a
	// comment or empty line, we need to insert new nodes before them.
	adjustContentLines(fileFixInfo.contentsToAdd, &yamlLines)

	for lineToAddIdx < len(*fileFixInfo.contentsToAdd) {
		for lineIdx <= (*fileFixInfo.contentsToAdd)[lineToAddIdx].line {
			// Check if the current line is not removed
			if yamlLines[lineIdx-1] != "*" {
				fixedYamlLines = append(fixedYamlLines, yamlLines[lineIdx-1])
			}
			lineIdx += 1
		}

		content := (*fileFixInfo.contentsToAdd)[lineToAddIdx].Content(newline)
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
