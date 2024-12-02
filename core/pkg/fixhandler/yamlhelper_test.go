package fixhandler

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

// Returns 'sameNodes' if the two nodes are the same.
func TestMatchNodes(t *testing.T) {
	nodeOne := &yaml.Node{
		Line:   1,
		Column: 1,
		Kind:   yaml.ScalarNode,
		Value:  "value",
	}
	nodeTwo := &yaml.Node{
		Line:   1,
		Column: 1,
		Kind:   yaml.ScalarNode,
		Value:  "value",
	}

	result := matchNodes(nodeOne, nodeTwo)

	assert.Equal(t, sameNodes, result)
}

// Adjusts line numbers for contentToAdd based on empty or comment lines before them
func TestAdjustContentLines_AdjustsLineNumbersForContentToAddBasedOnEmptyOrCommentLinesBeforeThem(t *testing.T) {
	contentToAdd := []contentToAdd{
		{line: 1},
		{line: 2},
		{line: 3},
		{line: 4},
		{line: 5},
		{line: 6},
		{line: 7},
		{line: 8},
		{line: 9},
		{line: 10},
	}
	linesSlice := []string{
		"line 1",
		"line 2",
		"line 3",
		"",
		"# comment",
		"line 6",
		"",
		"line 8",
		"# comment",
		"line 10",
	}

	adjustContentLines(&contentToAdd, &linesSlice)
	fmt.Println(contentToAdd)
	assert.Equal(t, 1, contentToAdd[0].line)
	assert.Equal(t, 2, contentToAdd[1].line)
	assert.Equal(t, 3, contentToAdd[2].line)
	assert.Equal(t, 3, contentToAdd[3].line)
	assert.Equal(t, 3, contentToAdd[4].line)
	assert.Equal(t, 6, contentToAdd[5].line)
	assert.Equal(t, 6, contentToAdd[6].line)
	assert.Equal(t, 8, contentToAdd[7].line)
	assert.Equal(t, 8, contentToAdd[8].line)
	assert.Equal(t, 10, contentToAdd[9].line)
}

// Adjusts line numbers for contentToAdd based on empty or comment lines before them
func TestAdjustContentLines_TestEdgeCaseWHereContentToAddHaveMoreLines(t *testing.T) {

	contentToAdd := []contentToAdd{
		{line: 1},
		{line: 2},
		{line: 3},
		{line: 4},
		{line: 5},
		{line: 6},
		{line: 7},
		{line: 8},
		{line: 9},
	}

	linesSlice := []string{
		"line 1",
		"line 2",
		"line 3",
		"",
		"# comment",
		"line 6",
		"",
	}

	adjustContentLines(&contentToAdd, &linesSlice)

	assert.Equal(t, 1, contentToAdd[0].line)
	assert.Equal(t, 2, contentToAdd[1].line)
	assert.Equal(t, 3, contentToAdd[2].line)
	assert.Equal(t, 3, contentToAdd[3].line)
	assert.Equal(t, 3, contentToAdd[4].line)
	assert.Equal(t, 6, contentToAdd[5].line)
	assert.Equal(t, 6, contentToAdd[6].line)
	assert.Equal(t, 7, contentToAdd[7].line)
	assert.Equal(t, 8, contentToAdd[8].line)
}

// If the differenceAtTop is less than or equal to 0, the function should return without modifying the fixedList.
func TestAdjustFixedListLines_WhenDifferenceAtTopIsLessThanOrEqualTo0(t *testing.T) {
	originalList := []nodeInfo{
		{node: &yaml.Node{Line: 1}},
		{node: &yaml.Node{Line: 2}},
		{node: &yaml.Node{Line: 3}},
	}
	fixedList := []nodeInfo{
		{node: &yaml.Node{Line: 1}},
		{node: &yaml.Node{Line: 2}},
		{node: &yaml.Node{Line: 3}},
	}

	adjustFixedListLines(&originalList, &fixedList)

	assert.Equal(t, []nodeInfo{
		{node: &yaml.Node{Line: 1}},
		{node: &yaml.Node{Line: 2}},
		{node: &yaml.Node{Line: 3}},
	}, fixedList)
}

// When the fixedList is empty, the function returns without modifying the line numbers of the fixedList.
func TestAdjustFixedListLines_emptyFixedList(t *testing.T) {
	originalList := []nodeInfo{
		{node: &yaml.Node{Line: 1}},
		{node: &yaml.Node{Line: 2}},
		{node: &yaml.Node{Line: 3}},
	}
	fixedList := []nodeInfo{}

	adjustFixedListLines(&originalList, &fixedList)

	assert.Empty(t, fixedList)
}

// Encodes a YAML node into a string
func TestEncodeIntoYaml_EncodesYamlNodeIntoString(t *testing.T) {
	parentNode := &yaml.Node{
		Kind: yaml.MappingNode,
	}
	nodeList := []nodeInfo{
		{
			node: &yaml.Node{
				Kind:  yaml.ScalarNode,
				Value: "key",
			},
		},
		{
			node: &yaml.Node{
				Kind:  yaml.ScalarNode,
				Value: "value",
			},
		},
	}
	tracker := 0

	result, err := enocodeIntoYaml(parentNode, &nodeList, tracker)

	assert.NoError(t, err)
	assert.Equal(t, "key: value\n", result)
}

// Encodes a YAML node into a string
func TestEncodeIntoYaml_EncodesNodeIntoStringWithNegativeTracker(t *testing.T) {
	parentNode := &yaml.Node{
		Kind: yaml.MappingNode,
	}
	nodeList := []nodeInfo{
		{
			node: &yaml.Node{
				Kind:  yaml.ScalarNode,
				Value: "key",
			},
		},
		{
			node: &yaml.Node{
				Kind:  yaml.ScalarNode,
				Value: "value",
			},
		},
	}
	tracker := -1

	_, err := enocodeIntoYaml(parentNode, &nodeList, tracker)

	assert.Error(t, err)
}

// Given a non-empty string content and a positive integer indentationSpaces, the function should return a string with each line of the content indented by the specified number of spaces.
func TestIndentContentNonEmptyStringPositiveIndentationSpaces(t *testing.T) {
	content := "line1\nline2\nline3"
	indentationSpaces := 4
	expected := "    line1\n    line2\n    line3\n"

	result := indentContent(content, indentationSpaces)

	if result != expected {
		t.Errorf("Expected %q, but got %q", expected, result)
	}
}

// Should correctly indent content with negative indentation spaces
func TestIndentContentNegativeIndentationSpaces(t *testing.T) {
	content := "line1\nline2\nline3"
	indentationSpaces := -2
	expected := "line1\nline2\nline3\n"

	result := indentContent(content, indentationSpaces)

	if result != expected {
		t.Errorf("Expected %q, but got %q", expected, result)
	}
}

// Returns the correct line to insert when originalListTracker is non-negative.
func TestGetLineToInsertNonNegative(t *testing.T) {
	fixInfoMetadata := &fixInfoMetadata{
		originalList: &[]nodeInfo{
			{node: &yaml.Node{Line: 1}},
			{node: &yaml.Node{Line: 2}},
			{node: &yaml.Node{Line: 3}},
		},
		originalListTracker: 1,
	}

	lineToInsert := getLineToInsert(fixInfoMetadata)

	assert.Equal(t, 1, lineToInsert)
}

// Assigns last line to contentToAdd with negative line value as a flag
func TestAssignLastLine(t *testing.T) {
	linesSlice := []string{
		"line 1",
		"line 2",
		"line 3",
		"line 4",
		"line 5",
	}

	contentsToAdd := []contentToAdd{
		{line: -2, content: "new line 2"},
	}

	assignLastLine(&contentsToAdd, &[]linesToRemove{}, &linesSlice)

	expected := 5
	actual := contentsToAdd[0].line
	if actual != expected {
		t.Errorf("Expected %d, but got %d", expected, actual)
	}
}

// returns the line number of the node at the given tracker position
func TestGetNodeLine_ReturnsLineNumberOfNodeAtGivenTrackerPosition(t *testing.T) {
	nodeList := []nodeInfo{
		{node: &yaml.Node{Line: 1}},
		{node: &yaml.Node{Line: 2}},
		{node: &yaml.Node{Line: 3}},
	}
	tracker := 1

	line := getNodeLine(&nodeList, tracker)

	assert.Equal(t, 2, line)
}

// Returns an error if the tracker position is a negative value.
func TestGetNodeLine_TrackerPositionNegativeValue_ReturnsError(t *testing.T) {
	nodeList := []nodeInfo{
		{node: &yaml.Node{Line: 1}},
		{node: &yaml.Node{Line: 2}},
		{node: &yaml.Node{Line: 3}},
	}
	tracker := -2

	line := getNodeLine(&nodeList, tracker)

	assert.Equal(t, -1, line)
}

// Returns true if the node is a value node in a mapping node with an odd index
func TestIsValueNodeInMapping_ReturnsTrueIfNodeIsValueNodeInMappingWithOddIndex(t *testing.T) {
	node := &nodeInfo{
		parent: &yaml.Node{
			Kind: yaml.MappingNode,
		},
		index: 1,
	}

	result := isValueNodeinMapping(node)

	assert.True(t, result)
}

// Returns true if the two nodes have the same line, column, kind, and value.
func TestIsSameNode_ReturnsTrueIfSameLineColumnKindAndValue(t *testing.T) {
	nodeOne := &yaml.Node{
		Line:   1,
		Column: 2,
		Kind:   yaml.ScalarNode,
		Value:  "value",
	}
	nodeTwo := &yaml.Node{
		Line:   1,
		Column: 2,
		Kind:   yaml.ScalarNode,
		Value:  "value",
	}

	result := isSameNode(nodeOne, nodeTwo)

	assert.True(t, result)
}

func TestIsSameNode_ReturnsFalseIfEitherNodeIsNil(t *testing.T) {
	nodeOne := &yaml.Node{
		Line:   1,
		Column: 2,
		Kind:   yaml.ScalarNode,
		Value:  "value",
	}
	var nodeTwo *yaml.Node

	result := isSameNode(nodeOne, nodeTwo)

	assert.False(t, result)

	result = isSameNode(nodeTwo, nodeOne)

	assert.False(t, result)
}

// Returns True for empty string
func TestReturnsTrueForEmptyString(t *testing.T) {
	lineContent := ""
	result := isEmptyLineOrComment(lineContent)
	assert.True(t, result)
}

// Returns the index of the first node in the list with the given line number.
func TestGetFirstNodeInLine_ReturnsIndex(t *testing.T) {
	list := []nodeInfo{
		{node: &yaml.Node{Line: 1}},
		{node: &yaml.Node{Line: 2}},
		{node: &yaml.Node{Line: 3}},
	}
	line := 2

	expected := 1
	result := getFirstNodeInLine(&list, line)

	if result != expected {
		t.Errorf("Expected %d, but got %d", expected, result)
	}
}

// returns -1 when the given line is not found in the list
func TestGetFirstNodeInLine_LineNotFound(t *testing.T) {
	list := []nodeInfo{
		{node: &yaml.Node{Line: 1}},
		{node: &yaml.Node{Line: 2}},
		{node: &yaml.Node{Line: 3}},
	}
	line := 4

	index := getFirstNodeInLine(&list, line)

	assert.Equal(t, -1, index)
}

// Function removes lines within specified range
func TestRemoveLinesWithinRange(t *testing.T) {
	linesToRemove := []linesToRemove{
		{startLine: 2, endLine: 4},
	}
	linesSlice := []string{
		"line 1",
		"line 2",
		"line 3",
		"line 4",
		"line 5",
	}

	removeLines(&linesToRemove, &linesSlice)

	expected := []string{
		"line 1",
		"*",
		"*",
		"*",
		"line 5",
	}
	assert.Equal(t, expected, linesSlice)
}

// The function correctly handles cases where the startLine and endLine are out of range of the input slice.
func TestRemoveOutOfRangeLines(t *testing.T) {
	linesToRemove := []linesToRemove{
		{startLine: 5, endLine: 7},
	}
	linesSlice := []string{
		"line 1",
		"line 2",
		"line 3",
		"line 4",
	}
	expected := []string{
		"line 1",
		"line 2",
		"line 3",
		"line 4",
	}

	removeLines(&linesToRemove, &linesSlice)

	if !reflect.DeepEqual(linesSlice, expected) {
		t.Errorf("Expected %v, but got %v", expected, linesSlice)
	}
}

// The function should correctly calculate the total number of children of the given node and add it to the current tracker.
func TestShouldCalculateTotalNumberOfChildrenAndAddToCurrentTracker(t *testing.T) {
	node := &yaml.Node{
		Content: []*yaml.Node{
			&yaml.Node{},
			&yaml.Node{},
			&yaml.Node{},
		},
	}
	currentTracker := 5

	updatedTracker := skipCurrentNode(node, currentTracker)

	expectedTracker := currentTracker + 4
	if updatedTracker != expectedTracker {
		t.Errorf("Expected updated tracker to be %d, but got %d", expectedTracker, updatedTracker)
	}
}

// Returns the updated tracker when given a valid nodeList and tracker.
func TestUpdateTrackerWithValidNodeListAndTracker(t *testing.T) {
	nodeList := []nodeInfo{
		{node: &yaml.Node{Kind: yaml.MappingNode}, parent: &yaml.Node{Kind: yaml.MappingNode}},
		{node: &yaml.Node{Kind: yaml.ScalarNode}},
	}
	tracker := 0

	updatedTracker := updateTracker(&nodeList, tracker)

	expectedTracker := 2
	if updatedTracker != expectedTracker {
		t.Errorf("Expected updated tracker to be %d, but got %d", expectedTracker, updatedTracker)
	}
}

// Returns a string joined from the input slice using the provided newline separator.
func TestGetStringFromSlice_JoinedWithNewlineSeparator(t *testing.T) {
	yamlLines := []string{"line1", "line2", "line3"}
	expected := "line1\nline2\nline3"
	result := getStringFromSlice(yamlLines, "\n")
	assert.Equal(t, expected, result)
}
