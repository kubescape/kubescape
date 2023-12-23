package gotree

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	p = &printer{}
)

func TestTreePrint(t *testing.T) {
	tests := []struct {
		name string
		tree Tree
		want string
	}{
		{
			name: "EmptyTreeMock",
			tree: EmptyTreeMock(),
			want: "\n",
		},
		{
			name: "RootTreeMock",
			tree: RootTreeMock(),
			want: "root\n",
		},
		{
			name: "SimpleTreeMock",
			tree: SimpleTreeMock(),
			want: "root\n" +
				"├── child1\n" +
				"└── child2\n",
		},
		{
			name: "SimpleTreeWithLinesMock",
			tree: SimpleTreeWithLinesMock(),
			want: "root\n" +
				"├── child1\n" +
				"├── child2\n" +
				"├── child3\n" +
				"│   Line2\n" +
				"│   Line3\n" +
				"└── child4\n",
		},
		{
			name: "SubTreeMock1",
			tree: SubTreeMock1(),
			want: "root\n" +
				"└── child1\n" +
				"    └── child1.1\n",
		},
		{
			name: "SubTreeMock2",
			tree: SubTreeMock2(),
			want: "root\n" +
				"├── child1\n" +
				"│   └── child1.1\n" +
				"├── child2\n" +
				"└── child3\n" +
				"    └── child3.1\n",
		},
		{
			name: "SubTreeWithLinesMock",
			tree: SubTreeWithLinesMock(),
			want: "root\n" +
				"├── child1\n" +
				"│   └── child1.1\n" +
				"│       Line2\n" +
				"│       Line3\n" +
				"├── child2\n" +
				"└── child3\n" +
				"    └── child3.1\n" +
				"        Line2\n" +
				"        Line3\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.tree.Print())
		})
	}
}

func TestPrintText_LastTree(t *testing.T) {
	inputText := "Root\n├── Child1\n└── Child2"
	expectedOutput := "└── Root\n    ├── Child1\n    └── Child2\n"

	result := p.printText(inputText, []bool{}, true)

	assert.Equal(t, expectedOutput, result)
}

func TestPrintText_NotLastTree(t *testing.T) {
	inputText := "Root\n├── Child1\n└── Child2"
	expectedOutput := "├── Root\n│   ├── Child1\n│   └── Child2\n"

	result := p.printText(inputText, []bool{}, false)

	assert.Equal(t, expectedOutput, result)
}

func Test_printer_printItems(t *testing.T) {
	tests := []struct {
		name string
		tree Tree
		want string
	}{
		{
			name: "EmptyTreeMock",
			tree: EmptyTreeMock(),
			want: "",
		},
		{
			name: "RootTreeMock",
			tree: RootTreeMock(),
			want: "",
		},
		{
			name: "SimpleTreeMock",
			tree: SimpleTreeMock(),
			want: "├── child1\n" +
				"└── child2\n",
		},
		{
			name: "SimpleTreeWithLinesMock",
			tree: SimpleTreeWithLinesMock(),
			want: "├── child1\n" +
				"├── child2\n" +
				"├── child3\n" +
				"│   Line2\n" +
				"│   Line3\n" +
				"└── child4\n",
		},
		{
			name: "SubTreeMock1",
			tree: SubTreeMock1(),
			want: "└── child1\n" +
				"    └── child1.1\n",
		},
		{
			name: "SubTreeMock2",
			tree: SubTreeMock2(),
			want: "├── child1\n" +
				"│   └── child1.1\n" +
				"├── child2\n" +
				"└── child3\n" +
				"    └── child3.1\n",
		},
		{
			name: "SubTreeWithLinesMock",
			tree: SubTreeWithLinesMock(),
			want: "├── child1\n" +
				"│   └── child1.1\n" +
				"│       Line2\n" +
				"│       Line3\n" +
				"├── child2\n" +
				"└── child3\n" +
				"    └── child3.1\n" +
				"        Line2\n" +
				"        Line3\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, p.printItems(tt.tree.Items(), []bool{}))
		})
	}
}
