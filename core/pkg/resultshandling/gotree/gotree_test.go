package gotree

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
				"╰── child2\n",
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
				"╰── child4\n",
		},
		{
			name: "SubTreeMock1",
			tree: SubTreeMock1(),
			want: "root\n" +
				"╰── child1\n" +
				"    ╰── child1.1\n",
		},
		{
			name: "SubTreeMock2",
			tree: SubTreeMock2(),
			want: "root\n" +
				"├── child1\n" +
				"│   ╰── child1.1\n" +
				"├── child2\n" +
				"╰── child3\n" +
				"    ╰── child3.1\n",
		},
		{
			name: "SubTreeWithLinesMock",
			tree: SubTreeWithLinesMock(),
			want: "root\n" +
				"├── child1\n" +
				"│   ╰── child1.1\n" +
				"│       Line2\n" +
				"│       Line3\n" +
				"├── child2\n" +
				"╰── child3\n" +
				"    ╰── child3.1\n" +
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
	inputText := "Root\n├── Child1\n╰── Child2"
	expectedOutput := "╰── Root\n    ├── Child1\n    ╰── Child2\n"

	result := p.printText(inputText, []bool{}, true)

	assert.Equal(t, expectedOutput, result)
}

func TestPrintText_NotLastTree(t *testing.T) {
	inputText := "Root\n├── Child1\n╰── Child2"
	expectedOutput := "├── Root\n│   ├── Child1\n│   ╰── Child2\n"

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
				"╰── child2\n",
		},
		{
			name: "SimpleTreeWithLinesMock",
			tree: SimpleTreeWithLinesMock(),
			want: "├── child1\n" +
				"├── child2\n" +
				"├── child3\n" +
				"│   Line2\n" +
				"│   Line3\n" +
				"╰── child4\n",
		},
		{
			name: "SubTreeMock1",
			tree: SubTreeMock1(),
			want: "╰── child1\n" +
				"    ╰── child1.1\n",
		},
		{
			name: "SubTreeMock2",
			tree: SubTreeMock2(),
			want: "├── child1\n" +
				"│   ╰── child1.1\n" +
				"├── child2\n" +
				"╰── child3\n" +
				"    ╰── child3.1\n",
		},
		{
			name: "SubTreeWithLinesMock",
			tree: SubTreeWithLinesMock(),
			want: "├── child1\n" +
				"│   ╰── child1.1\n" +
				"│       Line2\n" +
				"│       Line3\n" +
				"├── child2\n" +
				"╰── child3\n" +
				"    ╰── child3.1\n" +
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

func TestNew(t *testing.T) {
	tree := New("root")
	assert.NotNil(t, tree)
	assert.Equal(t, "root", tree.Text())
	assert.Empty(t, tree.Items())
}

func TestNew_EmptyText(t *testing.T) {
	tree := New("")
	assert.NotNil(t, tree)
	assert.Equal(t, "", tree.Text())
}

func TestAdd_SingleChild(t *testing.T) {
	root := New("root")
	child := root.Add("child")
	assert.NotNil(t, child)
	assert.Equal(t, "child", child.Text())
	items := root.Items()
	require.Len(t, items, 1)
	assert.Equal(t, "child", items[0].Text())
}

func TestAdd_MultipleChildren(t *testing.T) {
	root := New("root")
	root.Add("child1")
	root.Add("child2")
	root.Add("child3")
	items := root.Items()
	require.Len(t, items, 3)
	assert.Equal(t, "child1", items[0].Text())
	assert.Equal(t, "child2", items[1].Text())
	assert.Equal(t, "child3", items[2].Text())
}

func TestAdd_ChainedBuilding(t *testing.T) {
	root := New("root")
	child := root.Add("child")
	child.Add("grandchild1")
	child.Add("grandchild2")

	require.Len(t, root.Items(), 1)
	require.Len(t, root.Items()[0].Items(), 2)
}

func TestAddTree_SingleSubtree(t *testing.T) {
	root := New("root")
	subtree := New("subtree")
	subtree.Add("sub-child")
	root.AddTree(subtree)

	items := root.Items()
	require.Len(t, items, 1)
	assert.Equal(t, "subtree", items[0].Text())
	require.Len(t, items[0].Items(), 1)
	assert.Equal(t, "sub-child", items[0].Items()[0].Text())
}

func TestAddTree_MultipleSubtrees(t *testing.T) {
	root := New("root")
	s1 := New("s1")
	s2 := New("s2")
	root.AddTree(s1)
	root.AddTree(s2)
	items := root.Items()
	require.Len(t, items, 2)
	assert.Equal(t, "s1", items[0].Text())
	assert.Equal(t, "s2", items[1].Text())
}

func TestText(t *testing.T) {
	tests := []string{"hello", "world", "complex text", ""}
	for _, text := range tests {
		t.Run(text, func(t *testing.T) {
			tree := New(text)
			assert.Equal(t, text, tree.Text())
		})
	}
}

func TestItems_Empty(t *testing.T) {
	tree := New("leaf")
	items := tree.Items()
	assert.NotNil(t, items)
	assert.Len(t, items, 0)
}

func TestItems_Order(t *testing.T) {
	root := New("root")
	root.Add("first")
	root.Add("second")
	root.Add("third")
	items := root.Items()
	require.Len(t, items, 3)
	assert.Equal(t, "first", items[0].Text())
	assert.Equal(t, "second", items[1].Text())
	assert.Equal(t, "third", items[2].Text())
}

func TestPrint_SingleNode(t *testing.T) {
	tree := New("only")
	result := tree.Print()
	assert.Contains(t, result, "only")
}

func TestPrint_NestedTree(t *testing.T) {
	root := New("root")
	child := root.Add("child")
	child.Add("grandchild")
	result := root.Print()
	assert.Contains(t, result, "root")
	assert.Contains(t, result, "child")
	assert.Contains(t, result, "grandchild")
}

func TestPrint_EmptyRoot(t *testing.T) {
	tree := New("")
	assert.NotPanics(t, func() {
		_ = tree.Print()
	})
}

func TestAdd_ReturnsChildNotParent(t *testing.T) {
	root := New("root")
	child := root.Add("child")
	assert.Equal(t, "child", child.Text())
	assert.NotEqual(t, root.Text(), child.Text())
}

func TestAddTree_PreservesSubtreeItems(t *testing.T) {
	root := New("root")
	subtree := New("sub")
	subtree.Add("a")
	subtree.Add("b")
	root.AddTree(subtree)
	require.Len(t, root.Items(), 1)
	require.Len(t, root.Items()[0].Items(), 2)
	assert.Equal(t, "a", root.Items()[0].Items()[0].Text())
	assert.Equal(t, "b", root.Items()[0].Items()[1].Text())
}
