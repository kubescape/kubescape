package gotree

func EmptyTreeMock() Tree {
	tree := New("")

	return tree
}

func RootTreeMock() Tree {
	tree := New("root")

	return tree
}

func SimpleTreeMock() Tree {
	tree := New("root")
	tree.Add("child1")
	tree.Add("child2")

	return tree
}

func SimpleTreeWithLinesMock() Tree {
	tree := New("root")
	tree.Add("child1")
	tree.Add("child2")

	tree.Add("child3\nLine2\nLine3")
	tree.Add("child4")

	return tree
}

func SubTreeMock1() Tree {
	tree := New("root")
	tree.Add("child1").Add("child1.1")

	return tree
}

func SubTreeMock2() Tree {
	tree := New("root")
	tree.Add("child1").Add("child1.1")
	tree.Add("child2")
	tree.Add("child3").Add("child3.1")

	return tree
}

func SubTreeWithLinesMock() Tree {
	tree := New("root")
	tree.Add("child1").Add("child1.1\nLine2\nLine3")
	tree.Add("child2")
	tree.Add("child3").Add("child3.1\nLine2\nLine3")

	return tree
}
