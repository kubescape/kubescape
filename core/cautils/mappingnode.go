package cautils

type ObjectID struct {
	apiVersion string
	kind       string
}

type MappingNode struct {
	ObjectID           *ObjectID
	Field              string
	Value              string
	TemplateFileName   string
	TemplateLineNumber int
}

type MappingNodes struct {
	Nodes            []map[string]MappingNode //Map line number of chart to template obj map[int]MappingNode
	TemplateFileName string
}

func (node *MappingNode) writeInfoToNode(objectID *ObjectID, path string, lineNumber int, value string, fileName string) {
	node.Field = path
	node.TemplateLineNumber = lineNumber
	node.ObjectID = objectID
	node.Value = value
	node.TemplateFileName = fileName
}

func NewMappingNodes() *MappingNodes {
	mappingNodes := new(MappingNodes)
	mappingNodes.TemplateFileName = ""
	return mappingNodes

}
