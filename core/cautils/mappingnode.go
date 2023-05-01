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
	Nodes            []MappingNode //Map line number of chart to template obj
	TemplateFileName string
}

type FileMapping struct {
	Mapping map[string]*MappingNodes
}

func (node *MappingNode) writeInfoToNode(objectID *ObjectID, path string, lineNumber int, value string, fileName string) {
	node.Field = path
	node.TemplateLineNumber = lineNumber
	node.ObjectID = objectID
	node.Value = value
	node.TemplateFileName = fileName
	return
}

func NewFileMapping() *FileMapping {
	fileMapping := new(FileMapping)
	fileMapping.Mapping = make(map[string]*MappingNodes)
	return fileMapping
}

// func NewMappingNodes() *MappingNodes {
// 	mappingNodes := new(MappingNodes)
// 	mappingNodes.Nodes = make(map[int]MappingNode)
// 	mappingNodes.TemplateFileName = ""
// 	return mappingNodes
// }
