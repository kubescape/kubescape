package fixhandler

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

// decodeDocumentRoots retains all physical documents, including empty ones.
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
			return nil, fmt.Errorf("cannot decode file as YAML: %w", err)
		}

		nodes = append(nodes, node)
	}

	return nodes, nil
}
