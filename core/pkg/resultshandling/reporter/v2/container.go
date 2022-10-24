package v2

import (
	"fmt"
	"hash/fnv"

	"github.com/kubescape/opa-utils/reporthandling"
)

const (
	ContainerApiVersion string = "container.kubscape.cloud"
	ContainerKind       string = "Container"
)

type Container struct {
	ImageTag   string            `json:"imageTag"`
	ImageHash  string            `json:"imageHash,omitempty"` //just in kind=pod imageHash:
	ApiVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   ContainerMetadata `json:"metadata"`
}

type ContainerMetadata struct {
	*Metadata
	Parent Metadata `json:"parent"`
}

type Metadata struct {
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Namespace  string `json:"namespace,omitempty"`
	ResourceID string `json:"resourceID,omitempty"`
	ApiVersion string `json:"apiVersion"`
}

func generateContainerResorceId(imageTag, parentResourceID string) string {
	hasher := fnv.New64a()
	hasher.Write([]byte(fmt.Sprintf("%s/%s", parentResourceID, imageTag)))
	return fmt.Sprintf("%v", hasher.Sum64())
}
func containerResorceBuilder(parentResource reporthandling.Resource, imageTag string) reporthandling.Resource {
	return reporthandling.Resource{
		ResourceID: generateContainerResorceId(imageTag, parentResource.ResourceID),
		Object: Container{
			Kind:       ContainerKind,
			ApiVersion: ContainerApiVersion,
			ImageTag:   imageTag,
			Metadata: ContainerMetadata{
				Metadata: &Metadata{Name: imageTag},
				Parent: Metadata{
					Name:       parentResource.GetName(),
					Namespace:  parentResource.GetNamespace(),
					Kind:       parentResource.GetKind(),
					ResourceID: parentResource.ResourceID,
					ApiVersion: parentResource.GetApiVersion(),
				},
			},
		}}
}
