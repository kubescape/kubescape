package v2

import (
	"fmt"
	"github.com/kubescape/opa-utils/reporthandling"
	"hash/fnv"
)

const (
	ContainerApiVersion string = "container.kubscape.cloud"
	ContainerKind       string = "Container"
)

type Container struct {
	ImageTag   string            `json:"imageTag"`
	ImageHash  string            `json:"imageHash"` //just in kind=pod imageHash:
	ApiVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   ContainerMetadata `json:"metadata"`
}

type ContainerMetadata struct {
	Name             string `json:"name"`
	Namespace        string `json:"namespace"`
	ParentKind       string `json:"parentKind"`
	ParentName       string `json:"parentName"`
	ParentResourceID string `json:"parentResourceID"`
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
				Name:             imageTag,
				Namespace:        parentResource.GetNamespace(),
				ParentResourceID: parentResource.ResourceID,
				ParentName:       parentResource.GetName(),
				ParentKind:       parentResource.GetKind(),
			},
		}}
}
