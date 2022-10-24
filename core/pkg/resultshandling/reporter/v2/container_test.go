package v2

import (
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
)

//go:embed testdata/ks-deployment.json
var deployment string

func TestContainerResorceBuilder(t *testing.T) {
	tests := []struct {
		name    string
		resorce string
		want    reporthandling.Resource
	}{
		{
			name:    "create resource",
			resorce: deployment,
			want: reporthandling.Resource{
				ResourceID: "14999009265974204971",
				Object: Container{
					Kind:       "Container",
					ApiVersion: "container.kubscape.cloud",
					ImageTag:   "quay.io/armosec/demoservice:v25",
					Metadata: ContainerMetadata{
						Metadata: &Metadata{Name: "quay.io/armosec/demoservice:v25"},
						Parent: Metadata{
							Name:       "demoservice-server",
							Kind:       "Deployment",
							ApiVersion: "apps/v1",
							Namespace:  "default",
						},
					},
				}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			object := make(map[string]interface{})
			json.Unmarshal([]byte(tt.resorce), &object)
			parentResorce := reporthandling.Resource{Object: object}
			res := containerResorceBuilder(parentResorce, "quay.io/armosec/demoservice:v25")
			assert.Equal(t, tt.want, res)
		})
	}
}
