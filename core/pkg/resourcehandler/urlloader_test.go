package resourcehandler

import (
	"testing"
)

func TestLoadResourcesFromUrl(t *testing.T) {
	//TODO: tests were commented out due to actual http calls ; http calls should be mocked.
	/*{
		workloads, err := loadResourcesFromUrl([]string{"https://github.com/kubescape/kubescape/tree/master/examples/online-boutique"})
		assert.NoError(t, err)
		assert.Equal(t, 12, len(workloads))

		for i, w := range workloads {
			switch i {
			case "https://raw.githubusercontent.com/kubescape/kubescape/master/examples/online-boutique/adservice.yaml":
				assert.Equal(t, 2, len(w))
				assert.Equal(t, "apps/v1//Deployment/adservice", w[0].GetID())
				assert.Equal(t, "/v1//Service/adservice", w[1].GetID())
			}
		}
	}
	{
		workloads, err := loadResourcesFromUrl([]string{"https://github.com/kubescape/kubescape"})
		assert.NoError(t, err)
		assert.Less(t, 12, len(workloads))

		for i, w := range workloads {
			switch i {
			case "https://raw.githubusercontent.com/kubescape/kubescape/master/examples/online-boutique/adservice.yaml":
				assert.Equal(t, 2, len(w))
				assert.Equal(t, "apps/v1//Deployment/adservice", w[0].GetID())
				assert.Equal(t, "/v1//Service/adservice", w[1].GetID())
			}
		}
	}
	{
		workloads, err := loadResourcesFromUrl([]string{"https://github.com/kubescape/kubescape/blob/master/examples/online-boutique/adservice.yaml"})
		assert.NoError(t, err)
		assert.Equal(t, 1, len(workloads))

		for i, w := range workloads {
			switch i {
			case "https://raw.githubusercontent.com/kubescape/kubescape/master/examples/online-boutique/adservice.yaml":
				assert.Equal(t, 2, len(w))
				assert.Equal(t, "apps/v1//Deployment/adservice", w[0].GetID())
				assert.Equal(t, "/v1//Service/adservice", w[1].GetID())
			}
		}
	}
	{
		workloads, err := loadResourcesFromUrl([]string{"https://raw.githubusercontent.com/kubescape/kubescape/master/examples/online-boutique/adservice.yaml"})
		assert.NoError(t, err)
		assert.Equal(t, 1, len(workloads))

		for i, w := range workloads {
			switch i {
			case "https://raw.githubusercontent.com/kubescape/kubescape/master/examples/online-boutique/adservice.yaml":
				assert.Equal(t, 2, len(w))
				assert.Equal(t, "apps/v1//Deployment/adservice", w[0].GetID())
				assert.Equal(t, "/v1//Service/adservice", w[1].GetID())
			}
		}
	}*/
}
