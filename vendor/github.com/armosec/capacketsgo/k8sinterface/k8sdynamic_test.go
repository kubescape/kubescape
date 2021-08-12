package k8sinterface

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	//
	// metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	// Uncomment to load all auth plugins
	// _ "k8s.io/client-go/plugin/pkg/client/auth
	//
	// Or uncomment to load specific auth plugins
	// _ "k8s.io/client-go/plugin/pkg/client/auth/azure"
	// _ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	// _ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
	// _ "k8s.io/client-go/plugin/pkg/client/auth/openstack"
)

// NewKubernetesApi -
func NewKubernetesApiMock() *KubernetesApi {

	return &KubernetesApi{
		KubernetesClient: kubernetesfake.NewSimpleClientset(),
		DynamicClient:    dynamicfake.NewSimpleDynamicClient(&runtime.Scheme{}),
		Context:          context.Background(),
	}
}

// func TestListDynamic(t *testing.T) {
// 	k8s := NewKubernetesApi()
// 	resource := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
// 	clientResource, err := k8s.DynamicClient.Resource(resource).Namespace("default").List(k8s.Context, metav1.ListOptions{})
// 	if err != nil {
// 		t.Errorf("err: %v", err)
// 	} else {
// 		bla, _ := json.Marshal(clientResource)
// 		// t.Errorf("BearerToken: %v", *K8SConfig)
// 		// ioutil.WriteFile("bla.json", bla, 777)
// 		t.Errorf("clientResource: %s", string(bla))
// 	}
// }
