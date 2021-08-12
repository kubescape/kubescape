package k8sinterface

import (
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
)

//
// Uncomment to load all auth plugins
// _ "k8s.io/client-go/plugin/pkg/client/auth
//
// Or uncomment to load specific auth plugins
// _ "k8s.io/client-go/plugin/pkg/client/auth/azure"
// _ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
// _ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
// _ "k8s.io/client-go/plugin/pkg/client/auth/openstack"

func ConvertUnstructuredSliceToMap(unstructuredSlice []unstructured.Unstructured) []map[string]interface{} {
	converted := make([]map[string]interface{}, len(unstructuredSlice))
	for i := range unstructuredSlice {
		converted[i] = unstructuredSlice[i].Object
	}
	return converted
}

func FilterOutOwneredResources(result []unstructured.Unstructured) []unstructured.Unstructured {
	response := []unstructured.Unstructured{}
	recognizedOwners := []string{"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job", "CronJob"}
	for i := range result {
		ownerReferences := result[i].GetOwnerReferences()
		if len(ownerReferences) == 0 {
			response = append(response, result[i])
		} else if !IsStringInSlice(recognizedOwners, ownerReferences[0].Kind) {
			response = append(response, result[i])
		}
	}
	return response
}

func IsStringInSlice(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

// String returns all labels listed as a human readable string.
// Conveniently, exactly the format that ParseSelector takes.
func SelectorToString(ls labels.Set) string {
	selector := make([]string, 0, len(ls))
	for key, value := range ls {
		if value != "" {
			selector = append(selector, key+"="+value)
		} else {
			selector = append(selector, key)
		}
	}
	// Sort for determinism.
	sort.StringSlice(selector).Sort()
	return strings.Join(selector, ",")
}
