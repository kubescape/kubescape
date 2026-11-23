package core

import (
	"context"
	"fmt"
	"strings"

	version "github.com/hashicorp/go-version"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var operatorDeploymentGVR = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}

// CheckOperatorVersion queries the operator deployment in namespace and verifies that its
// version satisfies minVersionStr.
func CheckOperatorVersion(ctx context.Context, namespace string, minVersionStr string) error {
	k8sClient := getKubernetesApi()
	if k8sClient == nil || k8sClient.KubernetesClient == nil {
		return nil
	}
	dyn := k8sClient.GetDynamicClient()
	if dyn == nil {
		return nil
	}
	return CheckOperatorVersionWithClient(ctx, dyn, namespace, minVersionStr)
}

// CheckOperatorVersionWithClient verifies the operator deployment version against minVersionStr using dyn.
func CheckOperatorVersionWithClient(ctx context.Context, dyn dynamic.Interface, namespace string, minVersionStr string) (err error) {
	if dyn == nil {
		return nil
	}

	defer func() {
		if r := recover(); r != nil {
			err = nil
		}
	}()

	minVer, err := version.NewVersion(minVersionStr)
	if err != nil {
		return fmt.Errorf("invalid minimum operator version %q: %w", minVersionStr, err)
	}

	// 1. Try to fetch the deployment named "operator" in namespace
	deploy, err := dyn.Resource(operatorDeploymentGVR).Namespace(namespace).Get(ctx, "operator", metav1.GetOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("checking operator deployment in namespace %q: %w", namespace, err)
		}
		// 2. Try listing deployments by label
		list, listErr := dyn.Resource(operatorDeploymentGVR).Namespace(namespace).List(ctx, metav1.ListOptions{
			LabelSelector: "app.kubernetes.io/name=operator",
		})
		if listErr != nil && !apierrors.IsNotFound(listErr) {
			return fmt.Errorf("listing operator deployments in namespace %q: %w", namespace, listErr)
		}
		if len(list.Items) > 0 {
			deploy = &list.Items[0]
		} else {
			list2, list2Err := dyn.Resource(operatorDeploymentGVR).Namespace(namespace).List(ctx, metav1.ListOptions{
				LabelSelector: "app=operator",
			})
			if list2Err != nil && !apierrors.IsNotFound(list2Err) {
				return fmt.Errorf("listing operator deployments in namespace %q: %w", namespace, list2Err)
			}
			if len(list2.Items) > 0 {
				deploy = &list2.Items[0]
			}
		}
	}

	if deploy == nil {
		return nil
	}

	foundVer := extractOperatorVersion(deploy)
	if foundVer == "" {
		return nil
	}

	curVer, err := version.NewVersion(foundVer)
	if err != nil {
		// Non-semver tags (e.g. "latest", dev branches, git commits) are allowed to avoid blocking development.
		return nil
	}

	if curVer.LessThan(minVer) {
		return fmt.Errorf("operator remediate patch requires Kubescape Operator >= %s (found %s in namespace %q)", minVersionStr, foundVer, namespace)
	}

	return nil
}

func extractOperatorVersion(deploy *unstructured.Unstructured) string {
	containers, found, _ := unstructured.NestedSlice(deploy.Object, "spec", "template", "spec", "containers")
	if found {
		var fallbackImageTag string
		operatorContainerFound := false

		// 1. Prefer a container explicitly named "operator" first
		for _, c := range containers {
			cMap, ok := c.(map[string]interface{})
			if !ok {
				continue
			}
			img, ok := cMap["image"].(string)
			if !ok {
				continue
			}
			cName, _ := cMap["name"].(string)
			if cName == "operator" {
				operatorContainerFound = true
				if tag := extractTagFromImage(img); tag != "" {
					return tag
				}
			} else if fallbackImageTag == "" && strings.Contains(img, "operator") {
				// Keep the first container matching by image in case no container is named "operator"
				fallbackImageTag = extractTagFromImage(img)
			}
		}

		// 2. Use image-based matching only when container named "operator" is absent (preserves discovery for renamed containers)
		if !operatorContainerFound && fallbackImageTag != "" {
			return fallbackImageTag
		}
	}

	// 3. Fall back to label app.kubernetes.io/version only if no container image tag was found
	labels := deploy.GetLabels()
	if ver, ok := labels["app.kubernetes.io/version"]; ok && ver != "" {
		return ver
	}

	return ""
}

func extractTagFromImage(img string) string {
	// Strip digest if present, e.g. "image:v0.2.224@sha256:..." -> "image:v0.2.224"
	// or "registry.example:5000/operator@sha256:..." -> "registry.example:5000/operator"
	if idx := strings.Index(img, "@"); idx != -1 {
		img = img[:idx]
	}

	// In container image references [registry[:port]/][namespace/]repository[:tag],
	// a tag is present only when the final colon appears AFTER the final slash
	// (distinguishing an image tag from a registry port).
	lastSlash := strings.LastIndex(img, "/")
	lastColon := strings.LastIndex(img, ":")
	if lastColon > lastSlash {
		tag := img[lastColon+1:]
		if tag != "" {
			return tag
		}
	}

	return ""
}
