package getter

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v3/core/pkg/securityexception"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	securityExceptionGroup   = "kubescape.io"
	securityExceptionVersion = "v1"
)

var (
	securityExceptionGVR = schema.GroupVersionResource{
		Group:    securityExceptionGroup,
		Version:  securityExceptionVersion,
		Resource: "securityexceptions",
	}
	clusterSecurityExceptionGVR = schema.GroupVersionResource{
		Group:    securityExceptionGroup,
		Version:  securityExceptionVersion,
		Resource: "clustersecurityexceptions",
	}
)

var _ IExceptionsGetter = &CRDExceptionsGetter{}

// CRDExceptionsGetter retrieves posture exceptions from SecurityException CRDs in-cluster.
type CRDExceptionsGetter struct {
	client    dynamic.Interface
	k8sClient client.Client
}

// NewCRDExceptionsGetter creates a CRD-backed exceptions getter with an injected Kubernetes client.
func NewCRDExceptionsGetter(k8sClient client.Client) *CRDExceptionsGetter {
	getter := &CRDExceptionsGetter{k8sClient: k8sClient}
	if !k8sinterface.IsConnectedToCluster() {
		return getter
	}
	config := k8sinterface.GetK8sConfig()
	if config == nil {
		return getter
	}
	client, err := dynamic.NewForConfig(config)
	if err != nil {
		return getter
	}
	getter.client = client
	return getter
}

func (g *CRDExceptionsGetter) GetExceptions(_ string) ([]armotypes.PostureExceptionPolicy, error) {
	if g == nil || g.client == nil {
		return []armotypes.PostureExceptionPolicy{}, nil
	}

	var out []armotypes.PostureExceptionPolicy

	seList, err := g.client.Resource(securityExceptionGVR).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for i := range seList.Items {
		policies, convErr := convertCRDObjectToPosturePolicies(&seList.Items[i], "SecurityException", g.k8sClient)
		if convErr != nil {
			continue
		}
		out = append(out, policies...)
	}

	cseList, err := g.client.Resource(clusterSecurityExceptionGVR).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for i := range cseList.Items {
		policies, convErr := convertCRDObjectToPosturePolicies(&cseList.Items[i], "ClusterSecurityException", g.k8sClient)
		if convErr != nil {
			continue
		}
		out = append(out, policies...)
	}

	return out, nil
}

func convertCRDObjectToPosturePolicies(
	obj *unstructured.Unstructured,
	kind string,
	k8sClient client.Client,
) ([]armotypes.PostureExceptionPolicy, error) {
	if obj == nil {
		return nil, fmt.Errorf("nil object")
	}
	name := obj.GetName()
	if name == "" {
		return nil, fmt.Errorf("missing name")
	}

	reason, reasonFound, err := unstructured.NestedString(obj.Object, "spec", "reason")
	if err != nil {
		return nil, fmt.Errorf("read reason: %w", err)
	}
	if !reasonFound {
		reason = ""
	}
	expiresAt, expiresAtFound, err := unstructured.NestedString(obj.Object, "spec", "expiresAt")
	if err != nil {
		return nil, fmt.Errorf("read expiresAt: %w", err)
	}
	if !expiresAtFound {
		expiresAt = ""
	}
	postureItems, postureFound, err := unstructured.NestedSlice(obj.Object, "spec", "posture")
	if err != nil {
		return nil, fmt.Errorf("read posture: %w", err)
	}
	if !postureFound {
		postureItems = nil
	}
	resources, err := buildResourceDesignators(obj, kind, k8sClient)
	if err != nil {
		return nil, err
	}

	policies := make([]armotypes.PostureExceptionPolicy, 0, len(postureItems))
	for _, raw := range postureItems {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		controlID, ok := item["controlID"].(string)
		if !ok || controlID == "" {
			continue
		}
		action, ok := item["action"].(string)
		if !ok {
			action = ""
		}
		policy, err := convertSecurityExceptionToPosturePolicy(name, controlID, "", action, expiresAt, reason, resources)
		if err != nil {
			continue
		}
		attrs := securityexception.CRDReferenceAttributes(securityexception.CRDReference{
			Kind:      kind,
			Name:      obj.GetName(),
			Namespace: obj.GetNamespace(),
			UID:       string(obj.GetUID()),
		})
		if policy.Attributes == nil {
			policy.Attributes = map[string]any{}
		}
		for k, v := range attrs {
			policy.Attributes[k] = v
		}
		policies = append(policies, policy)
	}

	return policies, nil
}

func buildResourceDesignators(
	obj *unstructured.Unstructured,
	kind string,
	k8sClient client.Client,
) ([]map[string]string, error) {
	designators := make([]map[string]string, 0, 2)

	namespace := obj.GetNamespace()
	if kind == "SecurityException" && namespace != "" {
		designators = append(designators, map[string]string{identifiers.AttributeNamespace: namespace})
	}

	_, objectSelectorFound, err := unstructured.NestedFieldNoCopy(obj.Object, "spec", "match", "objectSelector")
	if err != nil {
		return nil, fmt.Errorf("read objectSelector: %w", err)
	}
	if objectSelectorFound {
		logger.L().Warning("SecurityException CRD uses unsupported spec.match.objectSelector; skipping",
			helpers.String("name", obj.GetName()),
			helpers.String("namespace", namespace),
			helpers.String("kind", kind),
		)
		return nil, fmt.Errorf("spec.match.objectSelector is not supported")
	}

	namespaceSelectorFound := false
	var namespaceNames []string
	if kind == "ClusterSecurityException" {
		selectorRaw, found, err := unstructured.NestedFieldCopy(obj.Object, "spec", "match", "namespaceSelector")
		if err != nil {
			return nil, fmt.Errorf("read namespaceSelector: %w", err)
		}
		if found {
			namespaceSelectorFound = true
			if k8sClient == nil {
				return nil, fmt.Errorf("namespaceSelector requires a kubernetes client")
			}
			selectorMap, ok := selectorRaw.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("namespaceSelector has unexpected type")
			}
			labelSelector := metav1.LabelSelector{}
			if err := runtime.DefaultUnstructuredConverter.FromUnstructured(selectorMap, &labelSelector); err != nil {
				return nil, fmt.Errorf("decode namespaceSelector: %w", err)
			}
			names, err := resolveNamespaceSelector(labelSelector, k8sClient)
			if err != nil {
				return nil, err
			}
			namespaceNames = names
		}
	}

	resources, resourcesFound, err := unstructured.NestedSlice(obj.Object, "spec", "match", "resources")
	if err != nil {
		return nil, fmt.Errorf("read resources: %w", err)
	}
	if !resourcesFound {
		resources = nil
	}
	resourceDesignators := make([]map[string]string, 0, len(resources))
	for _, raw := range resources {
		resource, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		attrs := map[string]string{}
		if namespace != "" {
			attrs[identifiers.AttributeNamespace] = namespace
		}
		if kindVal, ok := resource["kind"].(string); ok && kindVal != "" {
			attrs[identifiers.AttributeKind] = kindVal
		}
		if nameVal, ok := resource["name"].(string); ok && nameVal != "" {
			attrs[identifiers.AttributeName] = nameVal
		}
		if apiGroup, ok := resource["apiGroup"].(string); ok && apiGroup != "" {
			attrs[identifiers.AttributeApiGroup] = apiGroup
		}
		if len(attrs) > 0 {
			resourceDesignators = append(resourceDesignators, attrs)
		}
	}

	if namespaceSelectorFound {
		if len(namespaceNames) > 0 && len(resourceDesignators) > 0 {
			for _, ns := range namespaceNames {
				for _, res := range resourceDesignators {
					combined := map[string]string{identifiers.AttributeNamespace: ns}
					for k, v := range res {
						combined[k] = v
					}
					designators = append(designators, combined)
				}
			}
		} else if len(namespaceNames) > 0 {
			for _, ns := range namespaceNames {
				designators = append(designators, map[string]string{identifiers.AttributeNamespace: ns})
			}
		}
	} else if len(resourceDesignators) > 0 {
		designators = append(designators, resourceDesignators...)
	}

	// Ensure the exception has at least one scope designator, otherwise exception processor ignores it.
	if len(designators) == 0 && !namespaceSelectorFound {
		designators = append(designators, map[string]string{identifiers.AttributeKind: "*"})
	}

	return designators, nil
}

// resolveNamespaceSelector returns namespace names matching a label selector.
func resolveNamespaceSelector(selector metav1.LabelSelector, k8sClient client.Client) ([]string, error) {
	if k8sClient == nil {
		return nil, fmt.Errorf("kubernetes client is nil")
	}
	parsedSelector := labels.Everything()
	if len(selector.MatchLabels) != 0 || len(selector.MatchExpressions) != 0 {
		selectorStr := metav1.FormatLabelSelector(&selector)
		var err error
		parsedSelector, err = labels.Parse(selectorStr)
		if err != nil {
			return nil, fmt.Errorf("parse namespaceSelector: %w", err)
		}
	}

	var namespaces corev1.NamespaceList
	if err := k8sClient.List(context.Background(), &namespaces, client.MatchingLabelsSelector{Selector: parsedSelector}); err != nil {
		return nil, fmt.Errorf("list namespaces: %w", err)
	}

	names := make([]string, 0, len(namespaces.Items))
	for i := range namespaces.Items {
		names = append(names, namespaces.Items[i].Name)
	}
	sort.Strings(names)
	return names, nil
}

func convertSecurityExceptionToPosturePolicy(
	name string,
	controlID string,
	frameworkName string,
	action string,
	expiresAt string,
	reason string,
	resources []map[string]string,
) (armotypes.PostureExceptionPolicy, error) {
	var actions []armotypes.PostureExceptionPolicyActions
	switch action {
	case "ignore":
		actions = []armotypes.PostureExceptionPolicyActions{armotypes.Disable}
	case "alert_only", "":
		actions = []armotypes.PostureExceptionPolicyActions{armotypes.AlertOnly}
	default:
		return armotypes.PostureExceptionPolicy{}, fmt.Errorf("unknown action %q: must be ignore or alert_only", action)
	}

	var expirationDate *time.Time
	if expiresAt != "" {
		t, err := time.Parse(time.RFC3339, expiresAt)
		if err != nil {
			return armotypes.PostureExceptionPolicy{}, fmt.Errorf("invalid expiresAt %q: %w", expiresAt, err)
		}
		expirationDate = &t
	}

	var designators []identifiers.PortalDesignator
	for _, res := range resources {
		if len(res) == 0 {
			continue
		}
		designators = append(designators, identifiers.PortalDesignator{
			DesignatorType: identifiers.DesignatorAttributes,
			Attributes:     res,
		})
	}

	var reasonPtr *string
	if reason != "" {
		reasonPtr = &reason
	}

	policy := armotypes.PostureExceptionPolicy{
		PolicyType: string(armotypes.PostureExceptionPolicyType),
		Actions:    actions,
		Resources:  designators,
		PosturePolicies: []armotypes.PosturePolicy{
			{
				ControlID:     controlID,
				FrameworkName: frameworkName,
			},
		},
		ExpirationDate: expirationDate,
		Reason:         reasonPtr,
	}
	policy.Name = fmt.Sprintf("%s/%s", name, controlID)

	return policy, nil
}
