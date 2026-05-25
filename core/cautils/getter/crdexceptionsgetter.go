package getter

import (
	"context"
	"fmt"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v3/core/pkg/securityexception"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
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
	client  dynamic.Interface
	primary IExceptionsGetter
}

func NewCRDExceptionsGetter(primary IExceptionsGetter) *CRDExceptionsGetter {
	getter := &CRDExceptionsGetter{primary: primary}
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

func (g *CRDExceptionsGetter) GetExceptions(clusterName string) ([]armotypes.PostureExceptionPolicy, error) {
	if g == nil {
		return []armotypes.PostureExceptionPolicy{}, nil
	}

	var cloudExceptions []armotypes.PostureExceptionPolicy
	if g.primary != nil {
		var err error
		cloudExceptions, err = g.primary.GetExceptions(clusterName)
		if err != nil {
			return nil, err
		}
	}

	if g.client == nil {
		return deduplicateExceptions(cloudExceptions, nil), nil
	}

	var crdExceptions []armotypes.PostureExceptionPolicy

	seList, err := g.client.Resource(securityExceptionGVR).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		if g.primary != nil {
			return deduplicateExceptions(cloudExceptions, nil), nil
		}
		return nil, err
	}
	for i := range seList.Items {
		policies, convErr := convertCRDObjectToPosturePolicies(&seList.Items[i], "SecurityException")
		if convErr != nil {
			continue
		}
		crdExceptions = append(crdExceptions, policies...)
	}

	cseList, err := g.client.Resource(clusterSecurityExceptionGVR).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		if g.primary != nil {
			return deduplicateExceptions(cloudExceptions, nil), nil
		}
		return nil, err
	}
	for i := range cseList.Items {
		policies, convErr := convertCRDObjectToPosturePolicies(&cseList.Items[i], "ClusterSecurityException")
		if convErr != nil {
			continue
		}
		crdExceptions = append(crdExceptions, policies...)
	}

	return deduplicateExceptions(cloudExceptions, crdExceptions), nil
}

func convertCRDObjectToPosturePolicies(obj *unstructured.Unstructured, kind string) ([]armotypes.PostureExceptionPolicy, error) {
	if obj == nil {
		return nil, fmt.Errorf("nil object")
	}
	name := obj.GetName()
	if name == "" {
		return nil, fmt.Errorf("missing name")
	}

	reason, _, _ := unstructured.NestedString(obj.Object, "spec", "reason")
	expiresAt, _, _ := unstructured.NestedString(obj.Object, "spec", "expiresAt")
	postureItems, _, _ := unstructured.NestedSlice(obj.Object, "spec", "posture")
	resources, err := buildResourceDesignators(obj, kind)
	if err != nil {
		return nil, err
	}

	policies := make([]armotypes.PostureExceptionPolicy, 0, len(postureItems))
	for _, raw := range postureItems {
		item, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		controlID, _ := item["controlID"].(string)
		if controlID == "" {
			continue
		}
		action, _ := item["action"].(string)
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
			policy.Attributes = map[string]interface{}{}
		}
		for k, v := range attrs {
			policy.Attributes[k] = v
		}
		policies = append(policies, policy)
	}

	return policies, nil
}

func buildResourceDesignators(obj *unstructured.Unstructured, kind string) ([]map[string]string, error) {
	designators := make([]map[string]string, 0, 2)

	namespace := obj.GetNamespace()
	if kind == "SecurityException" && namespace != "" {
		designators = append(designators, map[string]string{identifiers.AttributeNamespace: namespace})
	}

	if _, found, _ := unstructured.NestedFieldNoCopy(obj.Object, "spec", "match", "objectSelector"); found {
		logger.L().Warning("SecurityException CRD uses unsupported spec.match.objectSelector; skipping",
			helpers.String("name", obj.GetName()),
			helpers.String("namespace", namespace),
			helpers.String("kind", kind),
		)
		return nil, fmt.Errorf("spec.match.objectSelector is not supported")
	}

	resources, _, _ := unstructured.NestedSlice(obj.Object, "spec", "match", "resources")
	for _, raw := range resources {
		resource, ok := raw.(map[string]interface{})
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
			designators = append(designators, attrs)
		}
	}

	// Ensure the exception has at least one scope designator, otherwise exception processor ignores it.
	if len(designators) == 0 {
		designators = append(designators, map[string]string{identifiers.AttributeKind: "*"})
	}

	return designators, nil
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

const exceptionKeySeparator = "\x1f"

func deduplicateExceptions(
	cloudExceptions []armotypes.PostureExceptionPolicy,
	crdExceptions []armotypes.PostureExceptionPolicy,
) []armotypes.PostureExceptionPolicy {
	if len(cloudExceptions) == 0 && len(crdExceptions) == 0 {
		return []armotypes.PostureExceptionPolicy{}
	}

	covered := make(map[string]struct{}, len(cloudExceptions))
	for _, cloud := range cloudExceptions {
		for _, policy := range cloud.PosturePolicies {
			if policy.ControlID == "" {
				continue
			}
			for _, resource := range cloud.Resources {
				key := exceptionDedupKey(policy.ControlID, resource)
				covered[key] = struct{}{}
			}
		}
	}

	merged := make([]armotypes.PostureExceptionPolicy, 0, len(cloudExceptions)+len(crdExceptions))
	merged = append(merged, cloudExceptions...)
	if len(crdExceptions) == 0 {
		return merged
	}

	for _, crd := range crdExceptions {
		if len(crd.Resources) == 0 || len(crd.PosturePolicies) == 0 {
			merged = append(merged, crd)
			continue
		}
		filteredResources := make([]identifiers.PortalDesignator, 0, len(crd.Resources))
		for _, resource := range crd.Resources {
			if !isResourceCovered(crd.PosturePolicies, resource, covered) {
				filteredResources = append(filteredResources, resource)
			}
		}
		if len(filteredResources) == 0 {
			continue
		}
		filteredPolicy := crd
		filteredPolicy.Resources = filteredResources
		merged = append(merged, filteredPolicy)
	}

	return merged
}

func isResourceCovered(
	policies []armotypes.PosturePolicy,
	resource identifiers.PortalDesignator,
	covered map[string]struct{},
) bool {
	for _, policy := range policies {
		if policy.ControlID == "" {
			continue
		}
		key := exceptionDedupKey(policy.ControlID, resource)
		if _, found := covered[key]; found {
			return true
		}
	}
	return false
}

// exceptionDedupKey builds a deterministic key using a separator not valid in Kubernetes names or kinds.
func exceptionDedupKey(controlID string, designator identifiers.PortalDesignator) string {
	return controlID + exceptionKeySeparator + designator.GetNamespace() + exceptionKeySeparator + designator.GetName() + exceptionKeySeparator + designator.GetKind()
}
