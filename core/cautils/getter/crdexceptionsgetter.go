package getter

import (
	"context"
	"fmt"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// Ensure CRDExceptionsGetter implements IExceptionsGetter
var _ IExceptionsGetter = &CRDExceptionsGetter{}

// GVR definitions for SecurityException CRDs
var (
	securityExceptionGVR = schema.GroupVersionResource{
		Group:    "kubescape.io",
		Version:  "v1beta1",
		Resource: "securityexceptions",
	}
	clusterSecurityExceptionGVR = schema.GroupVersionResource{
		Group:    "kubescape.io",
		Version:  "v1beta1",
		Resource: "clustersecurityexceptions",
	}
)

// CRDExceptionsGetter reads PostureExceptionPolicies from
// SecurityException and ClusterSecurityException CRDs in-cluster.
// It wraps an existing IExceptionsGetter (fallback) and merges CRD
// entries with it. Fallback (cloud/file) takes precedence over CRD.
type CRDExceptionsGetter struct {
	dynamicClient dynamic.Interface
	fallback      IExceptionsGetter
}

// NewCRDExceptionsGetter creates a CRDExceptionsGetter.
// fallback may be nil. If dynamicClient is nil, only fallback is used.
func NewCRDExceptionsGetter(dynamicClient dynamic.Interface, fallback IExceptionsGetter) *CRDExceptionsGetter {
	return &CRDExceptionsGetter{
		dynamicClient: dynamicClient,
		fallback:      fallback,
	}
}

// GetExceptions returns merged exceptions: fallback first, then CRD-based.
// Fallback (cloud/file/github) always takes precedence over CRD exceptions.
func (c *CRDExceptionsGetter) GetExceptions(clusterName string) ([]armotypes.PostureExceptionPolicy, error) {
	var result []armotypes.PostureExceptionPolicy

	// Step 1: get fallback exceptions (cloud or file-based)
	if c.fallback != nil {
		fallbackExceptions, err := c.fallback.GetExceptions(clusterName)
		if err != nil {
			logger.L().Warning("CRDExceptionsGetter: fallback getter failed",
				helpers.Error(err))
		} else {
			result = append(result, fallbackExceptions...)
		}
	}

	// Step 2: if no dynamic client, return fallback only
	if c.dynamicClient == nil {
		return result, nil
	}

	// Step 3: read CRD-based exceptions
	crdExceptions, err := c.getCRDExceptions()
	if err != nil {
		logger.L().Warning("CRDExceptionsGetter: failed to read CRD exceptions, using fallback only",
			helpers.Error(err))
		return result, nil
	}

	// Step 4: merge — fallback already in result, CRD appended after
	result = append(result, crdExceptions...)
	logger.L().Info("CRDExceptionsGetter: loaded exceptions",
		helpers.Int("fallback", len(result)-len(crdExceptions)),
		helpers.Int("crd", len(crdExceptions)))

	return result, nil
}

// getCRDExceptions reads both namespaced SecurityException and
// cluster-scoped ClusterSecurityException resources.
func (c *CRDExceptionsGetter) getCRDExceptions() ([]armotypes.PostureExceptionPolicy, error) {
	ctx := context.Background()
	var policies []armotypes.PostureExceptionPolicy

	// Read namespaced SecurityExceptions (all namespaces)
	seList, err := c.dynamicClient.Resource(securityExceptionGVR).
		Namespace("").
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing SecurityExceptions: %w", err)
	}

	for _, item := range seList.Items {
		policy, err := convertToPolicyException(item.Object)
		if err != nil {
			logger.L().Warning("CRDExceptionsGetter: skipping invalid SecurityException",
				helpers.String("name", item.GetName()),
				helpers.String("namespace", item.GetNamespace()),
				helpers.Error(err))
			continue
		}
		if isExpired(policy) {
			logger.L().Debug("CRDExceptionsGetter: skipping expired exception",
				helpers.String("name", item.GetName()))
			continue
		}
		policies = append(policies, *policy)
		go emitMatchEvent(ctx, c.dynamicClient, item.GetNamespace(), item.GetName(), firstControlID(policy))
	}

	// Read cluster-scoped ClusterSecurityExceptions
	cseList, err := c.dynamicClient.Resource(clusterSecurityExceptionGVR).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing ClusterSecurityExceptions: %w", err)
	}

	for _, item := range cseList.Items {
		policy, err := convertToPolicyException(item.Object)
		if err != nil {
			logger.L().Warning("CRDExceptionsGetter: skipping invalid ClusterSecurityException",
				helpers.String("name", item.GetName()),
				helpers.Error(err))
			continue
		}
		if isExpired(policy) {
			logger.L().Debug("CRDExceptionsGetter: skipping expired cluster exception",
				helpers.String("name", item.GetName()))
			continue
		}
		policies = append(policies, *policy)
		go emitMatchEvent(ctx, c.dynamicClient, item.GetNamespace(), item.GetName(), firstControlID(policy))
	}

	return policies, nil
}

// convertToPolicyException converts an unstructured SecurityException object
// to armotypes.PostureExceptionPolicy using exact real struct fields:
//   - PostureExceptionPolicy.Actions []PostureExceptionPolicyActions
//   - PostureExceptionPolicy.PosturePolicies []PosturePolicy
//   - PostureExceptionPolicy.Resources []identifiers.PortalDesignator
//   - PostureExceptionPolicy.Reason *string
//   - PostureExceptionPolicy.ExpirationDate *time.Time
func convertToPolicyException(obj map[string]interface{}) (*armotypes.PostureExceptionPolicy, error) {
	metadata, _ := obj["metadata"].(map[string]interface{})
	spec, ok := obj["spec"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("missing spec")
	}

	name, _ := metadata["name"].(string)
	namespace, _ := metadata["namespace"].(string)
	reason, _ := spec["reason"].(string)
	expiresAt, _ := spec["expiresAt"].(string)

	policy := &armotypes.PostureExceptionPolicy{
		PortalBase: armotypes.PortalBase{
			Name: fmt.Sprintf("crd-%s-%s", namespace, name),
		},
		PolicyType: string(armotypes.PostureExceptionPolicyType),
		Reason:     &reason,
	}

	// Parse expiresAt → ExpirationDate *time.Time
	if expiresAt != "" {
		t, err := time.Parse(time.RFC3339, expiresAt)
		if err == nil {
			policy.ExpirationDate = &t
		}
	}

	// Map posture[] → Actions + PosturePolicies
	// CRD action "ignore" → Disable, "alert_only" → AlertOnly
	if posture, ok := spec["posture"].([]interface{}); ok {
		actionSet := map[armotypes.PostureExceptionPolicyActions]bool{}
		for _, p := range posture {
			pMap, ok := p.(map[string]interface{})
			if !ok {
				continue
			}
			controlID, _ := pMap["controlID"].(string)
			frameworkName, _ := pMap["frameworkName"].(string)
			action, _ := pMap["action"].(string)

			// map CRD action → PostureExceptionPolicyActions
			var policyAction armotypes.PostureExceptionPolicyActions
			switch action {
			case "alert_only":
				policyAction = armotypes.AlertOnly
			default: // "ignore"
				policyAction = armotypes.Disable
			}
			actionSet[policyAction] = true

			policy.PosturePolicies = append(policy.PosturePolicies,
				armotypes.PosturePolicy{
					ControlID:     controlID,
					FrameworkName: frameworkName,
				})
		}
		// deduplicated actions
		for a := range actionSet {
			policy.Actions = append(policy.Actions, a)
		}
	}

	// Map match → Resources []identifiers.PortalDesignator
	if match, ok := spec["match"].(map[string]interface{}); ok {
		designator := mapMatchToDesignator(match, namespace)
		policy.Resources = []identifiers.PortalDesignator{designator}
	}

	return policy, nil
}

// mapMatchToDesignator converts CRD match fields to identifiers.PortalDesignator.
// resources[].kind  → Attributes["kind"]
// resources[].name  → Attributes["name"]
// objectSelector    → Attributes["label.<key>"]
// namespaceSelector → Attributes["namespace.label.<key>"]
// namespace (from object metadata) → Attributes["namespace"]
func mapMatchToDesignator(match map[string]interface{}, defaultNamespace string) identifiers.PortalDesignator {
	attrs := map[string]string{}

	if defaultNamespace != "" {
		attrs["namespace"] = defaultNamespace
	}

	// resources → kind + name
	if resources, ok := match["resources"].([]interface{}); ok && len(resources) > 0 {
		if res, ok := resources[0].(map[string]interface{}); ok {
			if kind, ok := res["kind"].(string); ok && kind != "" {
				attrs["kind"] = kind
			}
			if name, ok := res["name"].(string); ok && name != "" {
				attrs["name"] = name
			}
		}
	}

	// objectSelector matchLabels → label attributes
	if objSel, ok := match["objectSelector"].(map[string]interface{}); ok {
		if matchLabels, ok := objSel["matchLabels"].(map[string]interface{}); ok {
			for k, v := range matchLabels {
				attrs["label."+k] = fmt.Sprintf("%v", v)
			}
		}
	}

	// namespaceSelector matchLabels
	if nsSel, ok := match["namespaceSelector"].(map[string]interface{}); ok {
		if matchLabels, ok := nsSel["matchLabels"].(map[string]interface{}); ok {
			for k, v := range matchLabels {
				attrs["namespace.label."+k] = fmt.Sprintf("%v", v)
			}
		}
	}

	return identifiers.PortalDesignator{
		DesignatorType: identifiers.DesignatorAttributes,
		Attributes:     attrs,
	}
}

// isExpired returns true if the exception's ExpirationDate is in the past.
func isExpired(policy *armotypes.PostureExceptionPolicy) bool {
	if policy.ExpirationDate == nil {
		return false
	}
	return time.Now().UTC().After(policy.ExpirationDate.UTC())
}

// emitMatchEvent emits a Kubernetes Event on the SecurityException resource
// when it is matched during a scan. This provides observability — users can
// run `kubectl get events` to see which exceptions were applied in each scan.
func emitMatchEvent(ctx context.Context, dynamicClient dynamic.Interface, namespace, name, controlID string) {
	eventsGVR := schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "events",
	}

	if namespace == "" {
		namespace = "default"
	}

	now := metav1.Now()
	event := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Event",
		"metadata": map[string]interface{}{
			"generateName": "security-exception-matched-",
			"namespace":    namespace,
		},
		"involvedObject": map[string]interface{}{
			"apiVersion": "kubescape.io/v1beta1",
			"kind":       "SecurityException",
			"name":       name,
			"namespace":  namespace,
		},
		"reason":  "ExceptionMatched",
		"message": fmt.Sprintf("SecurityException matched during scan: control %s excepted", controlID),
		"type":    "Normal",
		"firstTimestamp": now.UTC().Format(time.RFC3339),
		"lastTimestamp":  now.UTC().Format(time.RFC3339),
		"count":          int64(1),
		"source": map[string]interface{}{
			"component": "kubescape",
		},
	}

	_, err := dynamicClient.Resource(eventsGVR).
		Namespace(namespace).
		Create(ctx, &unstructured.Unstructured{Object: event}, metav1.CreateOptions{})
	if err != nil {
		logger.L().Warning("CRDExceptionsGetter: failed to emit match event",
			helpers.String("name", name),
			helpers.Error(err))
	}
}

// firstControlID returns the first control ID from a policy for event labeling.
func firstControlID(policy *armotypes.PostureExceptionPolicy) string {
	if len(policy.PosturePolicies) > 0 {
		return policy.PosturePolicies[0].ControlID
	}
	return "unknown"
}
