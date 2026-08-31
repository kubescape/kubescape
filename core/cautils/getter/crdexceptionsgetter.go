package getter

import (
	"context"
	"fmt"
	"maps"
	"sort"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/pkg/securityexception"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
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
	securityExceptionVersion = "v1beta1"
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

// NewCRDExceptionsGetterWithClients creates a CRD-backed exceptions getter from
// clients that belong to the same scan target. Callers that already resolved a
// Kubernetes target should use this constructor instead of consulting the
// process-global Kubernetes configuration again.
func NewCRDExceptionsGetterWithClients(dynamicClient dynamic.Interface, k8sClient client.Client) *CRDExceptionsGetter {
	return &CRDExceptionsGetter{
		client:    dynamicClient,
		k8sClient: k8sClient,
	}
}

func (g *CRDExceptionsGetter) GetExceptions(ctx context.Context, _ string) ([]armotypes.PostureExceptionPolicy, error) {
	if g == nil || g.client == nil {
		return []armotypes.PostureExceptionPolicy{}, nil
	}

	var out []armotypes.PostureExceptionPolicy

	processFunc := func(list *unstructured.UnstructuredList, kind string) error {
		for i := range list.Items {
			policies, convErr := convertCRDObjectToPosturePolicies(ctx, &list.Items[i], kind, g.k8sClient)
			if convErr != nil {
				if isContextErr(convErr) {
					return convErr
				}
				logger.L().Warning(fmt.Sprintf("skipping %s that failed to convert to posture exceptions", kind),
					helpers.String("name", list.Items[i].GetName()),
					helpers.String("namespace", list.Items[i].GetNamespace()),
					helpers.Error(convErr))
				continue
			}
			out = append(out, policies...)
		}
		return nil
	}

	err := listCRDsWithPagination(ctx, securityExceptionGVR, g.client, func(list *unstructured.UnstructuredList) error {
		return processFunc(list, "SecurityException")
	})
	if err != nil {
		return nil, err
	}

	err = listCRDsWithPagination(ctx, clusterSecurityExceptionGVR, g.client, func(list *unstructured.UnstructuredList) error {
		return processFunc(list, "ClusterSecurityException")
	})
	if err != nil {
		return nil, err
	}

	return out, nil
}

func listCRDsWithPagination(ctx context.Context, gvr schema.GroupVersionResource, dynamicClient dynamic.Interface, processFunc func(*unstructured.UnstructuredList) error) error {
	limit := int64(100)
	continueToken := ""

	for {
		listOptions := metav1.ListOptions{Limit: limit, Continue: continueToken}
		var list *unstructured.UnstructuredList
		var err error

		retries := 5
		backoff := 1 * time.Second
		for i := 0; i < retries; i++ {
			list, err = dynamicClient.Resource(gvr).List(ctx, listOptions)
			if err != nil {
				if k8serrors.IsTooManyRequests(err) {
					logger.L().Warning("Rate limited (429) when listing CRDs, retrying",
						helpers.String("gvr", gvr.String()),
						helpers.Int("retry", i+1))

					if i == retries-1 {
						break
					}

					timer := time.NewTimer(backoff)
					select {
					case <-ctx.Done():
						timer.Stop()
						return ctx.Err()
					case <-timer.C:
						backoff *= 2
						continue
					}
				}
				break
			}
			break
		}

		if err != nil {
			return fmt.Errorf("failed to list %s CRDs: %w", gvr.Resource, err)
		}

		if err := processFunc(list); err != nil {
			return err
		}

		continueToken = list.GetContinue()
		if continueToken == "" {
			break
		}
	}

	return nil
}

func convertCRDObjectToPosturePolicies(
	ctx context.Context,
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
	resources, err := buildResourceDesignators(ctx, obj, kind, k8sClient)
	if err != nil {
		return nil, err
	}
	// objectSelector (matchLabels + matchExpressions) is carried as a policy-level
	// LabelSelector and evaluated by the exception processor with labels.Selector
	// semantics, ANDed against the resource designators above.
	objectSelector, err := decodeObjectSelector(obj)
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
		// frameworkName scopes the exception to a single framework; an empty value
		// (field omitted) applies the exception framework-wide.
		frameworkName, _ := item["frameworkName"].(string)
		policy, err := convertSecurityExceptionToPosturePolicy(name, controlID, frameworkName, action, expiresAt, reason, resources, objectSelector)
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
		maps.Copy(policy.Attributes, attrs)
		policies = append(policies, policy)
	}

	return policies, nil
}

func buildResourceDesignators(
	ctx context.Context,
	obj *unstructured.Unstructured,
	kind string,
	k8sClient client.Client,
) ([]map[string]string, error) {
	designators := make([]map[string]string, 0, 2)

	// A namespaced SecurityException is implicitly scoped to its own namespace. That
	// scope is carried per resource designator below (and as a fallback when no
	// resources/objectSelector narrow it); it must NOT be added as a standalone
	// designator here, or it would be OR'd with the narrower ones and widen the
	// exception back to the whole namespace.
	namespace := obj.GetNamespace()

	// objectSelector is handled separately as a policy-level LabelSelector (see
	// decodeObjectSelector); this function only builds the resource/namespace-scoped
	// designators, which the exception processor ANDs with that selector.

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
			names, err := resolveNamespaceSelector(ctx, labelSelector, k8sClient)
			if err != nil {
				return nil, err
			}
			if len(names) == 0 {
				// A selector matching no namespace must not fall through to the
				// scopeless-exception fallback below: an empty designator list
				// means "matches every cluster" downstream, which would turn a
				// deliberately narrow exception into a cluster-wide one.
				return nil, fmt.Errorf("namespaceSelector matched no namespaces")
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
					maps.Copy(combined, res)
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
	// A namespaced SecurityException with no narrowing falls back to its whole namespace;
	// a cluster-scoped one falls back to all kinds.
	if len(designators) == 0 && !namespaceSelectorFound {
		if kind == "SecurityException" && namespace != "" {
			designators = append(designators, map[string]string{identifiers.AttributeNamespace: namespace})
		} else {
			designators = append(designators, map[string]string{identifiers.AttributeKind: "*"})
		}
	}

	return designators, nil
}

// decodeObjectSelector decodes spec.match.objectSelector into an armotypes.LabelSelector
// carrying the full selector (matchLabels + matchExpressions). It returns nil when the
// selector is absent OR present-but-empty: an empty selector must impose no label
// constraint (the exception is scoped by its other match fields), it must not silently
// widen to match every workload. The exception processor (opa-utils) evaluates a non-nil
// selector with labels.Selector semantics and ANDs it with the resource designators, so
// both matchLabels and matchExpressions are honored.
func decodeObjectSelector(obj *unstructured.Unstructured) (*armotypes.LabelSelector, error) {
	selectorRaw, found, err := unstructured.NestedFieldCopy(obj.Object, "spec", "match", "objectSelector")
	if err != nil {
		return nil, fmt.Errorf("read objectSelector: %w", err)
	}
	if !found {
		return nil, nil
	}
	selectorMap, ok := selectorRaw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("objectSelector has unexpected type")
	}
	labelSelector := metav1.LabelSelector{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(selectorMap, &labelSelector); err != nil {
		return nil, fmt.Errorf("decode objectSelector: %w", err)
	}
	if len(labelSelector.MatchLabels) == 0 && len(labelSelector.MatchExpressions) == 0 {
		return nil, nil // empty selector: no label constraint
	}
	return toArmoLabelSelector(labelSelector), nil
}

// toArmoLabelSelector converts a metav1.LabelSelector to the armotypes.LabelSelector
// shape consumed by PostureExceptionPolicy.ObjectSelector.
func toArmoLabelSelector(sel metav1.LabelSelector) *armotypes.LabelSelector {
	out := &armotypes.LabelSelector{MatchLabels: sel.MatchLabels}
	if len(sel.MatchExpressions) > 0 {
		out.MatchExpressions = make([]armotypes.LabelSelectorRequirement, len(sel.MatchExpressions))
		for i, r := range sel.MatchExpressions {
			out.MatchExpressions[i] = armotypes.LabelSelectorRequirement{
				Key:      r.Key,
				Operator: r.Operator,
				Values:   r.Values,
			}
		}
	}
	return out
}

// resolveNamespaceSelector returns namespace names matching a label selector.
func resolveNamespaceSelector(ctx context.Context, selector metav1.LabelSelector, k8sClient client.Client) ([]string, error) {
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
	if err := k8sClient.List(ctx, &namespaces, client.MatchingLabelsSelector{Selector: parsedSelector}); err != nil {
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
	objectSelector *armotypes.LabelSelector,
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
		PolicyType:     string(armotypes.PostureExceptionPolicyType),
		Actions:        actions,
		Resources:      designators,
		ObjectSelector: objectSelector,
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
