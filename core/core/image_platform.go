package core

import (
	"sort"
	"strings"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/pkg/imagescan"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	stableOSLabel   = "kubernetes.io/os"
	stableArchLabel = "kubernetes.io/arch"
	betaOSLabel     = "beta.kubernetes.io/os"
	betaArchLabel   = "beta.kubernetes.io/arch"
)

// ImageScanTarget is an image plus the OCI platform variant that must be
// resolved from a registry index. Platform is empty only when neither the user
// nor the workload supplies enough information to make a safe choice.
type ImageScanTarget struct {
	Image    string
	Platform string
	// SkipUnavailable is set only for automatically inferred fan-out targets.
	// Explicit and uniquely required platforms remain fail-closed.
	SkipUnavailable bool
}

func (t ImageScanTarget) String() string {
	return imageScanTarget(t.Image, t.Platform)
}

// buildNodePlatformIndex records the concrete platform of Node resources that
// were already collected for the posture scan. No additional Kubernetes API
// request is needed, and scheduled Pods can be tied to the same image variant
// the kubelet actually selected.
func buildNodePlatformIndex(resources map[string]workloadinterface.IMetadata) map[string]string {
	index := make(map[string]string)
	for _, resource := range resources {
		if resource == nil || !strings.EqualFold(resource.GetKind(), "Node") {
			continue
		}
		if platform := platformFromNode(resource); platform != "" {
			index[resource.GetName()] = platform
		}
	}
	return index
}

func platformFromNode(node workloadinterface.IMetadata) string {
	labels, _, _ := unstructured.NestedStringMap(node.GetObject(), "metadata", "labels")
	osName := firstNonEmpty(labels[stableOSLabel], labels[betaOSLabel])
	architecture := firstNonEmpty(labels[stableArchLabel], labels[betaArchLabel])

	// Kubernetes normally publishes the stable labels, but status.nodeInfo is
	// authoritative enough to recover older or deliberately stripped Nodes.
	if osName == "" {
		osName, _, _ = unstructured.NestedString(node.GetObject(), "status", "nodeInfo", "operatingSystem")
	}
	if architecture == "" {
		architecture, _, _ = unstructured.NestedString(node.GetObject(), "status", "nodeInfo", "architecture")
	}

	return canonicalInferredPlatform(osName, architecture)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func canonicalInferredPlatform(osName, architecture string) string {
	if osName == "" || architecture == "" {
		return ""
	}
	platform, err := imagescan.NormalizePlatform(osName + "/" + architecture)
	if err != nil {
		return ""
	}
	return platform
}

// inferWorkloadPlatforms returns every concrete platform allowed by the
// workload's hard scheduling constraints. It deliberately ignores preferred
// affinity because the scheduler may choose a different platform. Partial and
// negative constraints are evaluated against the collected Node inventory.
func inferWorkloadPlatforms(workload *workloadinterface.Workload, nodePlatforms map[string]string) []string {
	return selectWorkloadPlatforms(workload, nodePlatforms).platforms
}

type workloadPlatformSelection struct {
	platforms       []string
	constrained     bool
	skipUnavailable bool
}

func selectWorkloadPlatforms(workload *workloadinterface.Workload, nodePlatforms map[string]string) workloadPlatformSelection {
	if workload == nil {
		return workloadPlatformSelection{}
	}
	podSpec, err := workload.GetPodSpec()
	if err != nil || podSpec == nil {
		return workloadPlatformSelection{}
	}

	if podSpec.NodeName != "" {
		if platform := nodePlatforms[podSpec.NodeName]; platform != "" {
			return workloadPlatformSelection{platforms: []string{platform}, constrained: true}
		}
	}

	platforms := platformsFromSchedulingConstraints(podSpec)
	if len(platforms) > 0 {
		return workloadPlatformSelection{
			platforms: platforms, constrained: true, skipUnavailable: len(platforms) > 1,
		}
	}

	observed := uniqueNodePlatforms(nodePlatforms)
	filtered, constrained := filterObservedPlatforms(podSpec, observed)
	if constrained {
		return workloadPlatformSelection{
			platforms:       filtered,
			constrained:     true,
			skipUnavailable: len(filtered) > 1,
		}
	}

	// An unconstrained workload can land on any node in a heterogeneous
	// cluster. These variants are best-effort because a registry index can omit
	// an architecture that is present in the cluster.
	return workloadPlatformSelection{
		platforms:       observed,
		skipUnavailable: len(observed) > 1,
	}
}

func filterObservedPlatforms(podSpec *corev1.PodSpec, observed []string) ([]string, bool) {
	if podSpec == nil {
		return observed, false
	}

	hasConstraint := false
	for key := range podSpec.NodeSelector {
		if isPlatformLabel(key) {
			hasConstraint = true
		}
	}
	if required := getRequiredNodeAffinity(podSpec); required != nil {
		for _, term := range required.NodeSelectorTerms {
			for _, expression := range term.MatchExpressions {
				if isFilterablePlatformExpression(expression) {
					hasConstraint = true
				}
			}
		}
	}
	if !hasConstraint {
		return observed, false
	}

	filtered := make([]string, 0, len(observed))
	for _, platform := range observed {
		parts := strings.Split(platform, "/")
		if len(parts) < 2 {
			continue
		}
		labels := map[string]string{
			stableOSLabel: parts[0], betaOSLabel: parts[0],
			stableArchLabel: parts[1], betaArchLabel: parts[1],
		}
		if platformMatchesSchedulingConstraints(podSpec, labels) {
			filtered = append(filtered, platform)
		}
	}
	return filtered, true
}

func platformMatchesSchedulingConstraints(podSpec *corev1.PodSpec, labels map[string]string) bool {
	for key, expected := range podSpec.NodeSelector {
		if isPlatformLabel(key) && labels[key] != expected {
			return false
		}
	}

	required := getRequiredNodeAffinity(podSpec)
	if required == nil {
		return true
	}
	for _, term := range required.NodeSelectorTerms {
		matches := true
		for _, expression := range term.MatchExpressions {
			if isFilterablePlatformExpression(expression) && !platformExpressionMatches(expression, labels) {
				matches = false
				break
			}
		}
		if matches {
			return true
		}
	}
	return false
}

func isFilterablePlatformExpression(expression corev1.NodeSelectorRequirement) bool {
	if !isPlatformLabel(expression.Key) {
		return false
	}
	return expression.Operator == corev1.NodeSelectorOpIn || expression.Operator == corev1.NodeSelectorOpNotIn
}

func getRequiredNodeAffinity(podSpec *corev1.PodSpec) *corev1.NodeSelector {
	if podSpec == nil || podSpec.Affinity == nil || podSpec.Affinity.NodeAffinity == nil {
		return nil
	}
	return podSpec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution
}

func isPlatformLabel(key string) bool {
	switch key {
	case stableOSLabel, betaOSLabel, stableArchLabel, betaArchLabel:
		return true
	default:
		return false
	}
}

func platformExpressionMatches(expression corev1.NodeSelectorRequirement, labels map[string]string) bool {
	value, exists := labels[expression.Key]
	contains := func() bool {
		for _, candidate := range expression.Values {
			if value == candidate {
				return true
			}
		}
		return false
	}

	switch expression.Operator {
	case corev1.NodeSelectorOpIn:
		return exists && contains()
	case corev1.NodeSelectorOpNotIn:
		return exists && !contains()
	default:
		return false
	}
}

func uniqueNodePlatforms(nodePlatforms map[string]string) []string {
	set := make(map[string]struct{}, len(nodePlatforms))
	for _, platform := range nodePlatforms {
		if platform != "" {
			set[platform] = struct{}{}
		}
	}
	platforms := make([]string, 0, len(set))
	for platform := range set {
		platforms = append(platforms, platform)
	}
	sort.Strings(platforms)
	return platforms
}

type platformConstraint struct {
	operatingSystems map[string]struct{}
	architectures    map[string]struct{}
	invalid          bool
}

func newPlatformConstraint() platformConstraint {
	return platformConstraint{
		operatingSystems: make(map[string]struct{}),
		architectures:    make(map[string]struct{}),
	}
}

func (c platformConstraint) clone() platformConstraint {
	cloned := newPlatformConstraint()
	cloned.invalid = c.invalid
	for value := range c.operatingSystems {
		cloned.operatingSystems[value] = struct{}{}
	}
	for value := range c.architectures {
		cloned.architectures[value] = struct{}{}
	}
	return cloned
}

func (c *platformConstraint) addExact(key, value string) {
	c.addAllowed(key, []string{value})
}

func (c *platformConstraint) addAllowed(key string, values []string) {
	target, relevant := c.valuesForLabel(key)
	if !relevant {
		return
	}

	allowed := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			allowed[value] = struct{}{}
		}
	}
	if len(allowed) == 0 {
		c.invalid = true
		return
	}

	if len(target) == 0 {
		for value := range allowed {
			target[value] = struct{}{}
		}
		return
	}

	for value := range target {
		if _, ok := allowed[value]; !ok {
			delete(target, value)
		}
	}
	if len(target) == 0 {
		c.invalid = true
	}
}

func (c *platformConstraint) markAmbiguous(key string) {
	if _, relevant := c.valuesForLabel(key); relevant {
		c.invalid = true
	}
}

func (c *platformConstraint) valuesForLabel(key string) (map[string]struct{}, bool) {
	switch key {
	case stableOSLabel, betaOSLabel:
		return c.operatingSystems, true
	case stableArchLabel, betaArchLabel:
		return c.architectures, true
	default:
		return nil, false
	}
}

func platformsFromSchedulingConstraints(podSpec *corev1.PodSpec) []string {
	if podSpec == nil {
		return nil
	}

	base := newPlatformConstraint()
	for key, value := range podSpec.NodeSelector {
		base.addExact(key, value)
	}
	if base.invalid {
		return nil
	}

	terms := []corev1.NodeSelectorTerm{{}}
	if podSpec.Affinity != nil && podSpec.Affinity.NodeAffinity != nil && podSpec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution != nil {
		terms = podSpec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms
		if len(terms) == 0 {
			return nil
		}
	}

	platformSet := make(map[string]struct{})
	for _, term := range terms {
		constraint := base.clone()
		for _, expression := range term.MatchExpressions {
			switch expression.Operator {
			case corev1.NodeSelectorOpIn:
				constraint.addAllowed(expression.Key, expression.Values)
			case corev1.NodeSelectorOpNotIn, corev1.NodeSelectorOpExists, corev1.NodeSelectorOpDoesNotExist, corev1.NodeSelectorOpGt, corev1.NodeSelectorOpLt:
				constraint.markAmbiguous(expression.Key)
			default:
				constraint.markAmbiguous(expression.Key)
			}
		}
		if constraint.invalid {
			return nil
		}
		if len(constraint.operatingSystems) == 0 || len(constraint.architectures) == 0 {
			// This OR branch could schedule on a platform that is not represented
			// by the other branches, so returning a partial set would be unsafe.
			return nil
		}
		for osName := range constraint.operatingSystems {
			for architecture := range constraint.architectures {
				platform := canonicalInferredPlatform(osName, architecture)
				if platform == "" {
					return nil
				}
				platformSet[platform] = struct{}{}
			}
		}
	}

	platforms := make([]string, 0, len(platformSet))
	for platform := range platformSet {
		platforms = append(platforms, platform)
	}
	sort.Strings(platforms)
	return platforms
}
