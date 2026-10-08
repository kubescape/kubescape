package pss

import (
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
)

// ExtractPodSpec extracts the corev1.PodSpec from an unstructured workload
// object. Supports Deployment, DaemonSet, StatefulSet, ReplicaSet, Job,
// CronJob (all at spec.template.spec or spec.jobTemplate.spec.template.spec)
// and Pod (at spec).
//
// Returns an error if the kind is unsupported or the spec cannot be found or decoded.
func ExtractPodSpec(kind string, obj map[string]any) (corev1.PodSpec, error) {
	var specPath []string
	switch kind {
	case "Pod":
		specPath = []string{"spec"}
	case "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job":
		specPath = []string{"spec", "template", "spec"}
	case "CronJob":
		specPath = []string{"spec", "jobTemplate", "spec", "template", "spec"}
	default:
		return corev1.PodSpec{}, fmt.Errorf("unsupported kind %q", kind)
	}

	raw := navigatePath(obj, specPath)
	if raw == nil {
		return corev1.PodSpec{}, fmt.Errorf("no PodSpec found at %v", specPath)
	}

	return decodePodSpec(raw)
}

// ExtractPodAnnotations extracts the pod or template annotations from an unstructured
// workload object. Supports Deployment, DaemonSet, StatefulSet, ReplicaSet, Job,
// CronJob (at spec.template.metadata.annotations or spec.jobTemplate.spec.template.metadata.annotations)
// and Pod (at metadata.annotations).
func ExtractPodAnnotations(kind string, obj map[string]any) map[string]string {
	var annotPath []string
	switch kind {
	case "Pod":
		annotPath = []string{"metadata", "annotations"}
	case "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job":
		annotPath = []string{"spec", "template", "metadata", "annotations"}
	case "CronJob":
		annotPath = []string{"spec", "jobTemplate", "spec", "template", "metadata", "annotations"}
	default:
		return nil
	}

	raw := navigatePath(obj, annotPath)
	if raw == nil {
		return nil
	}

	switch m := raw.(type) {
	case map[string]string:
		return m
	case map[string]any:
		res := make(map[string]string, len(m))
		for k, v := range m {
			if s, ok := v.(string); ok {
				res[k] = s
			}
		}
		return res
	}
	return nil
}

// EvaluateUnstructured extracts the PodSpec and relevant Pod or template annotations
// from an unstructured object and evaluates it against the given PSS Level in a single step.
func EvaluateUnstructured(kind string, obj map[string]any, level Level) ([]Violation, error) {
	podSpec, err := ExtractPodSpec(kind, obj)
	if err != nil {
		return nil, err
	}
	return EvaluateUnstructuredWithMetadata(kind, obj, podSpec, level), nil
}

// EvaluateUnstructuredWithMetadata evaluates an extracted PodSpec alongside the metadata
// annotations present on the unstructured workload object.
func EvaluateUnstructuredWithMetadata(kind string, obj map[string]any, podSpec corev1.PodSpec, level Level) []Violation {
	annotations := ExtractPodAnnotations(kind, obj)
	return EvaluateWithAnnotations(podSpec, annotations, level)
}

// WorkloadResultFromUnstructured extracts the PodSpec from an unstructured object
// and produces a complete WorkloadResult with violations and strictest compliance level.
func WorkloadResultFromUnstructured(kind, name, namespace string, obj map[string]any, level Level) (WorkloadResult, error) {
	podSpec, err := ExtractPodSpec(kind, obj)
	if err != nil {
		return WorkloadResult{}, err
	}
	annotations := ExtractPodAnnotations(kind, obj)
	return WorkloadResult{
		Kind:       kind,
		Name:       name,
		Namespace:  namespace,
		Violations: EvaluateWithAnnotations(podSpec, annotations, level),
		PassesAt:   PassesAtWithAnnotations(podSpec, annotations),
	}, nil
}

func decodePodSpec(raw any) (corev1.PodSpec, error) {
	b, err := json.Marshal(raw)
	if err != nil {
		return corev1.PodSpec{}, fmt.Errorf("marshal: %w", err)
	}
	var ps corev1.PodSpec
	if err := json.Unmarshal(b, &ps); err != nil {
		return corev1.PodSpec{}, fmt.Errorf("unmarshal: %w", err)
	}
	return ps, nil
}

func navigatePath(obj map[string]any, path []string) any {
	current := any(obj)
	for _, key := range path {
		m, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = m[key]
	}
	return current
}
