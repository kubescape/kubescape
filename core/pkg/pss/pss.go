// Package pss evaluates a Kubernetes PodSpec against the Pod Security
// Standards (Privileged, Baseline, Restricted) and reports every
// restriction the spec violates. This is a pure analysis package with
// no cluster connectivity, scan-engine, or MCP dependency — the same
// role core/pkg/exposure plays for service exposure analysis and
// core/pkg/rbacgraph plays for RBAC escalation analysis.
//
// The PSS specification is defined at:
// https://kubernetes.io/docs/concepts/security/pod-security-standards/
//
// This implementation targets the Kubernetes v1.31 PSS specification.
// Each check function in checks.go documents which spec section it
// implements and which Kubernetes version introduced or changed it.
package pss

import (
	corev1 "k8s.io/api/core/v1"
)

// Evaluate checks podSpec against the given level and returns every
// Violation. An empty slice means the PodSpec fully complies at that
// level. Evaluating against Privileged always returns nil (the
// Privileged level applies no restrictions).
//
// Each Violation carries the Level at which that check is first
// restricted, so a caller evaluating at Restricted will see both
// Baseline-level and Restricted-level violations in the result.
func Evaluate(podSpec corev1.PodSpec, level Level) []Violation {
	return EvaluateWithAnnotations(podSpec, nil, level)
}

// EvaluateWithAnnotations checks podSpec against the given level and returns every
// Violation, including checks for legacy annotations (e.g. AppArmor) provided in annotations.
func EvaluateWithAnnotations(podSpec corev1.PodSpec, annotations map[string]string, level Level) []Violation {
	if level <= Privileged {
		return nil
	}
	var violations []Violation

	// Pod-level checks
	violations = append(violations, checkHostNamespaces(podSpec)...)
	violations = append(violations, checkHostPorts(podSpec)...)
	violations = append(violations, checkVolumes(podSpec)...)
	violations = append(violations, checkSysctls(podSpec)...)
	violations = append(violations, checkPodSELinux(podSpec)...)
	violations = append(violations, checkPodSeccompProfile(podSpec)...)
	violations = append(violations, checkPodAppArmorProfile(podSpec)...)
	violations = append(violations, checkLegacyAppArmor(annotations)...)

	// Container-level checks — run on standard containers and init containers
	allContainers := []struct {
		list []corev1.Container
		kind string
	}{
		{podSpec.Containers, "container"},
		{podSpec.InitContainers, "initContainer"},
	}

	for _, group := range allContainers {
		for _, c := range group.list {
			violations = append(violations, checkHostProcess(c, group.kind)...)
			violations = append(violations, checkPrivileged(c, group.kind)...)
			violations = append(violations, checkCapabilities(c, group.kind)...)
			violations = append(violations, checkProcMount(c, group.kind)...)
			violations = append(violations, checkSELinux(c, group.kind)...)
			violations = append(violations, checkSeccompProfile(podSpec, c, group.kind)...)
			violations = append(violations, checkAllowPrivilegeEscalation(c, group.kind)...)
			violations = append(violations, checkRunAsNonRoot(podSpec, c, group.kind)...)
			violations = append(violations, checkRunAsUser(podSpec, c, group.kind)...)
			violations = append(violations, checkAppArmorProfile(podSpec, c, group.kind)...)
		}
	}

	// Ephemeral containers — converted to corev1.Container to reuse checks
	for _, ec := range podSpec.EphemeralContainers {
		c := ephemeralToContainer(ec)
		kind := "ephemeralContainer"
		violations = append(violations, checkHostProcess(c, kind)...)
		violations = append(violations, checkPrivileged(c, kind)...)
		violations = append(violations, checkCapabilities(c, kind)...)
		violations = append(violations, checkProcMount(c, kind)...)
		violations = append(violations, checkSELinux(c, kind)...)
		violations = append(violations, checkSeccompProfile(podSpec, c, kind)...)
		violations = append(violations, checkAllowPrivilegeEscalation(c, kind)...)
		violations = append(violations, checkRunAsNonRoot(podSpec, c, kind)...)
		violations = append(violations, checkRunAsUser(podSpec, c, kind)...)
		violations = append(violations, checkAppArmorProfile(podSpec, c, kind)...)
	}

	isWindows := podSpec.OS != nil && podSpec.OS.Name == corev1.Windows

	// Filter to requested level:
	// Violations with v.Level <= requested level are returned.
	// For Windows workloads (spec.os.name == "windows"), Linux-specific Restricted
	// checks (Capabilities, SeccompProfile, AllowPrivilegeEscalation) are exempted per PSS spec.
	var filtered []Violation
	for _, v := range violations {
		if isWindows && v.Level == Restricted &&
			(v.Check == "Capabilities" || v.Check == "SeccompProfile" || v.Check == "AllowPrivilegeEscalation") {
			continue
		}
		if v.Level <= level {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

// PassesAt returns the strictest Level a PodSpec fully complies with.
// Returns Privileged if it has Baseline violations;
// Returns Baseline if it has no Baseline violations but has Restricted violations;
// Returns Restricted if it has no violations at all.
func PassesAt(podSpec corev1.PodSpec) Level {
	return PassesAtWithAnnotations(podSpec, nil)
}

// PassesAtWithAnnotations returns the strictest Level a PodSpec and its annotations fully comply with.
func PassesAtWithAnnotations(podSpec corev1.PodSpec, annotations map[string]string) Level {
	if len(EvaluateWithAnnotations(podSpec, annotations, Baseline)) > 0 {
		return Privileged
	}
	if len(EvaluateWithAnnotations(podSpec, annotations, Restricted)) > 0 {
		return Baseline
	}
	return Restricted
}
