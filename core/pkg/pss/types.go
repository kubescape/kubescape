package pss

import "strings"

// Level represents a Pod Security Standards enforcement level.
// Levels are ordered: Privileged < Baseline < Restricted.
type Level int

const (
	// Privileged is unrestricted — no checks applied.
	Privileged Level = iota
	// Baseline prevents known privilege escalations — a minimal
	// policy for non-hardened workloads.
	Baseline
	// Restricted is the most restrictive standard — requires
	// following current Pod hardening best practices.
	Restricted
)

func (l Level) String() string {
	switch l {
	case Privileged:
		return "Privileged"
	case Baseline:
		return "Baseline"
	case Restricted:
		return "Restricted"
	default:
		return "unknown"
	}
}

// ParseLevel converts a string to a Level. Returns (Privileged, false) for
// unrecognized strings. Comparison is case-insensitive.
func ParseLevel(s string) (Level, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "privileged":
		return Privileged, true
	case "baseline":
		return Baseline, true
	case "restricted":
		return Restricted, true
	default:
		return Privileged, false
	}
}

// Violation is a single PSS restriction a PodSpec violates.
type Violation struct {
	// Check is the PSS restriction category ID, matching the
	// Kubernetes spec's heading (e.g. "HostNetwork", "Privileged",
	// "Capabilities"). Stable across versions.
	Check string

	// Level is the strictest PSS level that forbids this configuration.
	// A Baseline violation means both Baseline and Restricted forbid it.
	Level Level

	// Container is the name of the container that violates this check.
	// Empty for pod-level checks (e.g. HostNetwork, Volumes).
	Container string

	// ContainerType is "container", "initContainer", or
	// "ephemeralContainer". Empty for pod-level checks.
	ContainerType string

	// Description is a human-readable explanation including the offending
	// value (e.g. "adds capability NET_RAW; Restricted requires
	// dropping ALL").
	Description string
}

// WorkloadResult aggregates violations for a single workload.
type WorkloadResult struct {
	Kind       string
	Name       string
	Namespace  string
	Violations []Violation
	// PassesAt is the strictest level this workload fully complies with.
	// Privileged if it violates Baseline checks; Baseline if it passes
	// Baseline but violates Restricted; Restricted if fully compliant.
	PassesAt Level
}
