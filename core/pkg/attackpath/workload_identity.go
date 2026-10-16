package attackpath

import (
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/pkg/vulnexposure"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// serviceAccountTokenMountPath is where the ServiceAccount admission plugin
// mounts the automatic token volume. The plugin skips a container that already
// has a volumeMount at exactly this path.
//
//nolint:gosec // G101: a mount path, not a credential
const serviceAccountTokenMountPath = "/var/run/secrets/kubernetes.io/serviceaccount"

// supportedWorkloadKinds are the kinds whose pod spec the resolver reads. They
// match the kinds the vulnerability-exposure tool resolves a workload for.
var supportedWorkloadKinds = map[string]bool{
	"Pod": true, "Deployment": true, "StatefulSet": true, "DaemonSet": true,
	"ReplicaSet": true, "Job": true, "CronJob": true,
}

// IsSupportedWorkloadKind reports whether the resolver reads the pod spec of
// kind. Anything else is reported unresolved, never guessed at.
func IsSupportedWorkloadKind(kind string) bool { return supportedWorkloadKinds[kind] }

type serviceAccountKey struct{ namespace, name string }

// ServiceAccountIndex answers the one question the token resolution needs of a
// ServiceAccount object: whether it was collected, and its own
// automountServiceAccountToken. Kubernetes has no namespace-level automount
// setting; the pod spec and the ServiceAccount are the only two levels.
type ServiceAccountIndex struct {
	automount map[serviceAccountKey]*bool
}

// NewServiceAccountIndex indexes the collected ServiceAccount objects.
func NewServiceAccountIndex(serviceAccounts []corev1.ServiceAccount) *ServiceAccountIndex {
	idx := &ServiceAccountIndex{automount: make(map[serviceAccountKey]*bool, len(serviceAccounts))}
	for _, sa := range serviceAccounts {
		idx.automount[serviceAccountKey{sa.Namespace, sa.Name}] = sa.AutomountServiceAccountToken
	}
	return idx
}

func (i *ServiceAccountIndex) lookup(namespace, name string) (automount *bool, found bool) {
	if i == nil {
		return nil, false
	}
	automount, found = i.automount[serviceAccountKey{namespace, name}]
	return automount, found
}

// ServiceAccountResolution is what the workload spec says about the
// ServiceAccount a workload's pods run as and whether a token reaches them.
// It is derived from the object alone: it says nothing about what the
// ServiceAccount may do, and Token is the spec's static assessment, not proof
// that a process in the pod can use a credential.
type ServiceAccountResolution struct {
	Resolved bool
	// Reason says why Resolved is false.
	Reason string

	Namespace string
	Name      string
	Origin    ServiceAccountOrigin

	Token TokenState
	// TokenReason explains a TokenNotMounted or TokenUnknown verdict.
	TokenReason string
}

// Identity adapts the resolution to the correlation input.
func (r ServiceAccountResolution) Identity() WorkloadIdentity {
	return WorkloadIdentity{
		Namespace:          r.Namespace,
		ServiceAccountName: r.Name,
		Origin:             r.Origin,
		Token:              r.Token,
		TokenReason:        r.TokenReason,
	}
}

// ResolveServiceAccount reads the ServiceAccount of a workload from its live
// or collected object. The object must be the workload itself: a mismatch in
// kind, namespace or name is unresolved, not matched leniently.
//
// Token semantics follow the ServiceAccount admission plugin:
//
//   - A pod-level automountServiceAccountToken wins over the ServiceAccount's;
//     the ServiceAccount's applies otherwise and defaults to true. When the
//     ServiceAccount object is not in the snapshot, its setting cannot be
//     known, so the automatic token is unknown rather than assumed.
//   - The automatic token is injected into every container that does not
//     already mount something at the default token path.
//   - A projected serviceAccountToken volume is a token as soon as a
//     container mounts it in a way that exposes the token file.
//
// Anything the spec cannot establish is TokenUnknown.
func ResolveServiceAccount(w vulnexposure.Workload, obj map[string]any, serviceAccounts *ServiceAccountIndex) ServiceAccountResolution {
	if !IsSupportedWorkloadKind(w.Kind) {
		return ServiceAccountResolution{Reason: fmt.Sprintf("kind %q is not a supported workload kind", w.Kind)}
	}
	if obj == nil {
		return ServiceAccountResolution{Reason: fmt.Sprintf("%s %s/%s was not found in the collected resources", w.Kind, w.Namespace, w.Name)}
	}
	if k, _, _ := unstructured.NestedString(obj, "kind"); k != "" && k != w.Kind {
		return ServiceAccountResolution{Reason: fmt.Sprintf("object kind %q does not match workload kind %q", k, w.Kind)}
	}
	if ns, _, _ := unstructured.NestedString(obj, "metadata", "namespace"); ns != w.Namespace {
		return ServiceAccountResolution{Reason: fmt.Sprintf("object namespace %q does not match workload namespace %q", ns, w.Namespace)}
	}
	if name, _, _ := unstructured.NestedString(obj, "metadata", "name"); name != w.Name {
		return ServiceAccountResolution{Reason: fmt.Sprintf("object name %q does not match workload name %q", name, w.Name)}
	}

	rawSpec, found, err := unstructured.NestedFieldNoCopy(obj, workloadinterface.PodSpec(w.Kind)...)
	spec, isMap := rawSpec.(map[string]any)
	if err != nil || !found || !isMap {
		return ServiceAccountResolution{Reason: fmt.Sprintf("%s %s/%s has no readable pod spec", w.Kind, w.Namespace, w.Name)}
	}

	name, origin, reason := serviceAccountName(spec)
	if reason != "" {
		return ServiceAccountResolution{Reason: reason}
	}

	res := ServiceAccountResolution{
		Resolved:  true,
		Namespace: w.Namespace,
		Name:      name,
		Origin:    origin,
	}
	automount, saFound := serviceAccounts.lookup(w.Namespace, name)
	res.Token, res.TokenReason = tokenState(spec, automount, saFound)
	return res
}

// serviceAccountName returns the effective ServiceAccount name of a pod spec.
// An omitted name is "default", reported as defaulted so it can be told apart
// from an explicit "default". The deprecated spec.serviceAccount is honoured
// when serviceAccountName is empty.
func serviceAccountName(spec map[string]any) (name string, origin ServiceAccountOrigin, reason string) {
	read := func(field string) (string, bool) {
		v, present := spec[field]
		if !present || v == nil {
			return "", true
		}
		s, ok := v.(string)
		return s, ok
	}
	name, ok := read("serviceAccountName")
	if !ok {
		return "", "", "spec.serviceAccountName is not a string"
	}
	legacy, ok := read("serviceAccount")
	if !ok {
		return "", "", "spec.serviceAccount is not a string"
	}
	switch {
	case name != "" && legacy != "" && name != legacy:
		return "", "", fmt.Sprintf("spec.serviceAccountName %q conflicts with the deprecated spec.serviceAccount %q", name, legacy)
	case name != "":
		return name, OriginExplicit, ""
	case legacy != "":
		return legacy, OriginExplicit, ""
	default:
		return "default", OriginDefaulted, ""
	}
}

// tokenState combines the two ways a token can reach a pod. A definite
// exposure wins; otherwise any unestablishable exposure leaves the state
// unknown; only when every route is definitely closed is it not-mounted.
func tokenState(spec map[string]any, saAutomount *bool, saFound bool) (TokenState, string) {
	containers, ok := containersOf(spec, "containers", "initContainers")
	if !ok {
		return TokenUnknown, "the pod spec's containers could not be read"
	}
	// Ephemeral containers (present on a live Pod) are never given the
	// automatic token, but one can mount a token volume the pod already has.
	ephemeral, ok := containersOf(spec, "ephemeralContainers")
	if !ok && spec["ephemeralContainers"] != nil {
		return TokenUnknown, "the pod spec's ephemeral containers could not be read"
	}

	autoMounted, autoUnknown, autoReason := automaticToken(spec, containers, saAutomount, saFound)
	volMounted, volUnknown, volReason := projectedTokenVolumes(spec, append(slices.Clone(containers), ephemeral...))

	switch {
	case autoMounted || volMounted:
		return TokenMounted, ""
	case autoUnknown:
		return TokenUnknown, autoReason
	case volUnknown:
		return TokenUnknown, volReason
	}
	return TokenNotMounted, "no automatic token is injected and no projected serviceAccountToken volume is mounted"
}

// containersOf returns the containers listed under the given pod-spec fields.
// It reports false when a field is present but unreadable, or when nothing was
// found at all.
func containersOf(spec map[string]any, fields ...string) ([]map[string]any, bool) {
	var out []map[string]any
	for _, field := range fields {
		raw, present := spec[field]
		if !present || raw == nil {
			continue
		}
		list, ok := raw.([]any)
		if !ok {
			return nil, false
		}
		for _, item := range list {
			c, ok := item.(map[string]any)
			if !ok {
				return nil, false
			}
			out = append(out, c)
		}
	}
	return out, len(out) > 0
}

func mountsOf(container map[string]any) []map[string]any {
	list, _ := container["volumeMounts"].([]any)
	var out []map[string]any
	for _, item := range list {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// automaticToken reports whether the admission plugin injects its token.
func automaticToken(spec map[string]any, containers []map[string]any, saAutomount *bool, saFound bool) (mounted, unknown bool, reason string) {
	var enabled, known bool
	switch v := spec["automountServiceAccountToken"].(type) {
	case nil:
		// Unset, or an explicit null: the ServiceAccount's setting applies.
		switch {
		case !saFound:
			return false, !allOccupyTokenPath(containers), "automountServiceAccountToken is unset and the ServiceAccount object was not collected"
		case saAutomount != nil:
			enabled, known = *saAutomount, true
		default:
			enabled, known = true, true
		}
	case bool:
		enabled, known = v, true
	default:
		return false, !allOccupyTokenPath(containers), "spec.automountServiceAccountToken is not a boolean"
	}
	if !known || !enabled || allOccupyTokenPath(containers) {
		return false, false, ""
	}
	return true, false, ""
}

// allOccupyTokenPath reports whether every container already mounts something
// at the default token path, so the plugin injects the token into none.
func allOccupyTokenPath(containers []map[string]any) bool {
	for _, c := range containers {
		occupied := false
		for _, m := range mountsOf(c) {
			if p, _ := m["mountPath"].(string); p == serviceAccountTokenMountPath {
				occupied = true
				break
			}
		}
		if !occupied {
			return false
		}
	}
	return true
}

// projectedTokenVolumes reports whether a projected serviceAccountToken volume
// is mounted so that its token file is exposed to some container.
func projectedTokenVolumes(spec map[string]any, containers []map[string]any) (mounted, unknown bool, reason string) {
	raw, present := spec["volumes"]
	if !present || raw == nil {
		return false, false, ""
	}
	volumes, ok := raw.([]any)
	if !ok {
		return false, true, "spec.volumes could not be read"
	}

	// volume name -> cleaned token file paths within it; "" means the path
	// was not established.
	tokenPaths := map[string][]string{}
	for _, item := range volumes {
		vol, ok := item.(map[string]any)
		if !ok {
			return false, true, "a volume entry could not be read"
		}
		name, _ := vol["name"].(string)
		projected, ok := vol["projected"].(map[string]any)
		if !ok {
			continue
		}
		sources, _ := projected["sources"].([]any)
		for _, s := range sources {
			src, ok := s.(map[string]any)
			if !ok {
				continue
			}
			sat, has := src["serviceAccountToken"]
			if !has {
				continue
			}
			tp := ""
			if m, ok := sat.(map[string]any); ok {
				if p, ok := m["path"].(string); ok && p != "" {
					tp = path.Clean(p)
				}
			}
			tokenPaths[name] = append(tokenPaths[name], tp)
		}
	}

	for _, c := range containers {
		for _, m := range mountsOf(c) {
			volName, _ := m["name"].(string)
			paths, isToken := tokenPaths[volName]
			if !isToken {
				continue
			}
			switch exposesToken(m, paths) {
			case exposed:
				return true, false, ""
			case exposureUnknown:
				unknown = true
				reason = fmt.Sprintf("volume %q holds a serviceAccountToken but whether this mount exposes it cannot be established from the spec", volName)
			}
		}
	}
	return false, unknown, reason
}

type exposure int

const (
	notExposed exposure = iota
	exposed
	exposureUnknown
)

// exposesToken decides whether one volumeMount of a token-bearing volume
// exposes a token file at one of paths.
//
// With no subPath the whole volume is mounted. A subPath exposes the token
// when, once cleaned, it is the volume root ("." or "./"), the token file, or
// a directory containing it; a sibling file does not. A subPathExpr without
// variable references is a literal and is read like a subPath. One with
// $(VAR) references depends on the container's environment, so the path
// cannot be established statically.
func exposesToken(mount map[string]any, tokenPaths []string) exposure {
	subPath, _ := mount["subPath"].(string)
	expr, _ := mount["subPathExpr"].(string)

	switch {
	case subPath != "" && expr != "":
		return exposureUnknown // mutually exclusive in a valid spec
	case subPath == "" && expr == "":
		return exposed
	case expr != "":
		if strings.Contains(expr, "$(") {
			return exposureUnknown
		}
		subPath = expr
	}

	if path.IsAbs(subPath) {
		return exposureUnknown
	}
	c := path.Clean(subPath)
	if c == ".." || strings.HasPrefix(c, "../") {
		return exposureUnknown
	}
	if c == "." {
		return exposed
	}
	for _, tp := range tokenPaths {
		if tp == "" {
			return exposureUnknown
		}
		if tp == c || strings.HasPrefix(tp, c+"/") {
			return exposed
		}
	}
	return notExposed
}

// ResolveWorkloadIdentities resolves every workload against its collected
// object and adapts the result to the correlation input. A workload that
// cannot be resolved is left out of identities and given a reason, so the
// correlation reports it unresolved rather than assuming an identity.
func ResolveWorkloadIdentities(
	objects map[vulnexposure.Workload]map[string]any,
	workloads []vulnexposure.Workload,
	serviceAccounts *ServiceAccountIndex,
) (identities map[vulnexposure.Workload]WorkloadIdentity, unresolved map[vulnexposure.Workload]string) {
	identities = make(map[vulnexposure.Workload]WorkloadIdentity, len(workloads))
	unresolved = map[vulnexposure.Workload]string{}
	for _, w := range workloads {
		res := ResolveServiceAccount(w, objects[w], serviceAccounts)
		if !res.Resolved {
			unresolved[w] = res.Reason
			continue
		}
		identities[w] = res.Identity()
	}
	return identities, unresolved
}
