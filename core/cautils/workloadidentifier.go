package cautils

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Workload identifiers name a single Kubernetes resource to scan, in the form
// accepted by `kubescape scan workload`:
//
//	<kind>[.<version>[.<group>]]/<name>
//	<namespace>/<kind>[.<version>[.<group>]]/<name>
//
// The parsing lives here rather than in cmd/scan because more than one entry
// point needs it — the scan command and the MCP server — and cmd/scan cannot be
// imported by the latter without pulling in cobra and the entire command tree.
// core/cautils is the lowest package both already depend on.

// ErrInvalidWorkloadIdentifier is returned when a workload identifier does not
// match the documented form. Callers compare against it with errors.Is, and the
// scan command re-exports this exact value, so it must stay a single package
// level error rather than being reconstructed per call site.
var ErrInvalidWorkloadIdentifier = errors.New("invalid workload identifier, expected <kind>[.<version>[.<group>]]/<name>")

// ValidateWorkloadIdentifier reports whether workloadIdentifier is well formed,
// discarding the parsed components. It exists so argument validation can run
// before a command is willing to do any other work.
func ValidateWorkloadIdentifier(workloadIdentifier string) error {
	_, _, _, _, err := ParseWorkloadIdentifierString(workloadIdentifier)
	return err
}

// ParseWorkloadIdentifierString splits a workload identifier into its parts.
//
// The namespace is optional and empty when the identifier omits it; the caller
// decides what an absent namespace means (the scan command falls back to its
// --namespace flag). apiVersion is likewise empty when the identifier carries a
// bare kind, which callers resolving against a live cluster may treat as "let
// discovery pick the group/version".
func ParseWorkloadIdentifierString(workloadIdentifier string) (namespace, kind, name, apiVersion string, err error) {
	// workloadIdentifier is in the form of kind/name or namespace/kind/name
	// example: default/Deployment/nginx-deployment
	x := strings.Split(workloadIdentifier, "/")
	if len(x) == 2 {
		if x[0] == "" || x[1] == "" {
			return "", "", "", "", ErrInvalidWorkloadIdentifier
		}
		parsedKind, parsedApiVersion, err := parseKindAndApiVersion(x[0])
		if err != nil {
			return "", "", "", "", err
		}
		return "", parsedKind, x[1], parsedApiVersion, nil
	}
	if len(x) == 3 {
		if x[0] == "" || x[1] == "" || x[2] == "" {
			return "", "", "", "", ErrInvalidWorkloadIdentifier
		}
		parsedKind, parsedApiVersion, err := parseKindAndApiVersion(x[1])
		if err != nil {
			return "", "", "", "", err
		}
		return x[0], parsedKind, x[2], parsedApiVersion, nil
	}

	return "", "", "", "", ErrInvalidWorkloadIdentifier
}

// apiVersionPattern matches a bare Kubernetes version segment (v1, v1beta1,
// v2alpha1). It guards the second dotted component so that "Deployment.apps"
// is rejected as a missing version rather than being silently read as one.
var apiVersionPattern = regexp.MustCompile(`^v\d+((alpha|beta)\d+)?$`)

// canonicalKinds maps lowercase resource kinds, plural names, and standard kubectl
// short names (from `kubectl api-resources`) to their canonical PascalCase Kind.
var canonicalKinds = map[string]string{
	// Workloads
	"pod": "Pod", "pods": "Pod", "po": "Pod",
	"deployment": "Deployment", "deployments": "Deployment", "deploy": "Deployment",
	"daemonset": "DaemonSet", "daemonsets": "DaemonSet", "ds": "DaemonSet",
	"statefulset": "StatefulSet", "statefulsets": "StatefulSet", "sts": "StatefulSet",
	"job": "Job", "jobs": "Job",
	"cronjob": "CronJob", "cronjobs": "CronJob", "cj": "CronJob",
	"replicaset": "ReplicaSet", "replicasets": "ReplicaSet", "rs": "ReplicaSet",
	"replicationcontroller": "ReplicationController", "replicationcontrollers": "ReplicationController", "rc": "ReplicationController",

	// Configuration & Storage
	"configmap": "ConfigMap", "configmaps": "ConfigMap", "cm": "ConfigMap",
	"secret": "Secret", "secrets": "Secret",
	"persistentvolumeclaim": "PersistentVolumeClaim", "persistentvolumeclaims": "PersistentVolumeClaim", "pvc": "PersistentVolumeClaim",
	"persistentvolume": "PersistentVolume", "persistentvolumes": "PersistentVolume", "pv": "PersistentVolume",
	"storageclass": "StorageClass", "storageclasses": "StorageClass", "sc": "StorageClass",
	"volumeattachment": "VolumeAttachment", "volumeattachments": "VolumeAttachment",

	// Networking
	"service": "Service", "services": "Service", "svc": "Service",
	"ingress": "Ingress", "ingresses": "Ingress", "ing": "Ingress",
	"networkpolicy": "NetworkPolicy", "networkpolicies": "NetworkPolicy", "netpol": "NetworkPolicy",
	"endpoints": "Endpoints", "ep": "Endpoints",
	"endpointslice": "EndpointSlice", "endpointslices": "EndpointSlice",
	"ingressclass": "IngressClass", "ingressclasses": "IngressClass",

	// Cluster, Node & RBAC
	"namespace": "Namespace", "namespaces": "Namespace", "ns": "Namespace",
	"node": "Node", "nodes": "Node", "no": "Node",
	"serviceaccount": "ServiceAccount", "serviceaccounts": "ServiceAccount", "sa": "ServiceAccount",
	"role": "Role", "roles": "Role",
	"rolebinding": "RoleBinding", "rolebindings": "RoleBinding",
	"clusterrole": "ClusterRole", "clusterroles": "ClusterRole",
	"clusterrolebinding": "ClusterRoleBinding", "clusterrolebindings": "ClusterRoleBinding",
	"customresourcedefinition": "CustomResourceDefinition", "customresourcedefinitions": "CustomResourceDefinition", "crd": "CustomResourceDefinition", "crds": "CustomResourceDefinition",

	// Policy, Scheduling & Quota
	"horizontalpodautoscaler": "HorizontalPodAutoscaler", "horizontalpodautoscalers": "HorizontalPodAutoscaler", "hpa": "HorizontalPodAutoscaler",
	"poddisruptionbudget": "PodDisruptionBudget", "poddisruptionbudgets": "PodDisruptionBudget", "pdb": "PodDisruptionBudget",
	"podsecuritypolicy": "PodSecurityPolicy", "podsecuritypolicies": "PodSecurityPolicy", "psp": "PodSecurityPolicy",
	"resourcequota": "ResourceQuota", "resourcequotas": "ResourceQuota", "quota": "ResourceQuota",
	"limitrange": "LimitRange", "limitranges": "LimitRange", "limits": "LimitRange",
	"priorityclass": "PriorityClass", "priorityclasses": "PriorityClass", "pc": "PriorityClass",
	"lease": "Lease", "leases": "Lease",
	"runtimeclass": "RuntimeClass", "runtimeclasses": "RuntimeClass",
	"flowschema": "FlowSchema", "flowschemas": "FlowSchema",
	"prioritylevelconfiguration": "PriorityLevelConfiguration", "prioritylevelconfigurations": "PriorityLevelConfiguration",
	"controllerrevision": "ControllerRevision", "controllerrevisions": "ControllerRevision",

	// Core cluster metadata & Storage migration/snapshots
	"componentstatus": "ComponentStatus", "componentstatuses": "ComponentStatus", "cs": "ComponentStatus",
	"event": "Event", "events": "Event", "ev": "Event",
	"binding": "Binding", "bindings": "Binding",
	"volumesnapshot": "VolumeSnapshot", "volumesnapshots": "VolumeSnapshot", "vs": "VolumeSnapshot",
	"volumesnapshotcontent": "VolumeSnapshotContent", "volumesnapshotcontents": "VolumeSnapshotContent",
	"volumesnapshotclass": "VolumeSnapshotClass", "volumesnapshotclasses": "VolumeSnapshotClass",
	"storageversionmigration": "StorageVersionMigration", "storageversionmigrations": "StorageVersionMigration",
	"storagestate": "StorageState", "storagestates": "StorageState",

	// Storage & CSI
	"csinode": "CSINode", "csinodes": "CSINode",
	"csidriver": "CSIDriver", "csidrivers": "CSIDriver",
	"csistoragecapacity": "CSIStorageCapacity", "csistoragecapacities": "CSIStorageCapacity",
	"podtemplate": "PodTemplate", "podtemplates": "PodTemplate",

	// Admission, Authorization & Certificates
	"apiservice": "APIService", "apiservices": "APIService",
	"mutatingwebhookconfiguration": "MutatingWebhookConfiguration", "mutatingwebhookconfigurations": "MutatingWebhookConfiguration",
	"validatingwebhookconfiguration": "ValidatingWebhookConfiguration", "validatingwebhookconfigurations": "ValidatingWebhookConfiguration",
	"certificatesigningrequest": "CertificateSigningRequest", "certificatesigningrequests": "CertificateSigningRequest", "csr": "CertificateSigningRequest",
	"tokenreview": "TokenReview", "tokenreviews": "TokenReview",
	"subjectaccessreview": "SubjectAccessReview", "subjectaccessreviews": "SubjectAccessReview",
	"selfsubjectaccessreview": "SelfSubjectAccessReview", "selfsubjectaccessreviews": "SelfSubjectAccessReview",
	"selfsubjectrulesreview": "SelfSubjectRulesReview", "selfsubjectrulesreviews": "SelfSubjectRulesReview",
	"localsubjectaccessreview": "LocalSubjectAccessReview", "localsubjectaccessreviews": "LocalSubjectAccessReview",
}

// NormalizeWorkloadKind maps a Kubernetes resource kind, plural name, or registered
// kubectl short name (from `kubectl api-resources`) to its canonical PascalCase Kind
// (e.g., "deployment", "deployments", "deploy" -> "Deployment").
//
// If the kind is unrecognized (such as a custom resource definition), the input string
// is returned unaltered.
func NormalizeWorkloadKind(kind string) string {
	if canonical, ok := canonicalKinds[strings.ToLower(kind)]; ok {
		return canonical
	}
	return kind
}

// builtinAPIGroups is an explicit allowlist of official Kubernetes built-in API groups.
// Domain-based groups outside this list (such as custom .k8s.io domains like example.k8s.io)
// are treated as custom resource groups so that declared custom resource Kinds are preserved.
var builtinAPIGroups = map[string]struct{}{
	"":                             {}, // core
	"admissionregistration.k8s.io": {},
	"apiextensions.k8s.io":         {},
	"apiregistration.k8s.io":       {},
	"apps":                         {},
	"authentication.k8s.io":        {},
	"authorization.k8s.io":         {},
	"autoscaling":                  {},
	"batch":                        {},
	"certificates.k8s.io":          {},
	"coordination.k8s.io":          {},
	"discovery.k8s.io":             {},
	"events.k8s.io":                {},
	"extensions":                   {},
	"flowcontrol.apiserver.k8s.io": {},
	"imagepolicy.k8s.io":           {},
	"internal.apiserver.k8s.io":    {},
	"migration.k8s.io":             {},
	"networking.k8s.io":            {},
	"node.k8s.io":                  {},
	"policy":                       {},
	"policy.k8s.io":                {},
	"rbac.authorization.k8s.io":    {},
	"resource.k8s.io":              {},
	"scheduling":                   {},
	"scheduling.k8s.io":            {},
	"snapshot.storage.k8s.io":      {},
	"storage.k8s.io":               {},
	"storagemigration.k8s.io":      {},
}

// isBuiltinGroup reports whether group corresponds to a recognized official Kubernetes built-in API group.
func isBuiltinGroup(group string) bool {
	_, ok := builtinAPIGroups[strings.ToLower(group)]
	return ok
}

// parseKindAndApiVersion splits the kind segment of an identifier into a kind
// and, when present, the apiVersion it encodes. The dotted form orders the
// components kind.version.group for readability, while Kubernetes apiVersion
// strings are group/version, so the group and version are swapped on the way
// out.
func parseKindAndApiVersion(kindStr string) (kind, apiVersion string, err error) {
	parts := strings.Split(kindStr, ".")
	if len(parts) == 1 {
		return NormalizeWorkloadKind(kindStr), "", nil
	}

	// Reject empty components
	for _, part := range parts {
		if part == "" {
			return "", "", fmt.Errorf("%w: empty component in %q", ErrInvalidWorkloadIdentifier, kindStr)
		}
	}

	if !apiVersionPattern.MatchString(parts[1]) {
		return "", "", fmt.Errorf("%w: %q is not a valid API version in %q", ErrInvalidWorkloadIdentifier, parts[1], kindStr)
	}

	if len(parts) >= 3 {
		group := strings.Join(parts[2:], ".")
		// Preserve custom resource Kind when an explicit custom API group is present,
		// preventing CRDs whose name matches a built-in kind or alias (e.g. Deploy.v1.example.com)
		// from being incorrectly rewritten to a built-in kind.
		kind := parts[0]
		if isBuiltinGroup(group) {
			kind = NormalizeWorkloadKind(parts[0])
		}
		return kind, group + "/" + parts[1], nil // kind.version.group -> group/version
	}
	return NormalizeWorkloadKind(parts[0]), parts[1], nil // kind.version -> version
}
