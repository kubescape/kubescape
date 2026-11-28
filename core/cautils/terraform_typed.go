package cautils

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
)

// typedResourceGVK maps the typed kubernetes_* Terraform provider resources we
// support to the apiVersion/kind of the K8s object they represent. Only
// resources with a stable, well-known shape are listed here — anything not in
// this table is left unscanned rather than guessed at, same policy as
// kubernetes_manifest.
var typedResourceGVK = map[string]struct{ apiVersion, kind string }{
	"kubernetes_deployment":                 {"apps/v1", "Deployment"},
	"kubernetes_deployment_v1":              {"apps/v1", "Deployment"},
	"kubernetes_stateful_set":               {"apps/v1", "StatefulSet"},
	"kubernetes_stateful_set_v1":            {"apps/v1", "StatefulSet"},
	"kubernetes_daemonset":                  {"apps/v1", "DaemonSet"},
	"kubernetes_daemon_set":                 {"apps/v1", "DaemonSet"},
	"kubernetes_daemon_set_v1":              {"apps/v1", "DaemonSet"},
	"kubernetes_pod":                        {"v1", "Pod"},
	"kubernetes_pod_v1":                     {"v1", "Pod"},
	"kubernetes_service":                    {"v1", "Service"},
	"kubernetes_service_v1":                 {"v1", "Service"},
	"kubernetes_config_map":                 {"v1", "ConfigMap"},
	"kubernetes_config_map_v1":              {"v1", "ConfigMap"},
	"kubernetes_secret":                     {"v1", "Secret"},
	"kubernetes_secret_v1":                  {"v1", "Secret"},
	"kubernetes_namespace":                  {"v1", "Namespace"},
	"kubernetes_namespace_v1":               {"v1", "Namespace"},
	"kubernetes_service_account":            {"v1", "ServiceAccount"},
	"kubernetes_service_account_v1":         {"v1", "ServiceAccount"},
	"kubernetes_default_service_account":    {"v1", "ServiceAccount"},
	"kubernetes_default_service_account_v1": {"v1", "ServiceAccount"},
	"kubernetes_job":                        {"batch/v1", "Job"},
	"kubernetes_job_v1":                     {"batch/v1", "Job"},
	"kubernetes_cron_job":                   {"batch/v1", "CronJob"},
	"kubernetes_cron_job_v1":                {"batch/v1", "CronJob"},
	"kubernetes_ingress":                    {"networking.k8s.io/v1beta1", "Ingress"},
	"kubernetes_ingress_v1":                 {"networking.k8s.io/v1", "Ingress"},
	"kubernetes_network_policy":             {"networking.k8s.io/v1", "NetworkPolicy"},
	"kubernetes_network_policy_v1":          {"networking.k8s.io/v1", "NetworkPolicy"},
	"kubernetes_role":                       {"rbac.authorization.k8s.io/v1", "Role"},
	"kubernetes_role_binding":               {"rbac.authorization.k8s.io/v1", "RoleBinding"},
	"kubernetes_cluster_role":               {"rbac.authorization.k8s.io/v1", "ClusterRole"},
	"kubernetes_cluster_role_binding":       {"rbac.authorization.k8s.io/v1", "ClusterRoleBinding"},

	"kubernetes_role_v1":                 {"rbac.authorization.k8s.io/v1", "Role"},
	"kubernetes_role_binding_v1":         {"rbac.authorization.k8s.io/v1", "RoleBinding"},
	"kubernetes_cluster_role_v1":         {"rbac.authorization.k8s.io/v1", "ClusterRole"},
	"kubernetes_cluster_role_binding_v1": {"rbac.authorization.k8s.io/v1", "ClusterRoleBinding"},

	"kubernetes_persistent_volume_claim":           {"v1", "PersistentVolumeClaim"},
	"kubernetes_persistent_volume_claim_v1":        {"v1", "PersistentVolumeClaim"},
	"kubernetes_persistent_volume":                 {"v1", "PersistentVolume"},
	"kubernetes_persistent_volume_v1":              {"v1", "PersistentVolume"},
	"kubernetes_pod_disruption_budget":             {"policy/v1beta1", "PodDisruptionBudget"},
	"kubernetes_pod_disruption_budget_v1":          {"policy/v1", "PodDisruptionBudget"},
	"kubernetes_resource_quota":                    {"v1", "ResourceQuota"},
	"kubernetes_resource_quota_v1":                 {"v1", "ResourceQuota"},
	"kubernetes_limit_range":                       {"v1", "LimitRange"},
	"kubernetes_limit_range_v1":                    {"v1", "LimitRange"},
	"kubernetes_horizontal_pod_autoscaler":         {"autoscaling/v1", "HorizontalPodAutoscaler"},
	"kubernetes_horizontal_pod_autoscaler_v1":      {"autoscaling/v1", "HorizontalPodAutoscaler"},
	"kubernetes_horizontal_pod_autoscaler_v2":      {"autoscaling/v2", "HorizontalPodAutoscaler"},
	"kubernetes_horizontal_pod_autoscaler_v2beta2": {"autoscaling/v2beta2", "HorizontalPodAutoscaler"},
	"kubernetes_priority_class":                    {"scheduling.k8s.io/v1", "PriorityClass"},
	"kubernetes_priority_class_v1":                 {"scheduling.k8s.io/v1", "PriorityClass"},

	"kubernetes_mutating_webhook_configuration":      {"admissionregistration.k8s.io/v1", "MutatingWebhookConfiguration"},
	"kubernetes_mutating_webhook_configuration_v1":   {"admissionregistration.k8s.io/v1", "MutatingWebhookConfiguration"},
	"kubernetes_validating_webhook_configuration":    {"admissionregistration.k8s.io/v1", "ValidatingWebhookConfiguration"},
	"kubernetes_validating_webhook_configuration_v1": {"admissionregistration.k8s.io/v1", "ValidatingWebhookConfiguration"},
	"kubernetes_storage_class":                       {"storage.k8s.io/v1", "StorageClass"},
	"kubernetes_storage_class_v1":                    {"storage.k8s.io/v1", "StorageClass"},
	"kubernetes_ingress_class":                       {"networking.k8s.io/v1", "IngressClass"},
	"kubernetes_ingress_class_v1":                    {"networking.k8s.io/v1", "IngressClass"},
	"kubernetes_certificate_signing_request":         {"certificates.k8s.io/v1", "CertificateSigningRequest"},
	"kubernetes_certificate_signing_request_v1":      {"certificates.k8s.io/v1", "CertificateSigningRequest"},
	"kubernetes_csi_driver":                          {"storage.k8s.io/v1", "CSIDriver"},
	"kubernetes_csi_driver_v1":                       {"storage.k8s.io/v1", "CSIDriver"},
	"kubernetes_runtime_class":                       {"node.k8s.io/v1", "RuntimeClass"},
	"kubernetes_runtime_class_v1":                    {"node.k8s.io/v1", "RuntimeClass"},
	"kubernetes_endpoints":                           {"v1", "Endpoints"},
	"kubernetes_endpoints_v1":                        {"v1", "Endpoints"},
	"kubernetes_endpoint_slice":                      {"discovery.k8s.io/v1", "EndpointSlice"},
	"kubernetes_endpoint_slice_v1":                   {"discovery.k8s.io/v1", "EndpointSlice"},
}

// pluralOverrides maps an HCL block label to the K8s array field name it must
// become, for the cases where camelCasing the block name alone isn't right
// (block "container" -> field "containers"). Anything not listed here just
// gets its singular name camelCased.
var pluralOverrides = map[string]string{
	"container":                  "containers",
	"init_container":             "initContainers",
	"volume":                     "volumes",
	"volume_mount":               "volumeMounts",
	"volume_device":              "volumeDevices",
	"volume_devices":             "volumeDevices",
	"env_from":                   "envFrom",
	"port":                       "ports",
	"toleration":                 "tolerations",
	"host_alias":                 "hostAliases",
	"host_aliases":               "hostAliases",
	"rule":                       "rules",
	"path":                       "paths",
	"subject":                    "subjects",
	"image_pull_secret":          "imagePullSecrets",
	"image_pull_secrets":         "imagePullSecrets",
	"match_expressions":          "matchExpressions",
	"match_expression":           "matchExpressions",
	"match_fields":               "matchFields",
	"match_field":                "matchFields",
	"volume_claim_template":      "volumeClaimTemplates",
	"http_header":                "httpHeaders",
	"sysctl":                     "sysctls",
	"limit":                      "limits",
	"metric":                     "metrics",
	"policy":                     "policies",
	"node_selector_term":         "nodeSelectorTerms",
	"node_selector_terms":        "nodeSelectorTerms",
	"webhook":                    "webhooks",
	"match_condition":            "matchConditions",
	"match_conditions":           "matchConditions",
	"match_label_expression":     "matchLabelExpressions",
	"match_label_expressions":    "matchLabelExpressions",
	"allowed_topology":           "allowedTopologies",
	"allowed_topologies":         "allowedTopologies",
	"token_request":              "tokenRequests",
	"token_requests":             "tokenRequests",
	"subset":                     "subsets",
	"endpoint":                   "endpoints",
	"address":                    "addresses",
	"not_ready_address":          "notReadyAddresses",
	"condition":                  "conditions",
	"readiness_gate":             "readinessGates",
	"topology_spread_constraint": "topologySpreadConstraints",
	"option":                     "options",
	"options":                    "options",
	"on_pod_condition":           "onPodConditions",
	"on_pod_conditions":          "onPodConditions",
}

// repeatableBlocks lists HCL block labels that always encode as a JSON array,
// even when only one instance is present — Terraform lets you repeat a block,
// but the K8s field underneath (e.g. spec.containers) is always a list.
var repeatableBlocks = map[string]bool{
	"container": true, "init_container": true, "volume": true, "volume_mount": true,
	"volume_device": true, "volume_devices": true,
	"env": true, "env_from": true, "port": true, "ports": true, "toleration": true,
	"host_alias": true, "host_aliases": true, "rule": true, "subject": true,
	"image_pull_secret": true, "image_pull_secrets": true,
	"match_expressions": true, "match_expression": true,
	"match_fields": true, "match_field": true, "volume_claim_template": true, "http_header": true,
	"sysctl": true, "ingress": true, "egress": true, "from": true, "to": true,
	"path": true, "tls": true,
	"limit": true, "metric": true, "policy": true,
	"node_selector_term": true, "node_selector_terms": true,
	"webhook":         true,
	"match_condition": true, "match_conditions": true,
	"match_label_expression": true, "match_label_expressions": true,
	"allowed_topology": true, "allowed_topologies": true,
	"token_request": true, "token_requests": true,
	"subset": true, "endpoint": true,
	"address": true, "not_ready_address": true,
	"readiness_gate": true, "topology_spread_constraint": true,
	"items": true, "sources": true,
	"preferred_during_scheduling_ignored_during_execution": true,
	"cluster_role_selectors":                               true,
	"option":                                               true, "options": true,
	"on_pod_condition": true, "on_pod_conditions": true,
}

// resourceMetaAttributes are Terraform meta-argument attributes valid on any
// resource block (they configure Terraform itself, not the K8s object).
// depends_on and provider in particular reference other resources/providers
// that the var-only evalCtx can never resolve, so they must be stripped
// before expression evaluation rather than left to fail into errs.
var resourceMetaAttributes = map[string]bool{
	"depends_on": true,
	"provider":   true,
	"count":      true,
	"for_each":   true,
}

// resourceMetaBlocks are Terraform meta-argument blocks valid on any resource
// block, stripped for the same reason. This is applied ONLY at the resource's
// top level — a nested "lifecycle" block (e.g. a container's postStart/
// preStop hooks) is a legitimate K8s field and must still be converted.
var resourceMetaBlocks = map[string]bool{
	"lifecycle":   true,
	"provisioner": true,
	"connection":  true,
}

// providerControlAttributes are top-level attributes of the Kubernetes
// provider's resources that tell the provider how to apply the object, such
// as whether to wait for a rollout. They are not part of the Kubernetes object
// the provider creates, so like the meta-arguments they are stripped at the
// resource's top level only.
var providerControlAttributes = map[string]bool{
	"wait_for_rollout":                 true, // deployments, stateful sets, daemon sets
	"wait_for_load_balancer":           true, // services, ingresses
	"wait_for_completion":              true, // jobs
	"wait_for_default_service_account": true, // namespaces
	"wait_for_service_account_token":   true, // secrets
	"wait_until_bound":                 true, // persistent volume claims
	"auto_approve":                     true, // certificate signing requests
	"target_state":                     true, // pods
	"data_wo_revision":                 true, // secrets
	"binary_data_wo_revision":          true, // secrets
}

// providerControlBlocks are the provider's top-level control blocks, stripped
// for the same reason.
var providerControlBlocks = map[string]bool{
	"timeouts": true,
}

var fieldInitialisms = map[string]string{
	"api":  "API",
	"cpu":  "CPU",
	"id":   "ID",
	"ip":   "IP",
	"ipc":  "IPC",
	"ips":  "IPs",
	"pid":  "PID",
	"uri":  "URI",
	"urls": "URLs",
	"uuid": "UUID",
}

func snakeToCamel(s string) string {
	parts := strings.Split(s, "_")
	for i := 1; i < len(parts); i++ {
		if parts[i] == "" {
			continue
		}
		if initialism, ok := fieldInitialisms[parts[i]]; ok {
			parts[i] = initialism
			continue
		}
		parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
	}
	return strings.Join(parts, "")
}

func fieldNameFor(blockType string) string {
	if v, ok := pluralOverrides[blockType]; ok {
		return v
	}
	if blockType == "ceph_fs" {
		return "cephfs"
	}
	return snakeToCamel(blockType)
}

func attributeNameFor(name string) string {
	switch name {
	case "data_disk_uri":
		return "diskURI"
	case "target_ww_ns":
		return "targetWWNs"
	case "timezone":
		return "timeZone"
	}
	if name == "storage_provisioner" {
		return "provisioner"
	}
	return snakeToCamel(name)
}

// rbdAttributeNames are the rbd volume source attributes the provider renames
// on their way to Kubernetes, where they are monitors, image, pool and user.
// The provider uses these names for the rbd block of both a pod volume and a
// PersistentVolume source.
var rbdAttributeNames = map[string]string{
	"ceph_monitors": "monitors",
	"rbd_image":     "image",
	"rbd_pool":      "pool",
	"rados_user":    "user",
}

// attributeKeyFor is attributeNameFor for an attribute of the block at path,
// for the attributes whose Kubernetes name depends on the block they are in.
func attributeKeyFor(path, name string) string {
	if isSecretResource(path) {
		// The provider sends data and the write-only data_wo as the Secret's
		// stringData, and binary_data and binary_data_wo, already base64, as
		// its data. A Secret has no binaryData field. The write-only values
		// are kept even without their *_revision argument, which only tells
		// the provider when to send them; they are masked like the rest.
		switch name {
		case "data", "data_wo":
			return "stringData"
		case "binary_data", "binary_data_wo":
			return "data"
		}
	}
	if strings.HasSuffix(path, ".rbd") {
		if key, ok := rbdAttributeNames[name]; ok {
			return key
		}
	}
	return attributeNameFor(name)
}

func isDigitOnly(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func canonicalizeNumericString(s string) string {
	trimmed := strings.TrimLeft(s, "0")
	if trimmed == "" {
		return "0"
	}
	return trimmed
}

func isNetworkPolicyPortField(path, name string) bool {
	if name != "port" && name != "end_port" {
		return false
	}
	if !strings.HasSuffix(path, ".ports") && path != "ports" {
		return false
	}
	// If path includes a resource type, ensure it is NetworkPolicy.
	if strings.Contains(path, "kubernetes_") && !strings.HasPrefix(path, "kubernetes_network_policy") {
		return false
	}
	return true
}

func isLegacyIngressBackendPortField(path, name string) bool {
	if name != "service_port" {
		return false
	}
	if !strings.HasSuffix(path, ".backend") && path != "backend" {
		return false
	}
	// Only kubernetes_ingress (legacy v1beta1), not kubernetes_ingress_v1.
	if strings.Contains(path, "kubernetes_") && (!strings.HasPrefix(path, "kubernetes_ingress") || strings.HasPrefix(path, "kubernetes_ingress_v1")) {
		return false
	}
	return true
}

func isIngressBackendServicePortNumberField(path, name string) bool {
	if name != "number" {
		return false
	}
	if !strings.HasSuffix(path, "backend.service.port") {
		return false
	}
	if strings.Contains(path, "kubernetes_") && !strings.Contains(path, "kubernetes_ingress") {
		return false
	}
	return true
}

func isBackendServicePortBlock(path, blockType string) bool {
	if blockType != "port" {
		return false
	}
	if !strings.HasSuffix(path, "backend.service") {
		return false
	}
	if strings.Contains(path, "kubernetes_") && !strings.Contains(path, "kubernetes_ingress") {
		return false
	}
	return true
}

func isPersistentVolumeSourceBlock(path, blockType string) bool {
	if blockType != "persistent_volume_source" {
		return false
	}
	if !strings.HasSuffix(path, ".spec") {
		return false
	}
	return strings.HasPrefix(path, "kubernetes_persistent_volume.") ||
		strings.HasPrefix(path, "kubernetes_persistent_volume_v1.")
}

func isEndpointSlicePortField(path, name string) bool {
	if name != "port" {
		return false
	}
	return strings.Contains(path, "kubernetes_endpoint_slice") && (strings.HasSuffix(path, ".port") || strings.HasSuffix(path, ".ports"))
}

func isConvertiblePortField(path, name string) bool {
	return isNetworkPolicyPortField(path, name) || isLegacyIngressBackendPortField(path, name) || isIngressBackendServicePortNumberField(path, name)
}

// isSecretResource reports whether path is the top level of a Secret
// resource. The provider takes its data attribute as plain text and sends it
// as the Secret's stringData; data in Kubernetes holds base64 values.
func isSecretResource(path string) bool {
	return (strings.HasPrefix(path, "kubernetes_secret.") || strings.HasPrefix(path, "kubernetes_secret_v1.")) &&
		strings.Count(path, ".") == 1
}

// isDaemonSetStrategyBlock reports whether blockType is the strategy block of
// a DaemonSet spec. The provider calls it strategy, but builds the DaemonSet's
// updateStrategy from it.
func isDaemonSetStrategyBlock(path, blockType string) bool {
	if blockType != "strategy" || !strings.HasSuffix(path, ".spec") || strings.Count(path, ".") != 2 {
		return false
	}
	return strings.HasPrefix(path, "kubernetes_daemonset.") || strings.HasPrefix(path, "kubernetes_daemon_set.") ||
		strings.HasPrefix(path, "kubernetes_daemon_set_v1.")
}

func isServiceAccountSecretBlock(path, blockType string) bool {
	if blockType != "secret" {
		return false
	}
	return (strings.HasPrefix(path, "kubernetes_service_account") ||
		strings.HasPrefix(path, "kubernetes_default_service_account")) &&
		strings.Count(path, ".") == 1
}

// isPersistentVolumeClaimRefBlock reports whether path is the claim_ref block
// of a PersistentVolume spec. The provider defaults its namespace to
// "default".
func isPersistentVolumeClaimRefBlock(path string) bool {
	if !strings.HasSuffix(path, ".spec.claim_ref") {
		return false
	}
	return strings.HasPrefix(path, "kubernetes_persistent_volume.") ||
		strings.HasPrefix(path, "kubernetes_persistent_volume_v1.")
}

// usesHPAV2beta2 reports whether the provider creates an unversioned
// kubernetes_horizontal_pod_autoscaler through autoscaling/v2beta2 rather than
// autoscaling/v1, which it does when the spec has a metric or behavior block.
func usesHPAV2beta2(obj map[string]interface{}) bool {
	spec, _ := obj["spec"].(map[string]interface{})
	if spec == nil {
		return false
	}
	_, hasMetrics := spec["metrics"]
	_, hasBehavior := spec["behavior"]
	return hasMetrics || hasBehavior
}

// isPodAffinityRequiredBlock reports whether blockType is the
// required_during_scheduling_ignored_during_execution block of a pod affinity
// or anti-affinity, which is a list of terms. The node affinity block of the
// same name is a single NodeSelector.
func isPodAffinityRequiredBlock(path, blockType string) bool {
	if blockType != "required_during_scheduling_ignored_during_execution" {
		return false
	}
	return strings.HasSuffix(path, ".pod_affinity") || strings.HasSuffix(path, ".pod_anti_affinity")
}

func isNestedHPAMetricBlock(path, blockType string) bool {
	if blockType != "metric" {
		return false
	}
	return strings.HasSuffix(path, ".external") || strings.HasSuffix(path, ".pods") || strings.HasSuffix(path, ".object")
}

// isEphemeralVolumeClaimTemplateBlock reports whether blockType is the
// volume_claim_template of an ephemeral volume source. The provider reuses the
// name from StatefulSet, but in an EphemeralVolumeSource it is a single object
// named volumeClaimTemplate, not the list of volumeClaimTemplates a StatefulSet
// takes.
func isEphemeralVolumeClaimTemplateBlock(path, blockType string) bool {
	if blockType != "volume_claim_template" {
		return false
	}
	return strings.HasSuffix(path, ".ephemeral")
}

// isServiceTargetPortField reports whether name is a Service port's
// target_port. The provider declares it as a string and turns it into a number
// or a name with intstr.Parse when it builds the Service.
func isServiceTargetPortField(path, name string) bool {
	if name != "target_port" {
		return false
	}
	if !strings.HasSuffix(path, ".port") && path != "port" {
		return false
	}
	if strings.Contains(path, "kubernetes_") && !strings.HasPrefix(path, "kubernetes_service") {
		return false
	}
	return true
}

// isHandlerPortField reports whether name is the port of an http_get or
// tcp_socket handler, as used by container probes and lifecycle hooks. Like
// target_port, the provider declares it as a string and parses it with
// intstr.Parse.
func isHandlerPortField(path, name string) bool {
	if name != "port" {
		return false
	}
	return strings.HasSuffix(path, ".http_get") || strings.HasSuffix(path, ".tcp_socket") ||
		path == "http_get" || path == "tcp_socket"
}

// isSecurityContextIDField reports whether name is a user or group ID in a pod
// or container security_context. The provider declares these as strings, so
// that 0 can be told apart from unset, and parses them with strconv.ParseInt;
// terraform show and imported configurations write them quoted.
func isSecurityContextIDField(path, name string) bool {
	switch name {
	case "run_as_user", "run_as_group", "fs_group":
		return strings.HasSuffix(path, ".security_context") || path == "security_context"
	}
	return false
}

// isJobTTLField reports whether name is a Job spec's ttl_seconds_after_finished,
// in a Job or in a CronJob's job template. The provider declares it as a
// string and parses it with strconv.Atoi.
func isJobTTLField(path, name string) bool {
	if name != "ttl_seconds_after_finished" || !strings.HasSuffix(path, ".spec") {
		return false
	}
	return strings.HasPrefix(path, "kubernetes_job") || strings.HasPrefix(path, "kubernetes_cron_job")
}

// isStringTypedNumberField covers the provider's string-typed fields that hold
// a number: int-or-string ports, where a value made of digits only is a port
// number and anything else a port name, as intstr.Parse reads it, and the
// security context IDs.
func isStringTypedNumberField(path, name string) bool {
	return isServiceTargetPortField(path, name) || isHandlerPortField(path, name) || isSecurityContextIDField(path, name) ||
		isJobTTLField(path, name)
}

// isVolumeFileModeField reports whether name is the default_mode of a secret,
// config_map, downward_api or projected volume source, or the mode of one of
// their items. The provider declares these as strings holding an octal number,
// such as "0644", and parses them with strconv.ParseInt(v, 8, 32).
func isVolumeFileModeField(path, name string) bool {
	switch name {
	case "default_mode":
		return strings.HasSuffix(path, ".secret") || strings.HasSuffix(path, ".config_map") ||
			strings.HasSuffix(path, ".downward_api") || strings.HasSuffix(path, ".projected")
	case "mode":
		return strings.HasSuffix(path, ".items")
	}
	return false
}

// isPDBIntOrStringField reports whether name is min_available or
// max_unavailable in a PodDisruptionBudget spec. The provider declares them as
// strings (or int-or-string) and intstr.Parse converts digit strings to
// integers while preserving percentage strings.
func isPDBIntOrStringField(path, name string) bool {
	if name != "min_available" && name != "max_unavailable" {
		return false
	}
	if !strings.HasSuffix(path, ".spec") && path != "spec" {
		return false
	}
	return strings.Contains(path, "kubernetes_pod_disruption_budget")
}

// providerBoolFields are the attributes the provider declares as bools, taken
// from its schema for the resources in typedResourceGVK. Each of these names
// is a bool wherever it appears, so the name alone is enough.
var providerBoolFields = map[string]bool{
	"allocate_load_balancer_node_ports": true,
	"allow_privilege_escalation":        true,
	"allow_volume_expansion":            true,
	"attach_required":                   true,
	"auto_approve":                      true,
	"automount_service_account_token":   true,
	"enable_service_links":              true,
	"global_default":                    true,
	"host_ipc":                          true,
	"host_network":                      true,
	"host_pid":                          true,
	"host_process":                      true,
	"immutable":                         true,
	"manual_selector":                   true,
	"optional":                          true,
	"paused":                            true,
	"pod_info_on_mount":                 true,
	"privileged":                        true,
	"publish_not_ready_addresses":       true,
	"read_only":                         true,
	"read_only_root_filesystem":         true,
	"ready":                             true,
	"run_as_non_root":                   true,
	"serving":                           true,
	"share_process_namespace":           true,
	"stdin":                             true,
	"stdin_once":                        true,
	"suspend":                           true,
	"terminating":                       true,
	"tty":                               true,
}

// terraformBoolString converts a string set on a bool attribute the way
// Terraform does before the provider sees it: only "true", "false", "1" and
// "0" convert, anything else is a Terraform error. strconv.ParseBool is not
// used because it also takes "TRUE" and "True", which Terraform rejects.
func terraformBoolString(s string) (bool, bool) {
	switch s {
	case "true", "1":
		return true, true
	case "false", "0":
		return false, true
	}
	return false, false
}

func attributeValueFor(path, name string, val interface{}) interface{} {
	// The provider keeps the security context IDs in strings so that "" can
	// leave them unset: it sets runAsUser, runAsGroup and fsGroup only from a
	// non-empty value.
	if s, ok := val.(string); ok && s == "" && isSecurityContextIDField(path, name) {
		return nil
	}
	if s, ok := val.(string); ok && isVolumeFileModeField(path, name) {
		if mode, err := strconv.ParseInt(s, 8, 32); err == nil {
			return json.Number(strconv.FormatInt(mode, 10))
		}
	}
	if s, ok := val.(string); ok && (isConvertiblePortField(path, name) || isStringTypedNumberField(path, name) || isPDBIntOrStringField(path, name) || isEndpointSlicePortField(path, name)) && isDigitOnly(s) {
		return json.Number(canonicalizeNumericString(s))
	}
	if s, ok := val.(string); ok && providerBoolFields[name] {
		if b, ok := terraformBoolString(s); ok {
			return b
		}
	}
	return val
}

// hclBodyToMap walks a raw hclsyntax.Body — no schema declaration needed —
// and converts it into a plain map[string]interface{}, applying the
// terraform-provider-kubernetes snake_case -> camelCase convention and known
// block pluralization so the result matches K8s JSON shape. Unresolved
// attribute expressions are recorded in errs and left unset rather than
// guessed at, matching the kubernetes_manifest policy. Known dynamic blocks
// are expanded with their iterator context before field conversion.
func hclBodyToMap(body *hclsyntax.Body, evalCtx *hcl.EvalContext, errs *[]error, path string) map[string]interface{} {
	converter := terraformBodyConverter{errs: errs, remaining: maxTerraformLocalSize}
	return converter.bodyToMap(body, evalCtx, path, false, false)
}

func (c *terraformBodyConverter) bodyToMap(body *hclsyntax.Body, evalCtx *hcl.EvalContext, path string, resource, generated bool) map[string]interface{} {
	out := map[string]interface{}{}

	for name, attr := range body.Attributes {
		if c.exhausted {
			break
		}
		if resource && (resourceMetaAttributes[name] || providerControlAttributes[name]) {
			continue
		}
		val, diags := attr.Expr.Value(evalCtx)
		if diags.HasErrors() {
			*c.errs = append(*c.errs, fmt.Errorf("%s: attribute %q: %w", path, name, diags))
			continue
		}
		if generated && !c.reserve(terraformValueSize(val, c.remaining)+len(name), path) {
			continue
		}
		if generated {
			checkReferences := len(attr.Expr.Variables()) > 0 || hasUnavailableTerraformFunctions(attr.Expr, evalCtx)
			if !val.IsWhollyKnown() || (checkReferences && c.references.hasUnresolvableVariables(attr.Expr, evalCtx)) {
				*c.errs = append(*c.errs, fmt.Errorf("%s: generated attribute %q contains unresolved references", path, name))
				continue
			}
		}
		value := attributeValueFor(path, name, ctyToGo(val))
		if value == nil {
			// Terraform treats an argument set to null as if it were not there,
			// and so does the provider; leaving it in the manifest as null makes
			// a rule read the field as set.
			continue
		}
		out[attributeKeyFor(path, name)] = value
	}
	if c.exhausted {
		return out
	}
	if isPodSpecBlockPath(path) {
		applyProviderDefaults(body, evalCtx, out, providerPodSpecDefaults)
	}
	if takesProviderNamespaceDefault(path) || isPersistentVolumeClaimRefBlock(path) {
		applyProviderDefaults(body, evalCtx, out, providerNamespaceDefault)
	}

	grouped := map[string][]terraformBlock{}
	var order []string
	for _, b := range c.blocks(body, evalCtx, path, generated) {
		if resource && resourceMetaBlocks[b.Type] {
			if b.generated {
				*c.errs = append(*c.errs, fmt.Errorf("%s: dynamic cannot generate Terraform meta-block %q", path, b.Type))
			}
			continue
		}
		// A provider control block is an ordinary block of the resource, so a
		// dynamic block may generate it.
		if resource && providerControlBlocks[b.Type] {
			continue
		}
		if _, seen := grouped[b.Type]; !seen {
			order = append(order, b.Type)
		}
		grouped[b.Type] = append(grouped[b.Type], b)
	}

	for _, blockType := range order {
		blocks := grouped[blockType]
		if isBackendServicePortBlock(path, blockType) {
			out["port"] = c.bodyToMap(blocks[0].Body, blocks[0].evalCtx, path+"."+blockType, false, blocks[0].generated)
			continue
		}
		if isPersistentVolumeSourceBlock(path, blockType) {
			pvSource := c.bodyToMap(blocks[0].Body, blocks[0].evalCtx, path+"."+blockType, false, blocks[0].generated)
			for k, v := range pvSource {
				out[k] = v
			}
			continue
		}
		field := fieldNameFor(blockType)
		isRepeatable := len(blocks) > 1 || repeatableBlocks[blockType]
		if isServiceAccountSecretBlock(path, blockType) {
			field = "secrets"
			isRepeatable = true
		}
		if isDaemonSetStrategyBlock(path, blockType) {
			field = "updateStrategy"
		}
		if isNestedHPAMetricBlock(path, blockType) {
			field = "metric"
			isRepeatable = false
		}
		if isEphemeralVolumeClaimTemplateBlock(path, blockType) {
			field = "volumeClaimTemplate"
			isRepeatable = false
		}
		if isPodAffinityRequiredBlock(path, blockType) {
			isRepeatable = true
		}

		if isRepeatable {
			var arr []interface{}
			for _, b := range blocks {
				arr = append(arr, c.bodyToMap(b.Body, b.evalCtx, path+"."+blockType, false, b.generated))
			}
			out[field] = arr
			continue
		}
		out[field] = c.bodyToMap(blocks[0].Body, blocks[0].evalCtx, path+"."+blockType, false, blocks[0].generated)
	}

	if strings.HasSuffix(path, ".path") && strings.HasPrefix(path, "kubernetes_ingress_v1") {
		if pt, has := out["pathType"]; !has || pt == nil {
			out["pathType"] = "ImplementationSpecific"
		}
	}

	return out
}

// hclResourceBodyToMap converts the top-level body of a resource block. It
// strips Terraform meta-arguments (depends_on, provider, count, for_each,
// lifecycle, provisioner, connection) before delegating each remaining
// attribute/block to the same conversion hclBodyToMap uses, so nested
// Kubernetes fields with the same names (e.g. a container's own "lifecycle"
// block) are unaffected.
func hclResourceBodyToMap(body *hclsyntax.Body, evalCtx *hcl.EvalContext, errs *[]error, path string, references ...terraformReferenceChecker) map[string]interface{} {
	converter := terraformBodyConverter{errs: errs, remaining: maxTerraformLocalSize}
	if len(references) > 0 {
		converter.references = references[0]
	}
	return converter.bodyToMap(body, evalCtx, path, true, false)
}

// extractTypedResources finds resource "kubernetes_<type>" "name" { ... }
// blocks for the typed provider resources listed in typedResourceGVK and
// converts each into a K8s manifest map. Resource types with no entry in the
// table are left alone (not guessed at); a metadata.name is defaulted from
// the Terraform resource label when the block doesn't set one explicitly. A
// resource with count or for_each becomes one manifest per known instance.
//
// An attribute that can't be resolved is left unset rather than guessed at.
// Its errors are returned as *terraformResourceError, so the loader can leave
// out only that resource and still scan the rest of the configuration.
func extractTypedResources(body hcl.Body, evalCtx *hcl.EvalContext, references ...terraformReferenceChecker) ([]map[string]interface{}, []error) {
	manifests, errs := extractTypedResourceManifests(body, evalCtx, references...)
	return terraformManifestObjects(manifests), errs
}

// extractTypedResourceManifests is extractTypedResources, keeping the source
// range of the resource block each manifest was converted from and marking
// the manifests of a resource with errors as incomplete.
func extractTypedResourceManifests(body hcl.Body, evalCtx *hcl.EvalContext, references ...terraformReferenceChecker) ([]terraformManifest, []error) {
	synBody, ok := body.(*hclsyntax.Body)
	if !ok {
		return nil, nil
	}
	var reference terraformReferenceChecker
	if len(references) > 0 {
		reference = references[0]
	}
	var errs []error
	var manifests []terraformManifest

	for _, block := range synBody.Blocks {
		if block.Type != "resource" || len(block.Labels) < 2 {
			continue
		}
		gvk, supported := typedResourceGVK[block.Labels[0]]
		if !supported {
			continue
		}

		path := block.Labels[0] + "." + block.Labels[1]
		instances, err := terraformResourceInstances(
			syntaxAttribute(block.Body, "count"), syntaxAttribute(block.Body, "for_each"),
			evalCtx, reference, path, reference.sourceSize(block.Body, block.Range().End.Byte-block.Range().Start.Byte))
		if err != nil {
			errs = append(errs, &terraformResourceError{resource: path, err: err})
			continue
		}
		// All instances of the resource share one converter, so the values and
		// dynamic blocks they generate are bounded together, not per instance.
		var resourceErrs []error
		converter := terraformBodyConverter{errs: &resourceErrs, remaining: maxTerraformLocalSize, references: reference}
		var converted []terraformManifest
		for _, instanceCtx := range instances {
			converted = append(converted, terraformManifest{
				object: typedResourceManifest(&converter, block, gvk.apiVersion, gvk.kind, instanceCtx, path),
				source: block.DefRange(),
			})
		}
		for _, err := range resourceErrs {
			errs = append(errs, &terraformResourceError{resource: path, err: err})
		}
		for i := range converted {
			converted[i].incomplete = len(resourceErrs) > 0
		}
		manifests = append(manifests, converted...)
	}
	return manifests, errs
}

// terraformResourceError is an error converting one resource, such as an
// attribute that depends on another resource, a data source or a variable
// without a value. Only that resource is left out of the scan.
type terraformResourceError struct {
	// resource is the resource's address, such as kubernetes_pod_v1.web.
	resource string
	err      error
}

func (e *terraformResourceError) Error() string {
	return e.err.Error()
}

func (e *terraformResourceError) Unwrap() error {
	return e.err
}

// onlyTerraformResourceErrors returns the resources errs left out, in order
// and without repeats, when every error in errs is a *terraformResourceError,
// so the rest of the configuration can still be scanned. ok is false when errs
// is empty or holds any other error.
func onlyTerraformResourceErrors(errs []error) (resources []string, ok bool) {
	resources, _, others := splitTerraformResourceErrors(errs)
	if len(errs) == 0 || len(others) > 0 {
		return nil, false
	}
	return resources, true
}

// splitTerraformResourceErrors splits errs into the resources that were left
// out, in order and without repeats, with the *terraformResourceError values
// that name them, and every other error.
func splitTerraformResourceErrors(errs []error) (resources []string, resourceErrs, others []error) {
	seen := map[string]bool{}
	for _, err := range errs {
		var resourceErr *terraformResourceError
		if !errors.As(err, &resourceErr) {
			others = append(others, err)
			continue
		}
		resourceErrs = append(resourceErrs, err)
		if !seen[resourceErr.resource] {
			seen[resourceErr.resource] = true
			resources = append(resources, resourceErr.resource)
		}
	}
	return resources, resourceErrs, others
}

// terraformUnresolvedResourcesSkip records that some resources of the
// Terraform configuration in dir were left out. Like the other Terraform
// skips, its reason carries neither resource labels nor file names, which
// --hide can't anonymize in free text; the resources are listed in Resources,
// which it does, and the scan logs name them with the reasons.
func terraformUnresolvedResourcesSkip(dir string, resources []string) SkippedManifest {
	return SkippedManifest{
		Path:      dir,
		Reason:    fmt.Sprintf("%d Terraform resource(s) not scanned because they use values that can't be resolved, such as other resources, data sources or variables without a value; see scan logs for details", len(resources)),
		Resources: resources,
	}
}

// syntaxAttribute returns the named attribute of body, or nil when it isn't set.
func syntaxAttribute(body *hclsyntax.Body, name string) *hcl.Attribute {
	if attr, ok := body.Attributes[name]; ok {
		return attr.AsHCLAttribute()
	}
	return nil
}

// typedResourceManifest converts one instance of a typed resource block,
// evaluated in evalCtx, into a Kubernetes manifest.
func typedResourceManifest(converter *terraformBodyConverter, block *hclsyntax.Block, apiVersion, kind string, evalCtx *hcl.EvalContext, path string) map[string]interface{} {
	obj := converter.bodyToMap(block.Body, evalCtx, path, true, false)
	obj["apiVersion"] = apiVersion
	if block.Labels[0] == "kubernetes_horizontal_pod_autoscaler" && usesHPAV2beta2(obj) {
		obj["apiVersion"] = "autoscaling/v2beta2"
	}
	obj["kind"] = kind

	meta, _ := obj["metadata"].(map[string]interface{})
	if meta == nil {
		meta = map[string]interface{}{}
	}
	if _, has := meta["name"]; !has {
		if block.Labels[0] == "kubernetes_default_service_account" || block.Labels[0] == "kubernetes_default_service_account_v1" {
			meta["name"] = "default"
		} else {
			meta["name"] = block.Labels[1]
		}
	}
	obj["metadata"] = meta
	return obj
}

// podSpecBlockPath is where, below the resource itself, a typed resource of the
// given kind keeps its pod spec block, or "" for a kind without one.
func podSpecBlockPath(kind string) string {
	switch kind {
	case "Pod":
		return "spec"
	case "Deployment", "StatefulSet", "DaemonSet", "Job":
		return "spec.template.spec"
	case "CronJob":
		return "spec.job_template.spec.template.spec"
	}
	return ""
}

// typedBlockPath splits path, as hclBodyToMap builds it (<resource
// type>.<resource name>.<blocks>), into the kind of the typed resource and the
// blocks below it.
func typedBlockPath(path string) (kind, blocks string, ok bool) {
	resourceType, rest, ok := strings.Cut(path, ".")
	if !ok {
		return "", "", false
	}
	_, blocks, ok = strings.Cut(rest, ".")
	if !ok {
		return "", "", false
	}
	gvk, known := typedResourceGVK[resourceType]
	if !known {
		return "", "", false
	}
	return gvk.kind, blocks, true
}

// isPodSpecBlockPath reports whether path is the pod spec block of a typed
// resource.
func isPodSpecBlockPath(path string) bool {
	kind, blocks, ok := typedBlockPath(path)
	if !ok {
		return false
	}
	want := podSpecBlockPath(kind)
	return want != "" && blocks == want
}

// clusterScopedTypedKinds are the typed resource kinds that live in no
// namespace. The provider gives their metadata no namespace field.
var clusterScopedTypedKinds = map[string]bool{
	"Namespace":                      true,
	"ClusterRole":                    true,
	"ClusterRoleBinding":             true,
	"PersistentVolume":               true,
	"PriorityClass":                  true,
	"MutatingWebhookConfiguration":   true,
	"ValidatingWebhookConfiguration": true,
	"StorageClass":                   true,
	"IngressClass":                   true,
	"CertificateSigningRequest":      true,
	"CSIDriver":                      true,
	"RuntimeClass":                   true,
}

// providerNamespaceDefault is the namespace the provider writes into a block
// that leaves it out. Its schema defaults namespace to "default" both in the
// metadata of a namespaced resource and in an RBAC binding's subject.
//
// Kubernetes does not do the same for a subject: it reads a ServiceAccount
// subject without a namespace as one in the RoleBinding's own namespace. So a
// kubernetes_role_binding in namespace "apps" naming ServiceAccount "ci" binds
// default/ci, and a cluster role binding naming one binds default/ci where the
// API server would otherwise reject it.
var providerNamespaceDefault = map[string]interface{}{
	"namespace": "default",
}

// takesProviderNamespaceDefault reports whether path is a block the provider
// gives a default namespace: the top-level metadata of a namespaced typed
// resource, or a subject of a role binding. A pod template's metadata is not
// one, as its pods take the namespace of the resource.
func takesProviderNamespaceDefault(path string) bool {
	kind, blocks, ok := typedBlockPath(path)
	if !ok {
		return false
	}
	switch blocks {
	case "metadata":
		return !clusterScopedTypedKinds[kind]
	case "subject":
		return kind == "RoleBinding" || kind == "ClusterRoleBinding"
	}
	return false
}

// providerPodSpecDefaults are pod spec fields the provider writes into every pod
// it creates even when the configuration leaves them out, because its schema
// gives them a default, and whose default differs from what Kubernetes does
// when the field is absent. automount_service_account_token defaults to true:
// the provider always sends automountServiceAccountToken, so a pod made from a
// configuration that leaves it out mounts a token even when its
// ServiceAccount disables automounting.
var providerPodSpecDefaults = map[string]interface{}{
	"automount_service_account_token": true,
}

// unwrapParentheses strips any enclosing grouping parentheses and
// interpolation-only template wraps from expr.
func unwrapParentheses(expr hcl.Expression) hcl.Expression {
	for {
		switch e := expr.(type) {
		case *hclsyntax.ParenthesesExpr:
			if e == nil {
				return expr
			}
			expr = e.Expression
		case *hclsyntax.TemplateWrapExpr:
			if e == nil {
				return expr
			}
			expr = e.Wrapped
		default:
			return expr
		}
	}
}

// hasUnresolvableVariables reports whether expr cannot be resolved in evalCtx,
// or whether expr evaluated to null because an unresolvable reference in a
// try(...) or conditional expression failed and fell back to null.
//
// Unused fallbacks in try(...) that reference unresolvable variables do not
// prevent provider defaults when the primary operand evaluates cleanly without
// error.
func hasUnresolvableVariables(expr hcl.Expression, evalCtx *hcl.EvalContext) bool {
	checker := terraformReferenceChecker{}
	return checker.hasUnresolvableVariables(expr, evalCtx)
}

type terraformReferenceChecker struct {
	localExpressions    map[string]hcl.Expression
	moduleCtx           *hcl.EvalContext
	declaredVariables   map[string]terraformVariable
	activeLocals        map[string]bool
	activeLocalPath     string
	allowUnknown        bool
	localResults        map[string]terraformLocalResult
	dependencyObservers []*terraformReferenceResult
	evaluations         map[terraformExpressionContext]terraformEvaluation
	expressionTypes     map[terraformExpressionContext]cty.Type
	proofVariables      map[hcl.Expression][]hcl.Traversal
	referenceResults    map[terraformReferenceContext]terraformReferenceResult
	forItems            map[terraformReferenceContext]terraformForItems
	// sourceSizes holds the source size of resource bodies merged from
	// override files, whose own source ranges cover only the base block.
	sourceSizes map[*hclsyntax.Body]int
}

// sourceSize is the source size in bytes of a resource block with the given
// body: span, the size of its source range, unless the body was merged from
// override files.
func (c *terraformReferenceChecker) sourceSize(body *hclsyntax.Body, span int) int {
	if size, ok := c.sourceSizes[body]; ok {
		return size
	}
	return span
}

type terraformReferenceResult struct {
	unresolved   bool
	dependencies map[string]bool
}

type terraformLocalResult struct {
	terraformReferenceResult
	activeLocalPath string
}

type terraformForItems struct {
	items        []terraformForItem
	dependencies map[string]bool
}

type terraformExpressionContext struct {
	expr hcl.Expression
	ctx  *hcl.EvalContext
}

type terraformReferenceContext struct {
	terraformExpressionContext
	activeLocals string
}

type terraformEvaluation struct {
	value    cty.Value
	diags    hcl.Diagnostics
	elements []cty.Value
}

type terraformForItem struct {
	key cty.Value
	ctx *hcl.EvalContext
}

func (c *terraformReferenceChecker) expressionValue(expr hcl.Expression, ctx *hcl.EvalContext) (cty.Value, hcl.Diagnostics) {
	key := terraformExpressionContext{expr, ctx}
	if result, exists := c.evaluations[key]; exists {
		return result.value, result.diags
	}
	value, diags := expr.Value(ctx)
	c.evaluations[key] = terraformEvaluation{value: value, diags: diags}
	return value, diags
}

func (c *terraformReferenceChecker) recordLocalDependency(name string) {
	if len(c.dependencyObservers) == 0 {
		return
	}
	observer := c.dependencyObservers[len(c.dependencyObservers)-1]
	if observer.dependencies == nil {
		observer.dependencies = map[string]bool{}
	}
	observer.dependencies[name] = true
}

func (c *terraformReferenceChecker) replayLocalDependencies(dependencies map[string]bool) {
	for name := range dependencies {
		c.recordLocalDependency(name)
	}
}

func (c *terraformReferenceChecker) finishDependencyObservation() {
	last := len(c.dependencyObservers) - 1
	observation := c.dependencyObservers[last]
	c.dependencyObservers = c.dependencyObservers[:last]
	c.replayLocalDependencies(observation.dependencies)
}

func (c *terraformReferenceChecker) forExpressionItems(loop *hclsyntax.ForExpr, evalCtx *hcl.EvalContext) ([]terraformForItem, bool) {
	cacheKey := terraformReferenceContext{terraformExpressionContext{loop, evalCtx}, c.activeLocalPath}
	if result, exists := c.forItems[cacheKey]; exists {
		c.replayLocalDependencies(result.dependencies)
		return result.items, false
	}
	observation := terraformReferenceResult{}
	c.dependencyObservers = append(c.dependencyObservers, &observation)
	defer c.finishDependencyObservation()
	if c.hasUnresolvableVariables(loop.CollExpr, evalCtx) {
		return nil, true
	}
	collection, diags := c.expressionValue(loop.CollExpr, evalCtx)
	if diags.HasErrors() || collection.IsNull() || !collection.IsKnown() || !collection.CanIterateElements() {
		return nil, false
	}
	if loop.CondExpr != nil {
		childCtx := evalCtx.NewChild()
		childCtx.Variables = map[string]cty.Value{loop.ValVar: cty.DynamicVal}
		if loop.KeyVar != "" {
			childCtx.Variables[loop.KeyVar] = cty.DynamicVal
		}
		condition, diags := c.expressionValue(loop.CondExpr, childCtx)
		failed := diags.HasErrors() || condition.IsNull()
		if !failed {
			_, err := convert.Convert(condition, cty.Bool)
			failed = err != nil
		}
		// try() and can() catch input errors, so a Boolean type proves the filter converts.
		call, isCall := unwrapParentheses(loop.CondExpr).(*hclsyntax.FunctionCallExpr)
		caught := isCall && (call.Name == "try" || call.Name == "can") && c.expressionType(call, childCtx).Equals(cty.Bool)
		// HCL checks filters with unknown iterator placeholders before iteration,
		// so a successful probe still depends on inputs when nothing is iterated.
		if failed || (collection.LengthInt() == 0 && !caught) {
			precheck := terraformReferenceChecker{
				localExpressions: c.localExpressions, moduleCtx: c.moduleCtx,
				declaredVariables: c.declaredVariables,
				activeLocals:      c.activeLocals, activeLocalPath: c.activeLocalPath,
				localResults: map[string]terraformLocalResult{}, dependencyObservers: c.dependencyObservers,
				allowUnknown: true,
			}
			if precheck.hasUnresolvableVariables(loop.CondExpr, childCtx) {
				return nil, true
			}
			if failed {
				return nil, false
			}
		}
	}
	var items []terraformForItem
	for it := collection.ElementIterator(); it.Next(); {
		key, value := it.Element()
		childCtx := evalCtx.NewChild()
		childCtx.Variables = map[string]cty.Value{loop.ValVar: value}
		if loop.KeyVar != "" {
			childCtx.Variables[loop.KeyVar] = key
		}
		if loop.CondExpr != nil {
			if c.hasUnresolvableVariables(loop.CondExpr, childCtx) {
				return nil, true
			}
			include, diags := c.expressionValue(loop.CondExpr, childCtx)
			if diags.HasErrors() || include.IsNull() || !include.IsKnown() {
				continue
			}
			include, err := convert.Convert(include, cty.Bool)
			if err != nil {
				continue
			}
			if !include.True() {
				continue
			}
		}
		if loop.KeyExpr != nil {
			if c.hasUnresolvableVariables(loop.KeyExpr, childCtx) {
				return nil, true
			}
			keyValue, keyDiags := c.expressionValue(loop.KeyExpr, childCtx)
			if keyDiags.HasErrors() || keyValue.IsNull() {
				continue
			}
			var err error
			key, err = convert.Convert(keyValue, cty.String)
			if err != nil {
				continue
			}
		}
		items = append(items, terraformForItem{key, childCtx})
	}
	c.forItems[cacheKey] = terraformForItems{items, observation.dependencies}
	return items, false
}

func (c *terraformReferenceChecker) hasUnresolvableVariables(expr hcl.Expression, evalCtx *hcl.EvalContext) bool {
	return c.hasUnresolvableSelection(expr, evalCtx, nil)
}

func (c *terraformReferenceChecker) hasUnresolvableSelection(expr hcl.Expression, evalCtx *hcl.EvalContext, selection hcl.Traversal) (unresolved bool) {
	expr = unwrapParentheses(expr)
	if expr == nil {
		return false
	}
	if evalCtx == nil {
		return len(expr.Variables()) > 0
	}

	if c.evaluations == nil {
		// Retain observations only for this check, including repeated splat selections.
		c.evaluations = map[terraformExpressionContext]terraformEvaluation{}
		c.expressionTypes = map[terraformExpressionContext]cty.Type{}
		c.proofVariables = map[hcl.Expression][]hcl.Traversal{}
		c.referenceResults = map[terraformReferenceContext]terraformReferenceResult{}
		c.forItems = map[terraformReferenceContext]terraformForItems{}
		defer func() {
			c.evaluations = nil
			c.expressionTypes = nil
			c.proofVariables = nil
			c.referenceResults = nil
			c.forItems = nil
		}()
	}
	val, diags := c.expressionValue(expr, evalCtx)
	if diags.HasErrors() {
		// A failed construction can hide unresolved expressions after the selected result.
		selection = nil
	} else if !val.IsKnown() && !c.allowUnknown {
		return true
	}
	if len(selection) == 0 {
		// Active locals affect cycle detection even when the evaluated value is unchanged.
		key := terraformReferenceContext{terraformExpressionContext{expr, evalCtx}, c.activeLocalPath}
		if result, checked := c.referenceResults[key]; checked {
			c.replayLocalDependencies(result.dependencies)
			return result.unresolved
		}
		observation := terraformReferenceResult{}
		c.dependencyObservers = append(c.dependencyObservers, &observation)
		defer func() {
			observation.unresolved = unresolved
			c.referenceResults[key] = observation
			c.finishDependencyObservation()
		}()
	}
	if call, ok := expr.(*hclsyntax.FunctionCallExpr); ok && !terraformFunctionAvailable(call.Name, evalCtx) {
		return true
	}

	if key, ok := expr.(*hclsyntax.ObjectConsKeyExpr); ok {
		if !key.ForceNonLiteral && hcl.ExprAsKeyword(key.Wrapped) != "" {
			return false
		}
		return c.hasUnresolvableSelection(key.Wrapped, evalCtx, selection)
	}

	if relative, ok := expr.(*hclsyntax.RelativeTraversalExpr); ok {
		return c.hasUnresolvableSelection(relative.Source, evalCtx, append(append(hcl.Traversal{}, relative.Traversal...), selection...))
	}

	if splat, ok := expr.(*hclsyntax.SplatExpr); ok {
		collection, diags := c.expressionValue(splat.Source, evalCtx)
		if diags.HasErrors() || collection.IsNull() || !collection.IsKnown() {
			return c.hasUnresolvableVariables(splat.Source, evalCtx)
		}
		ty := collection.Type()
		autoUpgrade := !ty.IsTupleType() && !ty.IsListType() && !ty.IsSetType()
		if autoUpgrade {
			collection = cty.TupleVal([]cty.Value{collection})
		}
		if collection.LengthInt() == 0 {
			return c.hasUnresolvableVariables(splat.Source, evalCtx)
		}
		postfix, selectedPath := terraformSplatTraversal(splat.Each, splat.Item, evalCtx)
		if !selectedPath || ty.IsSetType() {
			if c.hasUnresolvableVariables(splat.Source, evalCtx) {
				return true
			}
		}
		selectedIndex := int64(-1)
		if len(selection) > 0 {
			index, valid := terraformSequenceIndex(selection[0])
			if !valid {
				return c.hasUnresolvableSelection(splat.Source, evalCtx, selection)
			}
			selectedIndex = index
		}
		sourceKey := terraformExpressionContext{splat.Source, evalCtx}
		observed := c.evaluations[sourceKey]
		if observed.elements == nil {
			observed.elements = collection.AsValueSlice()
			c.evaluations[sourceKey] = observed
		}
		elements := observed.elements
		start := 0
		if selectedIndex >= 0 {
			if selectedIndex >= int64(len(elements)) {
				return c.hasUnresolvableSelection(splat.Source, evalCtx, selection)
			}
			start = int(selectedIndex)
			elements = elements[start : start+1]
		}
		for i, value := range elements {
			tail := selection
			if selectedIndex >= 0 {
				tail = selection[1:]
			}
			if selectedPath && !ty.IsSetType() {
				sourceSelection := append(append(hcl.Traversal{}, postfix...), tail...)
				if !autoUpgrade {
					sourceSelection = append(hcl.Traversal{hcl.TraverseIndex{Key: cty.NumberIntVal(int64(start + i))}}, sourceSelection...)
				}
				if c.hasUnresolvableSelection(splat.Source, evalCtx, sourceSelection) {
					return true
				}
			}
			if c.hasUnresolvableSelection(terraformSplatItemExpression(splat.Each, splat.Item, value), evalCtx, tail) {
				return true
			}
		}
		return false
	}

	if loop, ok := expr.(*hclsyntax.ForExpr); ok {
		items, unresolved := c.forExpressionItems(loop, evalCtx)
		if unresolved {
			return true
		}
		selectedKey := cty.NilVal
		if len(selection) > 0 && loop.KeyExpr == nil {
			indexValue, valid := terraformSequenceIndex(selection[0])
			if !valid || indexValue >= int64(len(items)) {
				return false
			}
			return c.hasUnresolvableSelection(loop.ValExpr, items[indexValue].ctx, selection[1:])
		} else if len(selection) > 0 {
			key, valid := terraformObjectSelectionKey(selection[0])
			if !valid {
				return false
			}
			selectedKey = key
		}
		resultIndex := int64(0)
		for _, item := range items {
			childCtx := item.ctx
			if selectedKey != cty.NilVal {
				if item.key == cty.NilVal || !item.key.RawEquals(selectedKey) {
					continue
				}
				if !loop.Group {
					return c.hasUnresolvableSelection(loop.ValExpr, childCtx, selection[1:])
				}
				if len(selection) > 1 {
					index, valid := terraformSequenceIndex(selection[1])
					if !valid {
						return false
					}
					if resultIndex == index {
						return c.hasUnresolvableSelection(loop.ValExpr, childCtx, selection[2:])
					}
					resultIndex++
					continue
				}
				if c.hasUnresolvableVariables(loop.ValExpr, childCtx) {
					return true
				}
				continue
			}
			if c.hasUnresolvableVariables(loop.ValExpr, childCtx) {
				return true
			}
		}
		return false
	}

	if call, ok := expr.(*hclsyntax.FunctionCallExpr); ok && call.Name == "try" {
		hadUnresolvableArg := false
		for _, rawArg := range call.Args {
			arg := unwrapParentheses(rawArg)
			val, diags := c.expressionValue(arg, evalCtx)
			if diags.HasErrors() || (!val.IsKnown() && !c.allowUnknown) {
				if c.hasUnresolvableVariables(arg, evalCtx) {
					hadUnresolvableArg = true
				}
				continue
			}
			if hadUnresolvableArg {
				// An earlier argument failed due to an unresolvable reference;
				// try() suppressed that unresolvable reference to use this fallback.
				return true
			}
			// This candidate succeeded without being preceded by an unresolvable reference.
			return c.hasUnresolvableSelection(arg, evalCtx, selection)
		}
		return true
	}

	if call, ok := expr.(*hclsyntax.FunctionCallExpr); ok && call.Name == "coalesce" {
		for i, rawArg := range call.Args {
			arg := unwrapParentheses(rawArg)
			val, diags := c.expressionValue(arg, evalCtx)
			if diags.HasErrors() {
				return c.hasUnresolvableVariables(arg, evalCtx)
			}
			if !val.IsKnown() {
				if c.allowUnknown {
					return c.hasUnresolvableVariables(arg, evalCtx)
				}
				return true
			}
			if val.IsNull() || (val.Type() == cty.String && val.AsString() == "") {
				if c.hasUnresolvableVariables(arg, evalCtx) {
					return true
				}
				continue
			}
			if !c.coalesceTypesIndependent(call.Args[i+1:], evalCtx, val.Type()) {
				return true
			}
			return c.hasUnresolvableSelection(arg, evalCtx, selection)
		}
		return false
	}

	if call, ok := expr.(*hclsyntax.FunctionCallExpr); ok && call.Name == "can" {
		if len(call.Args) == 0 {
			return false
		}
		arg := unwrapParentheses(call.Args[0])
		return c.hasUnresolvableVariables(arg, evalCtx)
	}

	if call, ok := expr.(*hclsyntax.FunctionCallExpr); ok && call.Name == "lookup" {
		args := call.Args
		if call.ExpandFinal {
			args = nil
			if len(call.Args) > 0 {
				last := len(call.Args) - 1
				if expanded, ok := unwrapParentheses(call.Args[last]).(*hclsyntax.TupleConsExpr); ok {
					args = append(append([]hclsyntax.Expression{}, call.Args[:last]...), expanded.Exprs...)
				} else if expanded, expandedDiags := c.expressionValue(call.Args[last], evalCtx); !expandedDiags.HasErrors() && expanded.IsKnown() && !expanded.IsNull() && (expanded.Type().IsTupleType() || expanded.Type().IsListType()) {
					count := expanded.LengthInt()
					if last+count == 2 || last+count == 3 {
						// A missing position checks the expansion's shape without reading unused values.
						if c.hasUnresolvableSelection(call.Args[last], evalCtx, hcl.Traversal{hcl.TraverseIndex{Key: cty.NumberIntVal(int64(count))}}) {
							return true
						}
						args = append([]hclsyntax.Expression{}, call.Args[:last]...)
						for i := 0; i < count; i++ {
							args = append(args, &hclsyntax.IndexExpr{
								Collection: call.Args[last],
								Key:        &hclsyntax.LiteralValueExpr{Val: cty.NumberIntVal(int64(i))},
								SrcRange:   call.Args[last].Range(),
							})
						}
					}
				}
			}
		}
		if len(args) == 2 || (len(args) == 3 && !diags.HasErrors()) {
			if c.hasUnresolvableVariables(args[1], evalCtx) {
				return true
			}
			mapping, mapDiags := c.expressionValue(args[0], evalCtx)
			key, keyDiags := c.expressionValue(args[1], evalCtx)
			if !mapDiags.HasErrors() && !keyDiags.HasErrors() && mapping.IsKnown() && !mapping.IsNull() && (mapping.Type().IsObjectType() || mapping.Type().IsMapType()) {
				key, err := convert.Convert(key, cty.String)
				if err == nil && key.IsKnown() && !key.IsNull() {
					found := mapping.Type().IsObjectType() && mapping.Type().HasAttribute(key.AsString())
					if mapping.Type().IsMapType() {
						found = mapping.HasIndex(key).True()
					}
					path := hcl.Traversal{hcl.TraverseIndex{Key: key}}
					if found {
						path = append(path, selection...)
					}
					if c.hasUnresolvableSelection(args[0], evalCtx, path) {
						return true
					}
					if len(args) == 3 {
						if !found {
							return c.hasUnresolvableSelection(args[2], evalCtx, selection)
						}
						// Maps validate the default's conversion even when their key exists.
						if mapping.Type().IsMapType() {
							return c.hasUnresolvableVariables(args[2], evalCtx)
						}
					}
					return false
				}
			}
		}
	}

	if call, ok := expr.(*hclsyntax.FunctionCallExpr); ok {
		for _, rawArg := range call.Args {
			if c.hasUnresolvableVariables(rawArg, evalCtx) {
				return true
			}
		}
		return false
	}

	if cond, ok := expr.(*hclsyntax.ConditionalExpr); ok {
		if c.allowUnknown {
			left := c.provenExpressionValue(cond.TrueResult, evalCtx)
			right := c.provenExpressionValue(cond.FalseResult, evalCtx)
			if left != cty.NilVal && right != cty.NilVal && !left.Type().HasDynamicTypes() && !right.Type().HasDynamicTypes() {
				if common, _ := convert.UnifyUnsafe([]cty.Type{left.Type(), right.Type()}); common == cty.NilType {
					return false
				}
			}
		}
		condExpr := unwrapParentheses(cond.Condition)
		if c.hasUnresolvableVariables(condExpr, evalCtx) {
			return true
		}
		val, diags := c.expressionValue(condExpr, evalCtx)
		if diags.HasErrors() || val.IsNull() {
			return false
		}
		if !val.IsKnown() {
			if c.allowUnknown {
				return c.hasUnresolvableSelection(cond.TrueResult, evalCtx, selection) || c.hasUnresolvableSelection(cond.FalseResult, evalCtx, selection)
			}
			return true
		}
		boolVal, err := convert.Convert(val, cty.Bool)
		if err != nil || !boolVal.IsKnown() || boolVal.IsNull() {
			// A fixed condition error is caught by try without consulting either branch.
			return false
		}
		if boolVal.True() {
			return c.hasUnresolvableSelection(cond.TrueResult, evalCtx, selection)
		}
		return c.hasUnresolvableSelection(cond.FalseResult, evalCtx, selection)
	}

	if join, ok := expr.(*hclsyntax.TemplateJoinExpr); ok {
		return c.hasUnresolvableVariables(join.Tuple, evalCtx)
	}

	if tmpl, ok := expr.(*hclsyntax.TemplateExpr); ok {
		for _, part := range tmpl.Parts {
			if c.hasUnresolvableVariables(part, evalCtx) {
				return true
			}
		}
		return false
	}

	if tuple, ok := expr.(*hclsyntax.TupleConsExpr); ok {
		if len(selection) > 0 {
			if i, valid := terraformSequenceIndex(selection[0]); valid && i < int64(len(tuple.Exprs)) {
				return c.hasUnresolvableSelection(tuple.Exprs[i], evalCtx, selection[1:])
			}
			return false
		}
		for _, elem := range tuple.Exprs {
			if c.hasUnresolvableVariables(elem, evalCtx) {
				return true
			}
		}
		return false
	}

	if obj, ok := expr.(*hclsyntax.ObjectConsExpr); ok {
		if len(selection) > 0 {
			key := cty.NilVal
			switch step := selection[0].(type) {
			case hcl.TraverseAttr:
				key = cty.StringVal(step.Name)
			case hcl.TraverseIndex:
				key = step.Key
			}
			if key != cty.NilVal {
				key, err := convert.Convert(key, cty.String)
				if err == nil && key.IsKnown() && !key.IsNull() {
					var selected hcl.Expression
					for _, item := range obj.Items {
						if c.hasUnresolvableVariables(item.KeyExpr, evalCtx) {
							return true
						}
						itemKey, diags := c.expressionValue(item.KeyExpr, evalCtx)
						if !diags.HasErrors() {
							itemKey, err = convert.Convert(itemKey, cty.String)
							if err == nil && itemKey.RawEquals(key) {
								selected = item.ValueExpr
							}
						}
					}
					return c.hasUnresolvableSelection(selected, evalCtx, selection[1:])
				}
			}
		}
		for _, item := range obj.Items {
			if c.hasUnresolvableVariables(objectKeyExpr(item.KeyExpr), evalCtx) || c.hasUnresolvableVariables(item.ValueExpr, evalCtx) {
				return true
			}
		}
		return false
	}

	if unary, ok := expr.(*hclsyntax.UnaryOpExpr); ok {
		return c.hasUnresolvableVariables(unary.Val, evalCtx)
	}

	if binary, ok := expr.(*hclsyntax.BinaryOpExpr); ok {
		if !diags.HasErrors() && (binary.Op == hclsyntax.OpLogicalOr || binary.Op == hclsyntax.OpLogicalAnd) {
			operands := []hclsyntax.Expression{binary.LHS, binary.RHS}
			for i, operand := range operands {
				value, operandDiags := c.expressionValue(operand, evalCtx)
				if operandDiags.HasErrors() {
					continue
				}
				value, err := convert.Convert(value, cty.Bool)
				if err == nil && value.IsKnown() && !value.IsNull() && value.True() == (binary.Op == hclsyntax.OpLogicalOr) && !c.hasUnresolvableVariables(operand, evalCtx) {
					other := operands[1-i]
					// HCL converts both operands before applying its logical shortcut.
					return c.hasUnresolvableVariables(other, evalCtx) && !c.convertsToBool(other, evalCtx)
				}
			}
		}
		return c.hasUnresolvableVariables(binary.LHS, evalCtx) || c.hasUnresolvableVariables(binary.RHS, evalCtx)
	}

	if idx, ok := expr.(*hclsyntax.IndexExpr); ok {
		if c.hasUnresolvableVariables(idx.Key, evalCtx) {
			return true
		}
		key, diags := c.expressionValue(idx.Key, evalCtx)
		if diags.HasErrors() || key.IsNull() || !key.IsKnown() {
			return c.hasUnresolvableVariables(idx.Collection, evalCtx)
		}
		return c.hasUnresolvableSelection(idx.Collection, evalCtx, append(hcl.Traversal{hcl.TraverseIndex{Key: key}}, selection...))
	}

	vars := expr.Variables()
	if len(vars) == 0 {
		return false
	}
	for _, traversal := range vars {
		if traversal.IsRelative() {
			continue
		}
		// Only the referenced variable, local or object must resolve. A key or
		// attribute missing from a known value is an evaluation error, which
		// try() catches as Terraform does, not an unresolvable reference.
		reference := append(append(hcl.Traversal{}, traversal...), selection...)
		depth := 1
		root := traversal.RootName()
		scope := terraformVariableScope(root, evalCtx)
		if (root == "var" || root == "local") && (scope == c.moduleCtx || (c.moduleCtx == nil && scope != nil && scope.Parent() == nil)) {
			depth = 2
		}
		if len(reference) > depth {
			reference = reference[:depth]
		}
		if _, diags := reference.TraverseAbs(evalCtx); diags.HasErrors() {
			return true
		}
		if c.localReferenceUnresolved(append(append(hcl.Traversal{}, traversal...), selection...), evalCtx) {
			return true
		}
	}
	return false
}

// objectKeyExpr returns the expression an object key is evaluated from. HCL
// wraps every key in an ObjectConsKeyExpr and reads a bare name such as
// namespace as a literal string, so that case has no expression (nil).
func objectKeyExpr(expr hclsyntax.Expression) hcl.Expression {
	key, ok := expr.(*hclsyntax.ObjectConsKeyExpr)
	if !ok || key == nil {
		return expr
	}
	if !key.ForceNonLiteral && hcl.ExprAsKeyword(key.Wrapped) != "" {
		return nil
	}
	return key.Wrapped
}

func (c *terraformReferenceChecker) localReferenceUnresolved(traversal hcl.Traversal, evalCtx *hcl.EvalContext) bool {
	if len(c.localExpressions) == 0 || traversal.RootName() != "local" {
		return false
	}
	// Iterators named local shadow the module's locals; source expressions always
	// resolve in the module context, without any iterator bindings.
	scope := terraformVariableScope("local", evalCtx)
	if scope != c.moduleCtx {
		return false
	}
	if len(traversal) == 1 {
		for name := range c.localExpressions {
			if c.localUnresolved(name, nil) {
				return true
			}
		}
		return false
	}
	var name string
	switch step := traversal[1].(type) {
	case hcl.TraverseAttr:
		name = step.Name
	case hcl.TraverseIndex:
		if !step.Key.IsNull() && step.Key.IsKnown() && step.Key.Type() == cty.String {
			name = step.Key.AsString()
		}
	}
	return c.localUnresolved(name, traversal[2:])
}

func (c *terraformReferenceChecker) localUnresolved(name string, selection hcl.Traversal) bool {
	c.recordLocalDependency(name)
	if c.activeLocals[name] {
		return true
	}
	var cacheKey strings.Builder
	fmt.Fprintf(&cacheKey, "%q", name)
	for _, step := range selection {
		switch step := step.(type) {
		case hcl.TraverseAttr:
			fmt.Fprintf(&cacheKey, ".%q", step.Name)
		case hcl.TraverseIndex:
			if step.Key.IsNull() || !step.Key.IsKnown() {
				fmt.Fprintf(&cacheKey, "[invalid:%s]", step.Key.Type().FriendlyName())
				continue
			}
			switch step.Key.Type() {
			case cty.Number:
				fmt.Fprintf(&cacheKey, "[number:%s]", step.Key.AsBigFloat().Text('p', -1))
			case cty.String:
				fmt.Fprintf(&cacheKey, "[string:%q]", step.Key.AsString())
			case cty.Bool:
				fmt.Fprintf(&cacheKey, "[bool:%t]", step.Key.True())
			default:
				fmt.Fprintf(&cacheKey, "[invalid:%s]", step.Key.Type().FriendlyName())
			}
		}
	}
	key := cacheKey.String()
	if result, checked := c.localResults[key]; checked {
		reuse := result.activeLocalPath == c.activeLocalPath
		if !reuse && !result.unresolved {
			reuse = true
			for dependency := range result.dependencies {
				if c.activeLocals[dependency] {
					reuse = false
					break
				}
			}
		}
		if reuse {
			c.replayLocalDependencies(result.dependencies)
			return result.unresolved
		}
	}
	expr, exists := c.localExpressions[name]
	if !exists {
		return false
	}
	if c.activeLocals == nil {
		c.activeLocals = map[string]bool{}
		c.localResults = map[string]terraformLocalResult{}
	}
	observation := terraformReferenceResult{}
	c.dependencyObservers = append(c.dependencyObservers, &observation)
	c.activeLocals[name] = true
	previousPath := c.activeLocalPath
	c.activeLocalPath += fmt.Sprintf("%q/", name)
	result := c.hasUnresolvableSelection(expr, c.moduleCtx, selection)
	if !result {
		value, valueDiags := c.expressionValue(expr, c.moduleCtx)
		stored, storedDiags := (hcl.Traversal{hcl.TraverseRoot{Name: "local"}, hcl.TraverseAttr{Name: name}}).TraverseAbs(c.moduleCtx)
		if len(selection) > 0 {
			if !valueDiags.HasErrors() {
				value, valueDiags = selection.TraverseRel(value)
			}
			if !storedDiags.HasErrors() {
				stored, storedDiags = selection.TraverseRel(stored)
			}
		}
		// The converter uses stored locals, which may have selected an earlier fallback.
		result = valueDiags.HasErrors() != storedDiags.HasErrors() || (!valueDiags.HasErrors() && !value.RawEquals(stored))
	}
	c.activeLocalPath = previousPath
	delete(c.activeLocals, name)
	observation.unresolved = result
	c.localResults[key] = terraformLocalResult{observation, previousPath}
	c.finishDependencyObservation()
	return result
}

func terraformVariableScope(name string, ctx *hcl.EvalContext) *hcl.EvalContext {
	for ctx != nil {
		if _, bound := ctx.Variables[name]; bound {
			return ctx
		}
		ctx = ctx.Parent()
	}
	return nil
}

func terraformFunctionAvailable(name string, ctx *hcl.EvalContext) bool {
	for ctx != nil {
		if _, exists := ctx.Functions[name]; exists {
			return true
		}
		ctx = ctx.Parent()
	}
	return false
}

func hasUnavailableTerraformFunctions(expr hclsyntax.Expression, ctx *hcl.EvalContext) bool {
	unavailable := false
	hclsyntax.VisitAll(expr, func(node hclsyntax.Node) hcl.Diagnostics {
		if call, ok := node.(*hclsyntax.FunctionCallExpr); ok && !terraformFunctionAvailable(call.Name, ctx) {
			unavailable = true
		}
		return nil
	})
	return unavailable
}

func terraformSequenceIndex(step hcl.Traverser) (int64, bool) {
	index, ok := step.(hcl.TraverseIndex)
	if !ok {
		return 0, false
	}
	key, err := convert.Convert(index.Key, cty.Number)
	if err != nil || key.IsNull() || !key.IsKnown() {
		return 0, false
	}
	value, accuracy := key.AsBigFloat().Int64()
	return value, accuracy == 0 && value >= 0
}

func terraformObjectSelectionKey(step hcl.Traverser) (cty.Value, bool) {
	switch step := step.(type) {
	case hcl.TraverseAttr:
		return cty.StringVal(step.Name), true
	case hcl.TraverseIndex:
		key, err := convert.Convert(step.Key, cty.String)
		return key, err == nil && key.IsKnown() && !key.IsNull()
	default:
		return cty.NilVal, false
	}
}

func terraformSplatTraversal(expr hclsyntax.Expression, item *hclsyntax.AnonSymbolExpr, ctx *hcl.EvalContext) (hcl.Traversal, bool) {
	switch e := expr.(type) {
	case *hclsyntax.AnonSymbolExpr:
		return nil, e == item
	case *hclsyntax.RelativeTraversalExpr:
		prefix, ok := terraformSplatTraversal(e.Source, item, ctx)
		return append(prefix, e.Traversal...), ok
	case *hclsyntax.IndexExpr:
		prefix, ok := terraformSplatTraversal(e.Collection, item, ctx)
		if !ok {
			return nil, false
		}
		key, diags := e.Key.Value(ctx)
		if diags.HasErrors() || key.IsNull() || !key.IsKnown() {
			return nil, false
		}
		return append(prefix, hcl.TraverseIndex{Key: key}), true
	default:
		return nil, false
	}
}

// Bind a splat's anonymous item without modifying the parsed expression tree.
func terraformSplatItemExpression(expr hclsyntax.Expression, item *hclsyntax.AnonSymbolExpr, value cty.Value) hclsyntax.Expression {
	switch e := expr.(type) {
	case *hclsyntax.AnonSymbolExpr:
		if e == item {
			return &hclsyntax.LiteralValueExpr{Val: value, SrcRange: e.Range()}
		}
	case *hclsyntax.RelativeTraversalExpr:
		bound := *e
		bound.Source = terraformSplatItemExpression(e.Source, item, value)
		return &bound
	case *hclsyntax.IndexExpr:
		bound := *e
		bound.Collection = terraformSplatItemExpression(e.Collection, item, value)
		return &bound
	case *hclsyntax.SplatExpr:
		bound := *e
		bound.Source = terraformSplatItemExpression(e.Source, item, value)
		return &bound
	}
	return expr
}

// applyProviderDefaults fills in defaults for the fields the block leaves out
// or sets to null, which Terraform treats the same way. A field whose
// expression could not be evaluated is left out, as every unresolved attribute
// is, rather than guessed.
func applyProviderDefaults(body *hclsyntax.Body, evalCtx *hcl.EvalContext, out map[string]interface{}, defaults map[string]interface{}) {
	for name, value := range defaults {
		field := attributeNameFor(name)
		if _, set := out[field]; set {
			continue
		}
		if attr, declared := body.Attributes[name]; declared {
			if hasUnresolvableVariables(attr.Expr, evalCtx) {
				continue
			}
			if _, diags := attr.Expr.Value(evalCtx); diags.HasErrors() {
				continue
			}
		}
		out[field] = value
	}
}
