package cautils

import (
	"encoding/json"
	"fmt"
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
	"kubernetes_deployment":           {"apps/v1", "Deployment"},
	"kubernetes_deployment_v1":        {"apps/v1", "Deployment"},
	"kubernetes_stateful_set":         {"apps/v1", "StatefulSet"},
	"kubernetes_stateful_set_v1":      {"apps/v1", "StatefulSet"},
	"kubernetes_daemonset":            {"apps/v1", "DaemonSet"},
	"kubernetes_daemon_set":           {"apps/v1", "DaemonSet"},
	"kubernetes_daemon_set_v1":        {"apps/v1", "DaemonSet"},
	"kubernetes_pod":                  {"v1", "Pod"},
	"kubernetes_pod_v1":               {"v1", "Pod"},
	"kubernetes_service":              {"v1", "Service"},
	"kubernetes_service_v1":           {"v1", "Service"},
	"kubernetes_config_map":           {"v1", "ConfigMap"},
	"kubernetes_config_map_v1":        {"v1", "ConfigMap"},
	"kubernetes_secret":               {"v1", "Secret"},
	"kubernetes_secret_v1":            {"v1", "Secret"},
	"kubernetes_namespace":            {"v1", "Namespace"},
	"kubernetes_namespace_v1":         {"v1", "Namespace"},
	"kubernetes_service_account":            {"v1", "ServiceAccount"},
	"kubernetes_service_account_v1":         {"v1", "ServiceAccount"},
	"kubernetes_default_service_account":    {"v1", "ServiceAccount"},
	"kubernetes_default_service_account_v1": {"v1", "ServiceAccount"},
	"kubernetes_job":                  {"batch/v1", "Job"},
	"kubernetes_job_v1":               {"batch/v1", "Job"},
	"kubernetes_cron_job":             {"batch/v1", "CronJob"},
	"kubernetes_cron_job_v1":          {"batch/v1", "CronJob"},
	"kubernetes_ingress":              {"networking.k8s.io/v1beta1", "Ingress"},
	"kubernetes_ingress_v1":           {"networking.k8s.io/v1", "Ingress"},
	"kubernetes_network_policy":       {"networking.k8s.io/v1", "NetworkPolicy"},
	"kubernetes_network_policy_v1":    {"networking.k8s.io/v1", "NetworkPolicy"},
	"kubernetes_role":                 {"rbac.authorization.k8s.io/v1", "Role"},
	"kubernetes_role_binding":         {"rbac.authorization.k8s.io/v1", "RoleBinding"},
	"kubernetes_cluster_role":         {"rbac.authorization.k8s.io/v1", "ClusterRole"},
	"kubernetes_cluster_role_binding": {"rbac.authorization.k8s.io/v1", "ClusterRoleBinding"},

	"kubernetes_role_v1":                 {"rbac.authorization.k8s.io/v1", "Role"},
	"kubernetes_role_binding_v1":         {"rbac.authorization.k8s.io/v1", "RoleBinding"},
	"kubernetes_cluster_role_v1":         {"rbac.authorization.k8s.io/v1", "ClusterRole"},
	"kubernetes_cluster_role_binding_v1": {"rbac.authorization.k8s.io/v1", "ClusterRoleBinding"},
}

// pluralOverrides maps an HCL block label to the K8s array field name it must
// become, for the cases where camelCasing the block name alone isn't right
// (block "container" -> field "containers"). Anything not listed here just
// gets its singular name camelCased.
var pluralOverrides = map[string]string{
	"container":             "containers",
	"init_container":        "initContainers",
	"volume":                "volumes",
	"volume_mount":          "volumeMounts",
	"env_from":              "envFrom",
	"port":                  "ports",
	"toleration":            "tolerations",
	"host_alias":            "hostAliases",
	"host_aliases":          "hostAliases",
	"rule":                  "rules",
	"path":                  "paths",
	"subject":               "subjects",
	"image_pull_secret":     "imagePullSecrets",
	"image_pull_secrets":    "imagePullSecrets",
	"match_expressions":     "matchExpressions",
	"volume_claim_template": "volumeClaimTemplates",
	"http_header":           "httpHeaders",
	"sysctl":                "sysctls",
}

// repeatableBlocks lists HCL block labels that always encode as a JSON array,
// even when only one instance is present — Terraform lets you repeat a block,
// but the K8s field underneath (e.g. spec.containers) is always a list.
var repeatableBlocks = map[string]bool{
	"container": true, "init_container": true, "volume": true, "volume_mount": true,
	"env": true, "env_from": true, "port": true, "ports": true, "toleration": true,
	"host_alias": true, "host_aliases": true, "rule": true, "subject": true,
	"image_pull_secret": true, "image_pull_secrets": true,
	"match_expressions": true, "volume_claim_template": true, "http_header": true,
	"sysctl": true, "ingress": true, "egress": true, "from": true, "to": true,
	"path": true, "tls": true,
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

var fieldInitialisms = map[string]string{
	"api":  "API",
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
	return snakeToCamel(blockType)
}

func attributeNameFor(name string) string {
	return snakeToCamel(name)
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

func isConvertiblePortField(path, name string) bool {
	return isNetworkPolicyPortField(path, name) || isLegacyIngressBackendPortField(path, name) || isIngressBackendServicePortNumberField(path, name)
}

func isServiceAccountSecretBlock(path, blockType string) bool {
	if blockType != "secret" {
		return false
	}
	return (strings.HasPrefix(path, "kubernetes_service_account") ||
		strings.HasPrefix(path, "kubernetes_default_service_account")) &&
		strings.Count(path, ".") == 1
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

// isStringTypedNumberField covers the provider's string-typed fields that hold
// a number: int-or-string ports, where a value made of digits only is a port
// number and anything else a port name, as intstr.Parse reads it, and the
// security context IDs.
func isStringTypedNumberField(path, name string) bool {
	return isServiceTargetPortField(path, name) || isHandlerPortField(path, name) || isSecurityContextIDField(path, name)
}

func attributeValueFor(path, name string, val interface{}) interface{} {
	// The provider keeps the security context IDs in strings so that "" can
	// leave them unset: it sets runAsUser, runAsGroup and fsGroup only from a
	// non-empty value.
	if s, ok := val.(string); ok && s == "" && isSecurityContextIDField(path, name) {
		return nil
	}
	if s, ok := val.(string); ok && (isConvertiblePortField(path, name) || isStringTypedNumberField(path, name)) && isDigitOnly(s) {
		return json.Number(canonicalizeNumericString(s))
	}
	return val
}

// hclBodyToMap walks a raw hclsyntax.Body — no schema declaration needed —
// and converts it into a plain map[string]interface{}, applying the
// terraform-provider-kubernetes snake_case -> camelCase convention and known
// block pluralization so the result matches K8s JSON shape. Unresolved
// attribute expressions are recorded in errs and left unset rather than
// guessed at, matching the kubernetes_manifest policy.
func hclBodyToMap(body *hclsyntax.Body, evalCtx *hcl.EvalContext, errs *[]error, path string) map[string]interface{} {
	out := map[string]interface{}{}

	for name, attr := range body.Attributes {
		val, diags := attr.Expr.Value(evalCtx)
		if diags.HasErrors() {
			*errs = append(*errs, fmt.Errorf("%s: attribute %q: %w", path, name, diags))
			continue
		}
		value := attributeValueFor(path, name, ctyToGo(val))
		if value == nil {
			// Terraform treats an argument set to null as if it were not there,
			// and so does the provider; leaving it in the manifest as null makes
			// a rule read the field as set.
			continue
		}
		out[attributeNameFor(name)] = value
	}
	if isPodSpecBlockPath(path) {
		applyProviderDefaults(body, evalCtx, out, providerPodSpecDefaults)
	}
	if takesProviderNamespaceDefault(path) {
		applyProviderDefaults(body, evalCtx, out, providerNamespaceDefault)
	}

	grouped := map[string][]*hclsyntax.Block{}
	var order []string
	for _, b := range body.Blocks {
		if _, seen := grouped[b.Type]; !seen {
			order = append(order, b.Type)
		}
		grouped[b.Type] = append(grouped[b.Type], b)
	}

	for _, blockType := range order {
		blocks := grouped[blockType]
		if isBackendServicePortBlock(path, blockType) {
			out["port"] = hclBodyToMap(blocks[0].Body, evalCtx, errs, path+"."+blockType)
			continue
		}
		field := fieldNameFor(blockType)
		isRepeatable := len(blocks) > 1 || repeatableBlocks[blockType]
		if isServiceAccountSecretBlock(path, blockType) {
			field = "secrets"
			isRepeatable = true
		}

		if isRepeatable {
			var arr []interface{}
			for _, b := range blocks {
				arr = append(arr, hclBodyToMap(b.Body, evalCtx, errs, path+"."+blockType))
			}
			out[field] = arr
			continue
		}
		out[field] = hclBodyToMap(blocks[0].Body, evalCtx, errs, path+"."+blockType)
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
func hclResourceBodyToMap(body *hclsyntax.Body, evalCtx *hcl.EvalContext, errs *[]error, path string) map[string]interface{} {
	out := map[string]interface{}{}

	for name, attr := range body.Attributes {
		if resourceMetaAttributes[name] {
			continue
		}
		val, diags := attr.Expr.Value(evalCtx)
		if diags.HasErrors() {
			*errs = append(*errs, fmt.Errorf("%s: attribute %q: %w", path, name, diags))
			continue
		}
		value := attributeValueFor(path, name, ctyToGo(val))
		if value == nil {
			// Terraform treats an argument set to null as if it were not there,
			// and so does the provider; leaving it in the manifest as null makes
			// a rule read the field as set.
			continue
		}
		out[attributeNameFor(name)] = value
	}

	grouped := map[string][]*hclsyntax.Block{}
	var order []string
	for _, b := range body.Blocks {
		if resourceMetaBlocks[b.Type] {
			continue
		}
		if _, seen := grouped[b.Type]; !seen {
			order = append(order, b.Type)
		}
		grouped[b.Type] = append(grouped[b.Type], b)
	}

	for _, blockType := range order {
		blocks := grouped[blockType]
		field := fieldNameFor(blockType)
		isRepeatable := len(blocks) > 1 || repeatableBlocks[blockType]
		if isServiceAccountSecretBlock(path, blockType) {
			field = "secrets"
			isRepeatable = true
		}

		if isRepeatable {
			var arr []interface{}
			for _, b := range blocks {
				arr = append(arr, hclBodyToMap(b.Body, evalCtx, errs, path+"."+blockType))
			}
			out[field] = arr
			continue
		}
		out[field] = hclBodyToMap(blocks[0].Body, evalCtx, errs, path+"."+blockType)
	}

	return out
}

// extractTypedResources finds resource "kubernetes_<type>" "name" { ... }
// blocks for the typed provider resources listed in typedResourceGVK and
// converts each into a K8s manifest map. Resource types with no entry in the
// table are left alone (not guessed at); a metadata.name is defaulted from
// the Terraform resource label when the block doesn't set one explicitly.
func extractTypedResources(body hcl.Body, evalCtx *hcl.EvalContext) ([]map[string]interface{}, []error) {
	synBody, ok := body.(*hclsyntax.Body)
	if !ok {
		return nil, nil
	}
	var errs []error
	var manifests []map[string]interface{}

	for _, block := range synBody.Blocks {
		if block.Type != "resource" || len(block.Labels) < 2 {
			continue
		}
		gvk, supported := typedResourceGVK[block.Labels[0]]
		if !supported {
			continue
		}

		obj := hclResourceBodyToMap(block.Body, evalCtx, &errs, block.Labels[0]+"."+block.Labels[1])
		obj["apiVersion"] = gvk.apiVersion
		obj["kind"] = gvk.kind

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

		manifests = append(manifests, obj)
	}
	return manifests, errs
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
	"Namespace":          true,
	"ClusterRole":        true,
	"ClusterRoleBinding": true,
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

// unwrapParentheses strips any enclosing grouping parentheses from expr.
func unwrapParentheses(expr hcl.Expression) hcl.Expression {
	for {
		p, ok := expr.(*hclsyntax.ParenthesesExpr)
		if !ok || p == nil {
			return expr
		}
		expr = p.Expression
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
	expr = unwrapParentheses(expr)
	if expr == nil {
		return false
	}
	if evalCtx == nil {
		return len(expr.Variables()) > 0
	}

	if val, diags := expr.Value(evalCtx); !diags.HasErrors() && !val.IsKnown() {
		return true
	}

	if call, ok := expr.(*hclsyntax.FunctionCallExpr); ok && call.Name == "try" {
		hadUnresolvableArg := false
		for _, rawArg := range call.Args {
			arg := unwrapParentheses(rawArg)
			val, diags := arg.Value(evalCtx)
			if diags.HasErrors() || !val.IsKnown() {
				if hasUnresolvableVariables(arg, evalCtx) {
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
			return hasUnresolvableVariables(arg, evalCtx)
		}
		return true
	}

	if cond, ok := expr.(*hclsyntax.ConditionalExpr); ok {
		condExpr := unwrapParentheses(cond.Condition)
		if hasUnresolvableVariables(condExpr, evalCtx) {
			return true
		}
		val, diags := condExpr.Value(evalCtx)
		if diags.HasErrors() || !val.IsKnown() || val.IsNull() {
			return true
		}
		boolVal, err := convert.Convert(val, cty.Bool)
		if err != nil || !boolVal.IsKnown() || boolVal.IsNull() {
			return true
		}
		if boolVal.True() {
			return hasUnresolvableVariables(cond.TrueResult, evalCtx)
		}
		return hasUnresolvableVariables(cond.FalseResult, evalCtx)
	}

	vars := expr.Variables()
	if len(vars) == 0 {
		return false
	}
	for _, traversal := range vars {
		if traversal.IsRelative() {
			continue
		}
		if _, diags := traversal.TraverseAbs(evalCtx); diags.HasErrors() {
			return true
		}
	}
	return false
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
