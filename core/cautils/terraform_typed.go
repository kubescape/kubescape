package cautils

import (
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
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
	"kubernetes_service_account":      {"v1", "ServiceAccount"},
	"kubernetes_service_account_v1":   {"v1", "ServiceAccount"},
	"kubernetes_job":                  {"batch/v1", "Job"},
	"kubernetes_job_v1":               {"batch/v1", "Job"},
	"kubernetes_cron_job_v1":          {"batch/v1", "CronJob"},
	"kubernetes_ingress_v1":           {"networking.k8s.io/v1", "Ingress"},
	"kubernetes_role":                 {"rbac.authorization.k8s.io/v1", "Role"},
	"kubernetes_role_binding":         {"rbac.authorization.k8s.io/v1", "RoleBinding"},
	"kubernetes_cluster_role":         {"rbac.authorization.k8s.io/v1", "ClusterRole"},
	"kubernetes_cluster_role_binding": {"rbac.authorization.k8s.io/v1", "ClusterRoleBinding"},
}

// pluralOverrides maps an HCL block label to the K8s array field name it must
// become, for the cases where camelCasing the block name alone isn't right
// (block "container" -> field "containers"). Anything not listed here just
// gets its singular name camelCased.
var pluralOverrides = map[string]string{
	"container":          "containers",
	"init_container":     "initContainers",
	"volume":             "volumes",
	"volume_mount":       "volumeMounts",
	"env_from":           "envFrom",
	"port":               "ports",
	"toleration":         "tolerations",
	"host_alias":         "hostAliases",
	"rule":               "rules",
	"subject":            "subjects",
	"image_pull_secrets": "imagePullSecrets",
}

// repeatableBlocks lists HCL block labels that always encode as a JSON array,
// even when only one instance is present — Terraform lets you repeat a block,
// but the K8s field underneath (e.g. spec.containers) is always a list.
var repeatableBlocks = map[string]bool{
	"container": true, "init_container": true, "volume": true, "volume_mount": true,
	"env": true, "env_from": true, "port": true, "toleration": true,
	"host_alias": true, "rule": true, "subject": true, "image_pull_secrets": true,
}

func snakeToCamel(s string) string {
	parts := strings.Split(s, "_")
	for i := 1; i < len(parts); i++ {
		if parts[i] == "" {
			continue
		}
		parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
	}
	return strings.Join(parts, "")
}

func fieldNameFor(blockOrAttr string) string {
	if v, ok := pluralOverrides[blockOrAttr]; ok {
		return v
	}
	return snakeToCamel(blockOrAttr)
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
		out[fieldNameFor(name)] = ctyToGo(val)
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
		field := fieldNameFor(blockType)

		if len(blocks) > 1 || repeatableBlocks[blockType] {
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

		obj := hclBodyToMap(block.Body, evalCtx, &errs, block.Labels[0]+"."+block.Labels[1])
		obj["apiVersion"] = gvk.apiVersion
		obj["kind"] = gvk.kind

		meta, _ := obj["metadata"].(map[string]interface{})
		if meta == nil {
			meta = map[string]interface{}{}
		}
		if _, has := meta["name"]; !has {
			meta["name"] = block.Labels[1]
		}
		obj["metadata"] = meta

		manifests = append(manifests, obj)
	}
	return manifests, errs
}
