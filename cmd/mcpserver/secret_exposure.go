package mcpserver

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/kubescape/kubescape/v4/core/pkg/pss"
	"github.com/mark3labs/mcp-go/mcp"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var configMapGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "configmaps"}

var (
	sensitiveEnvKeyRegex = regexp.MustCompile(`(?i)(?:(?:^|_|-)(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|AUTH_TOKEN|AUTH_CONFIG|PRIVATE_KEY|ACCESS_KEY|CLIENT_SECRET|DATABASE_URL|DB_PASS|DB_PASSWORD|CREDENTIALS?|SSH_AUTH_SOCK|DOCKER_AUTH_CONFIG)|PGPASS(?:WORD|WD)|[A-Za-z0-9_]+_PWD)(?:$|_|-)`)
	privateKeyRegex      = regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----`)
	awsAccessKeyRegex    = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	githubTokenRegex     = regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9_]{36,}\b`)
	slackTokenRegex      = regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z]{10,}-[0-9A-Za-z]+\b`)
	jwtTokenRegex        = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]+\b`)
	uriCredentialsRegex  = regexp.MustCompile(`\b[a-zA-Z][a-zA-Z0-9+.-]*://[^:\s@/?#]+:[^\s/?#]+@[^/\s]+`)

	sensitiveConfigMapFileRegex = regexp.MustCompile(`(?i)(?:id_rsa|id_ecdsa|id_ed25519|credentials\.json|\.env|jwt\.key)$`)
	nonSecretKeySuffixRegex     = regexp.MustCompile(`(?i)[_-](?:NAME|FILE|PATH|DIR|REF|TTL|EXPIRY|EXPIRES|TIMEOUT|LENGTH|LEN|URL_PATH|ENABLED|TYPE)$`)
)

var safePlaceholderValues = map[string]struct{}{
	"":            {},
	"true":        {},
	"false":       {},
	"0":           {},
	"1":           {},
	"none":        {},
	"null":        {},
	"disabled":    {},
	"enabled":     {},
	"test":        {},
	"dummy":       {},
	"placeholder": {},
	"changeme":    {},
	"change-me":   {},
	"to-be-set":   {},
	"unset":       {},
	"sample":      {},
	"example":     {},
}

var supportedSecretExposureKinds = []string{
	"Deployment",
	"DaemonSet",
	"StatefulSet",
	"ReplicaSet",
	"Job",
	"CronJob",
	"Pod",
	"ConfigMap",
}

// SecretFinding represents a detected secret exposure in workload or configuration data.
type SecretFinding struct {
	ResourceKind string `json:"resourceKind"`
	ResourceName string `json:"resourceName"`
	Namespace    string `json:"namespace"`
	Container    string `json:"container,omitempty"`
	Location     string `json:"location"`
	Key          string `json:"key"`
	RuleID       string `json:"ruleId"`
	Description  string `json:"description"`
	MaskedValue  string `json:"maskedValue"`
	Severity     string `json:"severity"`
}

// SecretExposureResult represents the structured result of secret exposure analysis.
type SecretExposureResult struct {
	Namespace       string          `json:"namespace"`
	TotalWorkloads  int             `json:"totalWorkloads"`
	TotalConfigMaps int             `json:"totalConfigMaps"`
	FindingsCount   int             `json:"findingsCount"`
	Findings        []SecretFinding `json:"findings"`
}

func isSafeValue(val string) bool {
	trimmed := strings.TrimSpace(val)
	if _, ok := safePlaceholderValues[strings.ToLower(trimmed)]; ok {
		return true
	}
	// Dynamic runtime expressions or templates
	if strings.HasPrefix(trimmed, "$(") || strings.HasPrefix(trimmed, "${") || strings.Contains(trimmed, "{{") {
		return true
	}
	return false
}

func maskSecret(val string) string {
	if strings.Contains(val, "-----BEGIN") {
		return "-----BEGIN PRIVATE KEY...[REDACTED]-----"
	}
	trimmed := strings.TrimSpace(val)
	if len(trimmed) < 20 {
		return "******"
	}
	return trimmed[:4] + "****" + trimmed[len(trimmed)-4:]
}

type valuePattern struct {
	ruleID      string
	regex       *regexp.Regexp
	description string
	severity    string
}

var highConfidenceValuePatterns = []valuePattern{
	{
		ruleID:      "PRIVATE_KEY_HEADER",
		regex:       privateKeyRegex,
		description: "Private key detected in configuration data",
		severity:    "Critical",
	},
	{
		ruleID:      "GITHUB_TOKEN",
		regex:       githubTokenRegex,
		description: "GitHub personal access token detected in configuration data",
		severity:    "Critical",
	},
	{
		ruleID:      "AWS_ACCESS_KEY_ID",
		regex:       awsAccessKeyRegex,
		description: "AWS Access Key ID detected in configuration data",
		severity:    "High",
	},
	{
		ruleID:      "SLACK_TOKEN",
		regex:       slackTokenRegex,
		description: "Slack API token detected in configuration data",
		severity:    "High",
	},
	{
		ruleID:      "JWT_TOKEN",
		regex:       jwtTokenRegex,
		description: "JSON Web Token (JWT) detected in configuration data",
		severity:    "High",
	},
	{
		ruleID:      "URI_CREDENTIALS",
		regex:       uriCredentialsRegex,
		description: "Connection URI with embedded credentials detected in configuration data",
		severity:    "High",
	},
}

func evaluateSecretString(key, val string) (matched bool, ruleID, desc, severity string) {
	if isSafeValue(val) {
		return false, "", "", ""
	}

	for _, p := range highConfidenceValuePatterns {
		if p.regex.MatchString(val) {
			return true, p.ruleID, p.description, p.severity
		}
	}

	if sensitiveEnvKeyRegex.MatchString(key) && !nonSecretKeySuffixRegex.MatchString(key) {
		if strings.HasPrefix(strings.TrimSpace(val), "/") {
			return false, "", "", ""
		}
		return true, "ENV_CREDENTIAL_KEYWORD", "Plain-text credential configured directly in configuration data", "High"
	}

	return false, "", "", ""
}

func canonicalSecretKind(kind string) (string, bool) {
	for _, sk := range supportedSecretExposureKinds {
		if strings.EqualFold(kind, sk) {
			return sk, true
		}
	}
	return "", false
}

// createSecretExposureTools registers the detect_secret_exposure tool.
func createSecretExposureTools(ksServer *KubescapeMcpserver) {
	toolHandler := func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]any)
		if !ok || args == nil {
			args = map[string]any{}
		}

		namespace, toolErr := mcpRequiredStringArg(args, "namespace")
		if toolErr != nil {
			return toolErr, nil
		}

		resourceKindArg, toolErr := mcpStringArg(args, "resource_kind")
		if toolErr != nil {
			return toolErr, nil
		}
		var filterKind string
		if resourceKindArg != "" {
			canonical, ok := canonicalSecretKind(resourceKindArg)
			if !ok {
				return mcpToolError(ErrCodeInvalidArgument,
					fmt.Sprintf("invalid resource_kind %q; must be one of: %s", resourceKindArg, strings.Join(supportedSecretExposureKinds, ", ")),
					map[string]any{"argument": "resource_kind", "supported_values": supportedSecretExposureKinds}), nil
			}
			filterKind = canonical
		}

		resourceName, toolErr := mcpStringArg(args, "resource_name")
		if toolErr != nil {
			return toolErr, nil
		}

		k8sClient, err := ksServer.getK8sClient()
		if err != nil {
			return mcpToolError(ErrCodeK8sClientError, fmt.Sprintf("failed to get k8s client: %v", err), nil), nil
		}
		dynClient := k8sClient.DynamicClient

		return executeSecretExposureScan(ctx, dynClient, namespace, filterKind, resourceName)
	}

	tool := mcp.NewTool(
		"detect_secret_exposure",
		mcp.WithDescription("Detect potential secret exposure in Kubernetes workloads and ConfigMaps within a namespace. Analyzes container env configurations, envFrom references, and ConfigMap data for exposed plain-text credentials and high-confidence secret patterns."),
		mcp.WithString("namespace", mcp.Required(), mcp.Description("Namespace to analyze")),
		mcp.WithString("resource_kind", mcp.Description("Filter by resource kind: Deployment, DaemonSet, StatefulSet, ReplicaSet, Job, CronJob, Pod, ConfigMap (optional)")),
		mcp.WithString("resource_name", mcp.Description("Filter by resource name (optional)")),
	)
	ksServer.s.AddTool(tool, toolHandler)

	aliasTool := mcp.NewTool(
		"analyze_secret_exposure",
		mcp.WithDescription("Analyze potential secret exposure in Kubernetes workloads and ConfigMaps within a namespace (alias for detect_secret_exposure)."),
		mcp.WithString("namespace", mcp.Required(), mcp.Description("Namespace to analyze")),
		mcp.WithString("resource_kind", mcp.Description("Filter by resource kind: Deployment, DaemonSet, StatefulSet, ReplicaSet, Job, CronJob, Pod, ConfigMap (optional)")),
		mcp.WithString("resource_name", mcp.Description("Filter by resource name (optional)")),
	)
	ksServer.s.AddTool(aliasTool, toolHandler)
}

func executeSecretExposureScan(
	ctx context.Context,
	dynClient dynamic.Interface,
	namespace string,
	filterKind string,
	resourceName string,
) (*mcp.CallToolResult, error) {
	// Always list ConfigMaps so envFrom / configMapKeyRef references from workloads can be inspected
	cmList, err := dynClient.Resource(configMapGVR).Namespace(namespace).List(ctx, metav1.ListOptions{})
	configMapsInScope := filterKind == "" || filterKind == "ConfigMap"
	if err != nil && !apierrors.IsNotFound(err) && (configMapsInScope || !apierrors.IsForbidden(err)) {
		return mcpToolError(classifyScanError(err), fmt.Sprintf("failed to list ConfigMaps: %v", err), map[string]any{"resource_type": "ConfigMap", "namespace": namespace}), nil
	}
	if err != nil {
		cmList = nil
	}

	configMapsByName := make(map[string]*unstructured.Unstructured)
	if cmList != nil {
		for i := range cmList.Items {
			cm := &cmList.Items[i]
			configMapsByName[cm.GetName()] = cm
		}
	}

	// 1. Scan ConfigMaps
	cmFindings := make(map[string][]SecretFinding)
	var analyzedConfigMaps []*unstructured.Unstructured
	if filterKind == "" || filterKind == "ConfigMap" {
		for _, cm := range configMapsByName {
			if resourceName != "" && cm.GetName() != resourceName {
				continue
			}
			analyzedConfigMaps = append(analyzedConfigMaps, cm)
			findings := scanConfigMap(cm, namespace)
			if len(findings) > 0 {
				cmFindings[cm.GetName()] = findings
			}
		}
	} else {
		// Even if not filtering on ConfigMap, scan namespace ConfigMaps for reference resolution
		for _, cm := range configMapsByName {
			findings := scanConfigMap(cm, namespace)
			if len(findings) > 0 {
				cmFindings[cm.GetName()] = findings
			}
		}
	}

	// 2. Scan Workloads
	var workloadTargets []pssWorkloadTarget
	if filterKind == "" {
		workloadTargets = pssWorkloadTargets
	} else if filterKind != "ConfigMap" {
		for _, target := range pssWorkloadTargets {
			if target.kind == filterKind {
				workloadTargets = []pssWorkloadTarget{target}
				break
			}
		}
	}

	var analyzedWorkloads []unstructured.Unstructured
	var workloadFindings []SecretFinding

	if len(workloadTargets) > 0 {
		rawWorkloads, toolErr := listPSSWorkloads(ctx, dynClient, namespace, workloadTargets)
		if toolErr != nil {
			return toolErr, nil
		}
		deduped := deduplicateWorkloads(rawWorkloads)

		for _, w := range deduped {
			if resourceName != "" && w.GetName() != resourceName {
				continue
			}
			analyzedWorkloads = append(analyzedWorkloads, w)
			findings := scanWorkload(&w, namespace, cmFindings, configMapsByName)
			workloadFindings = append(workloadFindings, findings...)
		}
	}

	// Check if a specific resource was requested but not found
	if resourceName != "" {
		found := len(analyzedWorkloads) > 0 || len(analyzedConfigMaps) > 0
		if !found {
			details := map[string]any{"argument": "resource_name", "namespace": namespace, "resource_name": resourceName}
			if filterKind != "" {
				details["resource_kind"] = filterKind
			}
			return mcpToolError(ErrCodeResourceNotFound,
				fmt.Sprintf("resource %q not found in namespace %q", resourceName, namespace),
				details), nil
		}
	}

	var allFindings []SecretFinding
	// Include ConfigMap findings if ConfigMaps were part of the analyzed scope
	if filterKind == "" || filterKind == "ConfigMap" {
		for _, cm := range analyzedConfigMaps {
			if findings, ok := cmFindings[cm.GetName()]; ok {
				allFindings = append(allFindings, findings...)
			}
		}
	}
	allFindings = append(allFindings, workloadFindings...)

	result := SecretExposureResult{
		Namespace:       namespace,
		TotalWorkloads:  len(analyzedWorkloads),
		TotalConfigMaps: len(analyzedConfigMaps),
		FindingsCount:   len(allFindings),
		Findings:        allFindings,
	}

	resBytes, err := jsonMarshal(result)
	if err != nil {
		return mcpToolError(ErrCodeMarshalError, fmt.Sprintf("failed to marshal result: %v", err), nil), nil
	}

	return mcp.NewToolResultStructured(result, string(resBytes)), nil
}

func scanConfigMap(cm *unstructured.Unstructured, namespace string) []SecretFinding {
	var findings []SecretFinding
	cmName := cm.GetName()

	data, _, _ := unstructured.NestedStringMap(cm.Object, "data")
	binaryData, _, _ := unstructured.NestedStringMap(cm.Object, "binaryData")

	for k, v := range data {
		matched, ruleID, desc, severity := evaluateSecretString(k, v)
		if matched {
			findings = append(findings, SecretFinding{
				ResourceKind: "ConfigMap",
				ResourceName: cmName,
				Namespace:    namespace,
				Location:     fmt.Sprintf("data.%s", k),
				Key:          k,
				RuleID:       ruleID,
				Description:  desc,
				MaskedValue:  maskSecret(v),
				Severity:     severity,
			})
			continue
		}

		if sensitiveConfigMapFileRegex.MatchString(k) {
			findings = append(findings, SecretFinding{
				ResourceKind: "ConfigMap",
				ResourceName: cmName,
				Namespace:    namespace,
				Location:     fmt.Sprintf("data.%s", k),
				Key:          k,
				RuleID:       "CONFIGMAP_SENSITIVE_KEY",
				Description:  "ConfigMap data key indicates credential or sensitive secret file",
				MaskedValue:  maskSecret(v),
				Severity:     "High",
			})
		}
	}

	for k, v := range binaryData {
		if sensitiveConfigMapFileRegex.MatchString(k) || (sensitiveEnvKeyRegex.MatchString(k) && !nonSecretKeySuffixRegex.MatchString(k)) {
			findings = append(findings, SecretFinding{
				ResourceKind: "ConfigMap",
				ResourceName: cmName,
				Namespace:    namespace,
				Location:     fmt.Sprintf("binaryData.%s", k),
				Key:          k,
				RuleID:       "CONFIGMAP_SENSITIVE_KEY",
				Description:  "ConfigMap binaryData key indicates credential or sensitive secret file",
				MaskedValue:  maskSecret(v),
				Severity:     "High",
			})
		}
	}

	return findings
}

func scanWorkload(
	w *unstructured.Unstructured,
	namespace string,
	cmFindings map[string][]SecretFinding,
	configMapsByName map[string]*unstructured.Unstructured,
) []SecretFinding {
	var findings []SecretFinding
	kind := w.GetKind()
	name := w.GetName()

	podSpec, err := pss.ExtractPodSpec(kind, w.Object)
	if err != nil {
		return nil
	}

	checkContainerEnv := func(cName string, envList []corev1.EnvVar, envFromList []corev1.EnvFromSource) {
		// 1. Scan plain env
		for _, env := range envList {
			if env.Value != "" {
				matched, ruleID, desc, severity := evaluateSecretString(env.Name, env.Value)
				if matched {
					findings = append(findings, SecretFinding{
						ResourceKind: kind,
						ResourceName: name,
						Namespace:    namespace,
						Container:    cName,
						Location:     fmt.Sprintf("env.%s", env.Name),
						Key:          env.Name,
						RuleID:       ruleID,
						Description:  desc,
						MaskedValue:  maskSecret(env.Value),
						Severity:     severity,
					})
				}
			}

			// Check configMapKeyRef pointing to sensitive ConfigMap key
			if env.ValueFrom != nil && env.ValueFrom.ConfigMapKeyRef != nil {
				cmRef := env.ValueFrom.ConfigMapKeyRef
				if cm, exists := configMapsByName[cmRef.Name]; exists {
					data, _, _ := unstructured.NestedStringMap(cm.Object, "data")
					val := data[cmRef.Key]
					envMatched, envRuleID, envDesc, envSeverity := evaluateSecretString(env.Name, val)
					keyMatched, keyRuleID, keyDesc, keySeverity := evaluateSecretString(cmRef.Key, val)
					matched := envMatched || keyMatched
					ruleID, desc, severity := envRuleID, envDesc, envSeverity
					if !envMatched {
						ruleID, desc, severity = keyRuleID, keyDesc, keySeverity
					}
					if matched || sensitiveConfigMapFileRegex.MatchString(cmRef.Key) {
						if !matched {
							ruleID = "CONFIGMAP_KEY_REF_CREDENTIAL"
							desc = fmt.Sprintf("Workload references sensitive key %q from ConfigMap %q", cmRef.Key, cmRef.Name)
							severity = "High"
						}
						findings = append(findings, SecretFinding{
							ResourceKind: kind,
							ResourceName: name,
							Namespace:    namespace,
							Container:    cName,
							Location:     fmt.Sprintf("env.%s.valueFrom.configMapKeyRef(%s.%s)", env.Name, cmRef.Name, cmRef.Key),
							Key:          env.Name,
							RuleID:       ruleID,
							Description:  desc,
							MaskedValue:  maskSecret(val),
							Severity:     severity,
						})
					}
				}
			}
		}

		// 2. Scan envFrom pointing to exposed ConfigMap
		for _, envFrom := range envFromList {
			if envFrom.ConfigMapRef != nil {
				refName := envFrom.ConfigMapRef.Name
				var dataFindings []SecretFinding
				for _, f := range cmFindings[refName] {
					if strings.HasPrefix(f.Location, "data.") {
						dataFindings = append(dataFindings, f)
					}
				}
				if len(dataFindings) > 0 {
					cmF := dataFindings
					findings = append(findings, SecretFinding{
						ResourceKind: kind,
						ResourceName: name,
						Namespace:    namespace,
						Container:    cName,
						Location:     fmt.Sprintf("envFrom.configMapRef.%s", refName),
						Key:          refName,
						RuleID:       "ENVFROM_EXPOSED_CONFIGMAP",
						Description:  fmt.Sprintf("Container imports environment variables from ConfigMap %q which contains exposed credentials", refName),
						MaskedValue:  cmF[0].MaskedValue,
						Severity:     "High",
					})
				}
			}
		}
	}

	for _, c := range podSpec.Containers {
		checkContainerEnv(c.Name, c.Env, c.EnvFrom)
	}
	for _, c := range podSpec.InitContainers {
		checkContainerEnv(c.Name, c.Env, c.EnvFrom)
	}
	for _, c := range podSpec.EphemeralContainers {
		checkContainerEnv(c.Name, c.Env, c.EnvFrom)
	}

	return findings
}
