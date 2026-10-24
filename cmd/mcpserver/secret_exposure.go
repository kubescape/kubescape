package mcpserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/kubescape/kubescape/v4/core/pkg/pss"
	"github.com/mark3labs/mcp-go/mcp"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
)

var configMapGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "configmaps"}

var (
	sensitiveEnvKeyRegex = regexp.MustCompile(`(?i)(?:(?:^|_|-|\.)(?:PASSWORD|PASSWD|SECRET|TOKEN|API[._-]KEY|APIKEY|AUTH[._-]TOKEN|AUTH[._-]CONFIG|PRIVATE[._-]KEY|ACCESS[._-]KEY|CLIENT[._-]SECRET|DATABASE[._-]URL|DB[._-]PASS|DB[._-]PASSWORD|CREDENTIALS?|SSH[._-]AUTH[._-]SOCK|DOCKER[._-]AUTH[._-]CONFIG|JWT|BEARER)|PGPASS(?:WORD|WD)|[A-Za-z0-9_]+_PWD)(?:$|_|-|\.)`)
	privateKeyRegex      = regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----`)
	awsAccessKeyRegex    = regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)
	githubTokenRegex     = regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{22,})\b`)
	slackTokenRegex      = regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z]{10,}-[0-9A-Za-z]+\b`)
	jwtTokenRegex        = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]+\b`)
	uriCredentialsRegex  = regexp.MustCompile(`\b[a-zA-Z][a-zA-Z0-9+.-]*://((?:\{\{[^{}]*\}\}|[^:\s@/?#])+):((?:\{\{[^{}]*\}\}|[^\s/?#])+)@[^/?#,;|\s"'` + "`" + `]+`)
	uriStartRegex        = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://`)

	sensitiveConfigMapFileRegex = regexp.MustCompile(`(?i)(?:id_rsa|id_ecdsa|id_ed25519|credentials\.json|\.env|jwt\.key)$`)
	nonSecretKeySuffixRegex     = regexp.MustCompile(`(?i)(?:[._-](?:NAME|FILE|PATH|DIR|REF|TTL|EXPIRY|EXPIRES|TIMEOUT|LENGTH|LEN|URL[._-]PATH|ENABLED|TYPE|ENDPOINT|ISSUER|AUDIENCE|ALGORITHM|ALG|HEADER|SCOPES?)|(?:TOKEN|JWT|AUTH)[._-](?:URL|URI))$`)
	queryCredentialKeyRegex     = regexp.MustCompile(`(?i)^(?:pwd|sslpassword)$`)
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
	ResourceKind      string `json:"resourceKind"`
	ResourceName      string `json:"resourceName"`
	Namespace         string `json:"namespace"`
	Container         string `json:"container,omitempty"`
	Location          string `json:"location"`
	Key               string `json:"key"`
	RuleID            string `json:"ruleId"`
	Description       string `json:"description"`
	MaskedValue       string `json:"maskedValue"`
	Severity          string `json:"severity"`
	valueDigest       string `json:"-"`
	hasSecretOverride bool   `json:"-"`
}

// SecretExposureResult represents the structured result of secret exposure analysis.
type SecretExposureResult struct {
	Namespace                   string          `json:"namespace"`
	TotalWorkloads              int             `json:"totalWorkloads"`
	TotalConfigMaps             int             `json:"totalConfigMaps"`
	FindingsCount               int             `json:"findingsCount"`
	Findings                    []SecretFinding `json:"findings"`
	ConfigMapReferencesResolved bool            `json:"configMapReferencesResolved"`
	Warnings                    []string        `json:"warnings,omitempty"`
}

// cloneStructured lets a SecretExposureResult be shared between callers of one
// in-flight analysis: every caller gets its own slices.
func (r SecretExposureResult) cloneStructured() any {
	r.Findings = slices.Clone(r.Findings)
	r.Warnings = slices.Clone(r.Warnings)
	return r
}

var (
	pureDollarParenRef = regexp.MustCompile(`^\$\([A-Za-z_][A-Za-z0-9_.-]*\)$`)
	pureDollarBraceRef = regexp.MustCompile(`^\$\{[A-Za-z_][A-Za-z0-9_]*\}$`)
	pureTemplateRef    = regexp.MustCompile(`^\{\{-?\s*[.$][A-Za-z0-9_.$]*\s*-?\}\}$`)
)

// isCompletePlaceholderExpression checks if a string consists of exactly one complete dynamic placeholder expression.
func isCompletePlaceholderExpression(s string) bool {
	trimmed := strings.TrimSpace(s)
	if strings.Contains(trimmed, "\n") || strings.Contains(trimmed, "\r") {
		return false
	}
	return pureDollarParenRef.MatchString(trimmed) ||
		pureDollarBraceRef.MatchString(trimmed) ||
		pureTemplateRef.MatchString(trimmed)
}

func isSafeValue(val string) bool {
	trimmed := strings.TrimSpace(val)
	if _, ok := safePlaceholderValues[strings.ToLower(trimmed)]; ok {
		return true
	}
	// Complete dynamic runtime expressions or templates
	if isCompletePlaceholderExpression(trimmed) {
		return true
	}
	return false
}

func isCompoundValue(val string) bool {
	trimmed := strings.TrimSpace(val)
	// URIs and connection schemes
	if strings.Contains(trimmed, "://") {
		return true
	}
	// Authority / embedded credentials (e.g. user:pass@host)
	if strings.Contains(trimmed, "@") {
		return true
	}
	// Key-value or YAML assignments (e.g. "database_password: q7!", "user:pass")
	if strings.Contains(trimmed, ":") {
		return true
	}
	// Assignments with = (excluding trailing base64 padding)
	if strings.Contains(strings.TrimRight(trimmed, "="), "=") {
		return true
	}
	// Query parameters or semicolon-delimited connection strings with key-value assignments
	if strings.Contains(trimmed, "?") || strings.Contains(trimmed, "&") || strings.Contains(trimmed, ";") {
		return true
	}
	// Multi-word / whitespace indicates configuration text or compound structure
	if strings.Contains(trimmed, " ") || strings.Contains(trimmed, "\t") {
		return true
	}
	// Structured data
	if (strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}")) ||
		(strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]")) {
		return true
	}
	return false
}

func maskSecret(val string) string {
	if strings.Contains(val, "-----BEGIN") {
		return "-----BEGIN PRIVATE KEY...[REDACTED]-----"
	}
	trimmed := strings.TrimSpace(val)
	if strings.Contains(trimmed, "\n") || strings.Contains(trimmed, "\r") {
		return "******"
	}
	if isCompoundValue(trimmed) {
		return "******"
	}
	if len(trimmed) < 20 {
		return "******"
	}
	return trimmed[:4] + "****" + trimmed[len(trimmed)-4:]
}

func maskConfigFileSecret(key, val string) string {
	if sensitiveConfigMapFileRegex.MatchString(key) {
		if strings.Contains(val, "-----BEGIN") {
			return "-----BEGIN PRIVATE KEY...[REDACTED]-----"
		}
		return "******"
	}
	upperKey := strings.ToUpper(key)
	if strings.Contains(upperKey, "URL") || strings.Contains(upperKey, "URI") || strings.Contains(upperKey, "DSN") || strings.Contains(upperKey, "CONNECTION_STRING") || strings.Contains(upperKey, "CONFIG") || strings.Contains(upperKey, "CONF") {
		return "******"
	}
	return maskSecret(val)
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

func hasExposedQueryCredentials(queryStr string) bool {
	for _, segment := range strings.FieldsFunc(queryStr, func(r rune) bool {
		return r == '&' || r == ';' || r == '?' || r == '#'
	}) {
		rawItems := strings.Split(segment, ",")
		for i := 0; i < len(rawItems); i++ {
			item := rawItems[i]
			k, v, found := strings.Cut(item, "=")
			if !found {
				continue
			}
			if unescapedK, err := url.QueryUnescape(k); err == nil {
				k = unescapedK
			}
			isCredentialKey := queryCredentialKeyRegex.MatchString(k) ||
				(sensitiveEnvKeyRegex.MatchString(k) && !nonSecretKeySuffixRegex.MatchString(k))
			if isCredentialKey {
				for i+1 < len(rawItems) {
					v = v + "," + rawItems[i+1]
					i++
				}
			} else {
				for i+1 < len(rawItems) && !strings.Contains(rawItems[i+1], "=") {
					v = v + "," + rawItems[i+1]
					i++
				}
			}
			if unescapedV, err := url.QueryUnescape(v); err == nil {
				v = unescapedV
			}
			if awsAccessKeyRegex.MatchString(v) || githubTokenRegex.MatchString(v) || slackTokenRegex.MatchString(v) || jwtTokenRegex.MatchString(v) {
				return true
			}
			if isCredentialKey {
				if strings.TrimSpace(v) != "" && !isCompletePlaceholderExpression(v) {
					return true
				}
			}
		}
	}
	return false
}

func isURISchemeByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '+' || c == '.' || c == '-'
}

func hasExposedURICredentials(val string) (hasMatch bool, hasExposed bool, safeRanges [][2]int) {
	locs := uriCredentialsRegex.FindAllStringSubmatchIndex(val, -1)
	if len(locs) == 0 {
		return false, false, nil
	}
	hasMatch = true
	for _, loc := range locs {
		user := val[loc[2]:loc[3]]
		pass := val[loc[4]:loc[5]]

		isAuthExposed := !isCompletePlaceholderExpression(pass) ||
			awsAccessKeyRegex.MatchString(user) ||
			githubTokenRegex.MatchString(user) ||
			slackTokenRegex.MatchString(user) ||
			jwtTokenRegex.MatchString(user)

		pos := loc[1]
		for pos < len(val) {
			if strings.ContainsRune(" \t\r\n\"'`", rune(val[pos])) {
				break
			}
			if (val[pos] == ',' || val[pos] == ';' || val[pos] == '|') && uriStartRegex.MatchString(strings.TrimLeft(val[pos+1:], " \t\r\n")) {
				break
			}
			if !isURISchemeByte(val[pos-1]) && uriStartRegex.MatchString(val[pos:]) {
				break
			}
			pos++
		}

		queryExposed := hasExposedQueryCredentials(val[loc[5]+1 : pos])

		if isAuthExposed || queryExposed {
			hasExposed = true
		} else {
			safeRanges = append(safeRanges, [2]int{loc[0], pos})
		}
	}
	return hasMatch, hasExposed, safeRanges
}

func evaluateSecretString(key, val string) (matched bool, ruleID, desc, severity string) {
	for _, p := range highConfidenceValuePatterns {
		if p.ruleID == "URI_CREDENTIALS" {
			hasMatch, hasExposed, safeRanges := hasExposedURICredentials(val)
			if hasExposed {
				return true, p.ruleID, p.description, p.severity
			}
			if hasMatch {
				// URI credentials were present and all matched URIs are safe.
				// Exempt only the safe URI portions and evaluate remaining compound content.
				var b strings.Builder
				lastIdx := 0
				for _, r := range safeRanges {
					if r[0] > lastIdx {
						b.WriteString(val[lastIdx:r[0]])
					}
					if r[1] > lastIdx {
						lastIdx = r[1]
					}
				}
				if lastIdx < len(val) {
					b.WriteString(val[lastIdx:])
				}
				remaining := strings.Trim(b.String(), " \t\r\n,;|\"'`")

				if remaining == "" {
					return false, "", "", ""
				}
				return evaluateSecretString(key, remaining)
			}
			continue
		}
		if p.regex.MatchString(val) {
			return true, p.ruleID, p.description, p.severity
		}
	}

	if isSafeValue(val) {
		return false, "", "", ""
	}

	if sensitiveEnvKeyRegex.MatchString(key) && !nonSecretKeySuffixRegex.MatchString(key) {
		upperKey := strings.ToUpper(key)
		isPathKey := upperKey == "PWD" || strings.HasSuffix(upperKey, "_PWD") || upperKey == "GOOGLE_APPLICATION_CREDENTIALS"
		if isPathKey && strings.HasPrefix(strings.TrimSpace(val), "/") {
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

		// Both registered names run this handler and produce the same result
		// for the same arguments, so they share one key: overlapping calls
		// through either name join a single execution. filterKind is the
		// canonical kind, so spelling and case do not split the key.
		params := url.Values{
			"namespace":     {namespace},
			"resource_kind": {filterKind},
			"resource_name": {resourceName},
		}
		return ksServer.doAnalysis(ctx, "secret_exposure", params, func(ctx context.Context) *mcp.CallToolResult {
			k8sClient, err := ksServer.getK8sClient()
			if err != nil {
				return mcpToolError(ErrCodeK8sClientError, fmt.Sprintf("failed to get k8s client: %v", err), nil)
			}
			res, err := executeSecretExposureScan(ctx, k8sClient.DynamicClient, namespace, filterKind, resourceName)
			if err != nil {
				return mcpToolError(classifyScanError(err), err.Error(), nil)
			}
			return res
		}), nil
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
	var warnings []string
	configMapRefsResolved := true
	if err != nil {
		cmList = nil
		configMapRefsResolved = false
		if !configMapsInScope {
			warnings = append(warnings, fmt.Sprintf("failed to list ConfigMaps (%s): workload envFrom and configMapKeyRef references could not be resolved", classifyScanErrorMessage(classifyScanError(err), "ConfigMap", err)))
		} else {
			warnings = append(warnings, fmt.Sprintf("failed to list ConfigMaps: %v", err))
		}
	}

	configMapsByName := make(map[string]*unstructured.Unstructured)
	if cmList != nil {
		for i := range cmList.Items {
			cm := &cmList.Items[i]
			configMapsByName[cm.GetName()] = cm
		}
	}

	// 1. Scan ConfigMaps
	// Populate cmFindings for all ConfigMaps in the namespace so workload reference
	// checks (envFrom / configMapKeyRef) can always resolve them, regardless of filters.
	cmFindings := make(map[string][]SecretFinding)
	var analyzedConfigMaps []*unstructured.Unstructured
	if cmList != nil {
		for i := range cmList.Items {
			cm := &cmList.Items[i]
			findings := scanConfigMap(cm, namespace)
			if len(findings) > 0 {
				cmFindings[cm.GetName()] = findings
			}
			if (filterKind == "" || filterKind == "ConfigMap") && (resourceName == "" || cm.GetName() == resourceName) {
				analyzedConfigMaps = append(analyzedConfigMaps, cm)
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

		for i := range rawWorkloads {
			w := &rawWorkloads[i]
			if resourceName != "" && w.GetName() != resourceName {
				continue
			}
			analyzedWorkloads = append(analyzedWorkloads, *w)
			findings := scanWorkload(w, namespace, configMapsByName)
			workloadFindings = append(workloadFindings, findings...)
		}

		workloadFindings = deduplicateWorkloadFindings(workloadFindings, rawWorkloads)
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

	allFindings := make([]SecretFinding, 0, len(workloadFindings))
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
		Namespace:                   namespace,
		TotalWorkloads:              len(analyzedWorkloads),
		TotalConfigMaps:             len(analyzedConfigMaps),
		FindingsCount:               len(allFindings),
		Findings:                    allFindings,
		ConfigMapReferencesResolved: configMapRefsResolved,
		Warnings:                    warnings,
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

	dataKeys := make([]string, 0, len(data))
	for k := range data {
		dataKeys = append(dataKeys, k)
	}
	sort.Strings(dataKeys)

	for _, k := range dataKeys {
		v := data[k]
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
				MaskedValue:  maskConfigFileSecret(k, v),
				Severity:     severity,
				valueDigest:  computeValueDigest(v),
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
				MaskedValue:  maskConfigFileSecret(k, v),
				Severity:     "High",
				valueDigest:  computeValueDigest(v),
			})
		}
	}

	binKeys := make([]string, 0, len(binaryData))
	for k := range binaryData {
		binKeys = append(binKeys, k)
	}
	sort.Strings(binKeys)

	for _, k := range binKeys {
		v := binaryData[k]
		// The API represents binaryData bytes as base64 strings. Inspect
		// the decoded content just as we inspect data, while always fully
		// masking binary findings (including the encoded representation).
		// Key-based findings retain their existing handling below.
		if decoded, err := base64.StdEncoding.DecodeString(v); err == nil {
			if matched, ruleID, desc, severity := evaluateSecretString("", string(decoded)); matched {
				findings = append(findings, SecretFinding{
					ResourceKind: "ConfigMap",
					ResourceName: cmName,
					Namespace:    namespace,
					Location:     fmt.Sprintf("binaryData.%s", k),
					Key:          k,
					RuleID:       ruleID,
					Description:  desc,
					MaskedValue:  "******",
					Severity:     severity,
					valueDigest:  computeValueDigest(string(decoded)),
				})
				continue
			}
		}
		if sensitiveConfigMapFileRegex.MatchString(k) || (sensitiveEnvKeyRegex.MatchString(k) && !nonSecretKeySuffixRegex.MatchString(k)) {
			findings = append(findings, SecretFinding{
				ResourceKind: "ConfigMap",
				ResourceName: cmName,
				Namespace:    namespace,
				Location:     fmt.Sprintf("binaryData.%s", k),
				Key:          k,
				RuleID:       "CONFIGMAP_SENSITIVE_KEY",
				Description:  "ConfigMap binaryData key indicates credential or sensitive secret file",
				MaskedValue:  "******",
				Severity:     "High",
				valueDigest:  computeValueDigest(v),
			})
		}
	}

	return findings
}

func scanWorkload(
	w *unstructured.Unstructured,
	namespace string,
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
		explicitEnvNames := make(map[string]struct{}, len(envList))
		for _, env := range envList {
			if env.Name != "" {
				explicitEnvNames[env.Name] = struct{}{}
			}
		}

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
						MaskedValue:  maskConfigFileSecret(env.Name, env.Value),
						Severity:     severity,
						valueDigest:  computeValueDigest(env.Value),
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
							MaskedValue:  maskConfigFileSecret(cmRef.Key, val),
							Severity:     severity,
							valueDigest:  computeValueDigest(val),
						})
					}
				}
			}
		}

		// 2. Scan envFrom pointing to exposed ConfigMap
		for idx, envFrom := range envFromList {
			if envFrom.ConfigMapRef != nil {
				refName := envFrom.ConfigMapRef.Name
				prefix := envFrom.Prefix

				// Later envFrom sources and explicit env entries take precedence over earlier envFrom sources
				overriddenKeys := make(map[string]struct{}, len(explicitEnvNames))
				for k := range explicitEnvNames {
					overriddenKeys[k] = struct{}{}
				}
				var laterSecretRefs []string
				seenLaterSecrets := make(map[string]struct{})
				for j := idx + 1; j < len(envFromList); j++ {
					laterSource := envFromList[j]
					if laterSource.SecretRef != nil {
						secName := laterSource.SecretRef.Name
						if secName != "" {
							if _, seen := seenLaterSecrets[secName]; !seen {
								seenLaterSecrets[secName] = struct{}{}
								laterSecretRefs = append(laterSecretRefs, secName)
							}
						}
						continue
					}
					if laterSource.ConfigMapRef == nil {
						continue
					}
					laterRef := laterSource.ConfigMapRef.Name
					laterPrefix := laterSource.Prefix
					if laterCM, exists := configMapsByName[laterRef]; exists {
						data, _, _ := unstructured.NestedStringMap(laterCM.Object, "data")
						for k := range data {
							overriddenKeys[laterPrefix+k] = struct{}{}
						}
					}
				}

				var hasExposed bool
				var exposedMaskedValue string
				var exposedValueDigest string
				exposedSeverity := "High"

				if cm, exists := configMapsByName[refName]; exists {
					data, _, _ := unstructured.NestedStringMap(cm.Object, "data")
					dataKeys := make([]string, 0, len(data))
					for k := range data {
						dataKeys = append(dataKeys, k)
					}
					sort.Strings(dataKeys)

					type envFromExposedEntry struct {
						effectiveKey string
						maskedValue  string
						rawValue     string
						severity     string
					}
					var exposedEntries []envFromExposedEntry

					for _, k := range dataKeys {
						effectiveKey := prefix + k
						if _, overridden := overriddenKeys[effectiveKey]; overridden {
							continue
						}
						v := data[k]
						if matched, _, _, sev := evaluateSecretString(effectiveKey, v); matched {
							exposedEntries = append(exposedEntries, envFromExposedEntry{
								effectiveKey: effectiveKey,
								maskedValue:  maskConfigFileSecret(effectiveKey, v),
								rawValue:     v,
								severity:     sev,
							})
							continue
						}
						if matched, _, _, sev := evaluateSecretString(k, v); matched {
							exposedEntries = append(exposedEntries, envFromExposedEntry{
								effectiveKey: effectiveKey,
								maskedValue:  maskConfigFileSecret(k, v),
								rawValue:     v,
								severity:     sev,
							})
							continue
						}
						if sensitiveConfigMapFileRegex.MatchString(effectiveKey) || sensitiveConfigMapFileRegex.MatchString(k) {
							exposedEntries = append(exposedEntries, envFromExposedEntry{
								effectiveKey: effectiveKey,
								maskedValue:  maskConfigFileSecret(k, v),
								rawValue:     v,
								severity:     "High",
							})
							continue
						}
					}
					if len(exposedEntries) > 0 {
						hasExposed = true
						exposedMaskedValue = exposedEntries[0].maskedValue
						for _, entry := range exposedEntries {
							if entry.severity == "Critical" {
								exposedSeverity = "Critical"
								break
							}
						}
						h := sha256.New()
						for _, entry := range exposedEntries {
							h.Write([]byte(entry.effectiveKey))
							h.Write([]byte("="))
							h.Write([]byte(computeValueDigest(entry.rawValue)))
							h.Write([]byte("\n"))
						}
						exposedValueDigest = hex.EncodeToString(h.Sum(nil))
					}
				}

				if hasExposed {
					desc := fmt.Sprintf("Container imports environment variables from ConfigMap %q which contains exposed credentials", refName)
					if len(laterSecretRefs) > 0 {
						desc += fmt.Sprintf("; later Secret sources %v may override some imported keys", laterSecretRefs)
					}
					findings = append(findings, SecretFinding{
						ResourceKind:      kind,
						ResourceName:      name,
						Namespace:         namespace,
						Container:         cName,
						Location:          fmt.Sprintf("envFrom.configMapRef.%s", refName),
						Key:               refName,
						RuleID:            "ENVFROM_EXPOSED_CONFIGMAP",
						Description:       desc,
						MaskedValue:       exposedMaskedValue,
						Severity:          exposedSeverity,
						valueDigest:       exposedValueDigest,
						hasSecretOverride: len(laterSecretRefs) > 0,
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

func deduplicateWorkloadFindings(findings []SecretFinding, workloads []unstructured.Unstructured) []SecretFinding {
	if len(findings) == 0 {
		return findings
	}

	workloadByKindName := make(map[string]*unstructured.Unstructured, len(workloads))
	workloadByUID := make(map[types.UID]*unstructured.Unstructured, len(workloads))

	for i := range workloads {
		w := &workloads[i]
		key := makeWorkloadKey(w.GetKind(), w.GetName())
		workloadByKindName[key] = w
		if uid := w.GetUID(); uid != "" {
			workloadByUID[uid] = w
		}
	}

	workloadFindingKeys := make(map[string]map[string]bool)
	for _, f := range findings {
		wKey := makeWorkloadKey(f.ResourceKind, f.ResourceName)
		if workloadFindingKeys[wKey] == nil {
			workloadFindingKeys[wKey] = make(map[string]bool)
		}
		fSig := makeFindingSignature(f)
		workloadFindingKeys[wKey][fSig] = true
	}

	var deduped []SecretFinding
	for _, f := range findings {
		wKey := makeWorkloadKey(f.ResourceKind, f.ResourceName)
		w := workloadByKindName[wKey]
		if w == nil {
			deduped = append(deduped, f)
			continue
		}

		ancestors := getEvaluatedAncestors(w, workloadByKindName, workloadByUID)
		isDuplicate := false
		fSig := makeFindingSignature(f)
		for _, ancestor := range ancestors {
			ancestorKey := makeWorkloadKey(ancestor.GetKind(), ancestor.GetName())
			if workloadFindingKeys[ancestorKey][fSig] {
				isDuplicate = true
				break
			}
		}

		if !isDuplicate {
			deduped = append(deduped, f)
		}
	}

	return deduped
}

func makeWorkloadKey(kind, name string) string {
	return fmt.Sprintf("%s/%s", strings.ToLower(kind), strings.ToLower(name))
}

// computeValueDigest calculates a SHA-256 hex digest of the raw credential value for internal deduplication.
func computeValueDigest(val string) string {
	sum := sha256.Sum256([]byte(val))
	return hex.EncodeToString(sum[:])
}

func makeFindingSignature(f SecretFinding) string {
	hasOverride := f.hasSecretOverride || strings.Contains(f.Description, "later Secret sources")
	return fmt.Sprintf("%s|%s|%s|%s|override=%t", f.Container, f.Location, f.Key, f.valueDigest, hasOverride)
}

func getEvaluatedAncestors(
	w *unstructured.Unstructured,
	byKindName map[string]*unstructured.Unstructured,
	byUID map[types.UID]*unstructured.Unstructured,
) []*unstructured.Unstructured {
	var ancestors []*unstructured.Unstructured
	visited := make(map[string]bool)
	curr := w

	for {
		owner := getWorkloadControllerRef(curr)
		if owner == nil {
			break
		}

		var parent *unstructured.Unstructured
		if owner.UID != "" {
			if p, ok := byUID[owner.UID]; ok && strings.EqualFold(p.GetKind(), owner.Kind) {
				parent = p
			}
		}
		if parent == nil {
			parentKey := makeWorkloadKey(owner.Kind, owner.Name)
			if p, ok := byKindName[parentKey]; ok {
				if owner.UID == "" || p.GetUID() == "" || owner.UID == p.GetUID() {
					parent = p
				}
			}
		}
		if parent == nil {
			break
		}

		parentKey := makeWorkloadKey(parent.GetKind(), parent.GetName())
		if visited[parentKey] {
			break
		}
		visited[parentKey] = true
		ancestors = append(ancestors, parent)
		curr = parent
	}

	return ancestors
}

func getWorkloadControllerRef(obj *unstructured.Unstructured) *metav1.OwnerReference {
	for _, ref := range obj.GetOwnerReferences() {
		if ref.Controller != nil && *ref.Controller {
			r := ref
			return &r
		}
	}
	refs := obj.GetOwnerReferences()
	if len(refs) > 0 {
		r := refs[0]
		return &r
	}
	return nil
}
