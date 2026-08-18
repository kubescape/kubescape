package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	spdxv1beta1 "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	"github.com/kubescape/kubescape/v3/core/pkg/fixhandler"
	"golang.org/x/sync/semaphore"
	"golang.org/x/sync/singleflight"
)

// newKsClient creates the Kubescape storage client. It is a package-level
// var so tests can override it to simulate initialization failures without a
// real connection attempt, while production always goes through this same
// value instead of a per-call fallback.
var newKsClient = func() (spdxv1beta1.SpdxV1beta1Interface, error) {
	return CreateKsObjectConnection("default", 10*time.Second)
}

var loadK8sConfig = k8sinterface.LoadK8sConfig

var setConnectedToCluster = k8sinterface.SetConnectedToCluster

var newK8sClient = k8sinterface.NewKubernetesApi

// jsonMarshal is a package-level var so tests can inject marshal failures.
var jsonMarshal = json.Marshal

type scanCtxState struct {
	ctx    context.Context
	cancel context.CancelFunc
	count  int
}

type KubescapeMcpserver struct {
	s          *server.MCPServer
	ksClientMu sync.Mutex
	ksClient   spdxv1beta1.SpdxV1beta1Interface
	// ksClientInit overrides newKsClient for this server instance; used by
	// tests. Nil means use newKsClient.
	ksClientInit func() (spdxv1beta1.SpdxV1beta1Interface, error)
	k8sClientMu  sync.Mutex
	k8sClient    *k8sinterface.KubernetesApi
	policyGetter *getter.DownloadReleasedPolicy
	scanSemMu    sync.Mutex
	scanSem      *semaphore.Weighted
	scanGroup    singleflight.Group
	scanCtxMu    sync.Mutex
	scanCtxs     map[string]*scanCtxState
}

func (ksServer *KubescapeMcpserver) getScanSem() *semaphore.Weighted {
	ksServer.scanSemMu.Lock()
	defer ksServer.scanSemMu.Unlock()
	if ksServer.scanSem == nil {
		ksServer.scanSem = semaphore.NewWeighted(2)
	}
	return ksServer.scanSem
}

// doScanChan executes a singleflight scan wrapped with context cancellation reference counting.
func (ksServer *KubescapeMcpserver) doScanChan(ctx context.Context, key string, scanFunc func(context.Context) (interface{}, error)) (interface{}, error) {
	ksServer.scanCtxMu.Lock()
	if ksServer.scanCtxs == nil {
		ksServer.scanCtxs = make(map[string]*scanCtxState)
	}
	state, ok := ksServer.scanCtxs[key]
	if !ok {
		scanCtx, cancel := context.WithCancel(context.Background())
		state = &scanCtxState{
			ctx:    scanCtx,
			cancel: cancel,
		}
		ksServer.scanCtxs[key] = state
	}
	state.count++
	ksServer.scanCtxMu.Unlock()

	defer func() {
		ksServer.scanCtxMu.Lock()
		defer ksServer.scanCtxMu.Unlock()
		state.count--
		if state.count <= 0 {
			state.cancel()
			delete(ksServer.scanCtxs, key)
			// Keep this inside scanCtxMu's critical section. Otherwise a new
			// generation could be registered and then forgotten here.
			ksServer.scanGroup.Forget(key)
		}
	}()

	ch := ksServer.scanGroup.DoChan(key, func() (interface{}, error) {
		if err := ksServer.getScanSem().Acquire(state.ctx, 1); err != nil {
			return nil, err
		}
		defer ksServer.getScanSem().Release(1)
		return scanFunc(state.ctx)
	})

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		return res.Val, res.Err
	}
}

// getKsClient lazily initializes the Kubescape storage client. A transient
// initialization failure is not cached, so the next call retries instead of
// returning the same error forever.
func (ksServer *KubescapeMcpserver) getKsClient() (spdxv1beta1.SpdxV1beta1Interface, error) {
	ksServer.ksClientMu.Lock()
	defer ksServer.ksClientMu.Unlock()
	if ksServer.ksClient != nil {
		return ksServer.ksClient, nil
	}
	init := ksServer.ksClientInit
	if init == nil {
		init = newKsClient
	}
	client, err := init()
	if err != nil {
		return nil, err
	}
	if client == nil {
		// Belt-and-braces: CreateKsObjectConnection never returns (nil, nil)
		// today, but this guards against a future/injected implementation
		// doing so. It only catches an untyped nil interface value; a typed
		// nil pointer wrapped in the interface would still slip through and
		// be cached, since the error contract is what init() implementations
		// are expected to honor.
		return nil, fmt.Errorf("kubernetes client initialization returned nil")
	}
	ksServer.ksClient = client
	return ksServer.ksClient, nil
}

// getK8sClient lazily initializes the Kubernetes API client. It probes with
// loadK8sConfig (genuinely retryable, unlike k8sinterface.IsConnectedToCluster,
// which latches to false forever after its first failure) and only calls
// k8sinterface.NewKubernetesApi (which terminates the process via
// logger.L().Fatal on most internal failures) once a kubeconfig is confirmed
// loadable, so a missing/invalid KUBECONFIG returns an error instead of
// killing the server. On success it also clears any stale "not connected"
// latch left over from an earlier transient failure, since k8sinterface never
// resets that global on its own. Once a client is built it is cached; there
// is no retry for failures inside NewKubernetesApi itself, since those are
// fatal by construction and cannot be recovered from in-process.
func (ksServer *KubescapeMcpserver) getK8sClient() (*k8sinterface.KubernetesApi, error) {
	ksServer.k8sClientMu.Lock()
	defer ksServer.k8sClientMu.Unlock()
	if ksServer.k8sClient != nil {
		return ksServer.k8sClient, nil
	}
	if err := loadK8sConfig(); err != nil {
		setConnectedToCluster(false)
		return nil, fmt.Errorf("no reachable kubernetes cluster: ensure KUBECONFIG is set or the server is running inside a cluster: %w", err)
	}
	setConnectedToCluster(true)
	ksServer.k8sClient = newK8sClient()
	return ksServer.k8sClient, nil
}

// toolHandler binds a registered tool to its declared name and normalizes an
// omitted arguments object. A non-null value of any other JSON shape is a
// client error: silently treating it as an empty object could discard scope
// filters and unintentionally widen a query.
func (ksServer *KubescapeMcpserver) toolHandler(name string) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]any)
		if !ok && request.Params.Arguments != nil {
			return mcp.NewToolResultError("arguments must be a JSON object"), nil
		}
		if args == nil {
			args = map[string]any{}
		}
		res, err := ksServer.CallTool(ctx, name, args)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return res, nil
	}
}

func createVulnerabilityToolsAndResources(ksServer *KubescapeMcpserver) {
	// Tool to list vulnerability manifests
	listManifestsTool := mcp.NewTool(
		"list_vulnerability_manifests",
		mcp.WithDescription("Discover available vulnerability manifests at image and workload levels"),
		mcp.WithString("namespace",
			mcp.Description("Filter by namespace (optional)"),
		),
		mcp.WithString("level",
			mcp.Description("Type of vulnerability manifests to list"),
			mcp.Enum("image", "workload", "both"),
		),
	)

	ksServer.s.AddTool(listManifestsTool, ksServer.toolHandler(listManifestsTool.Name))

	listVulnerabilitiesTool := mcp.NewTool(
		"list_vulnerabilities_in_manifest",
		mcp.WithDescription("List all vulnerabilities in a given manifest"),
		mcp.WithString("namespace",
			mcp.Description("Filter by namespace (optional)"),
		),
		mcp.WithString("manifest_name",
			mcp.Required(),
			mcp.Description("Name of the manifest to list vulnerabilities from"),
		),
	)

	ksServer.s.AddTool(listVulnerabilitiesTool, ksServer.toolHandler(listVulnerabilitiesTool.Name))

	listVulnerabilityMatchesForCVE := mcp.NewTool(
		"list_vulnerability_matches_for_cve",
		mcp.WithDescription("List all vulnerability matches for a given CVE in a given manifest"),
		mcp.WithString("namespace",
			mcp.Description("Filter by namespace (optional)"),
		),
		mcp.WithString("manifest_name",
			mcp.Required(),
			mcp.Description("Name of the manifest to list vulnerabilities from"),
		),
		mcp.WithString("cve_id",
			mcp.Required(),
			mcp.Description("ID of the CVE to list matches for"),
		),
	)

	ksServer.s.AddTool(listVulnerabilityMatchesForCVE, ksServer.toolHandler(listVulnerabilityMatchesForCVE.Name))

	vulnerabilityManifestTemplate := mcp.NewResourceTemplate(
		"kubescape://vulnerability-manifests/{namespace}/{manifest_name}",
		"Vulnerability Manifest",
		mcp.WithTemplateDescription("Complete vulnerability manifest either for a specific workload or image. Use 'list_vulnerability_manifests' tool to discover available manifests."),
		mcp.WithTemplateMIMEType("application/json"),
	)

	ksServer.s.AddResourceTemplate(vulnerabilityManifestTemplate, ksServer.ReadResource)

}

func createConfigurationsToolsAndResources(ksServer *KubescapeMcpserver) {
	// Tool to list configuration manifests
	listConfigsTool := mcp.NewTool(
		"list_configuration_security_scan_manifests",
		mcp.WithDescription("Discover available security configuration scan results at workload level (this returns a list of manifests, not the scan results themselves, to get the scan results, use the get_configuration_security_scan_manifest tool)"),
		mcp.WithString("namespace",
			mcp.Description("Filter by namespace (optional)"),
		),
	)

	ksServer.s.AddTool(listConfigsTool, ksServer.toolHandler(listConfigsTool.Name))

	getConfigDetailsTool := mcp.NewTool(
		"get_configuration_security_scan_manifest",
		mcp.WithDescription("Get details of a specific security configuration scan result"),
		mcp.WithString("namespace",
			mcp.Description("Namespace of the manifest (optional, defaults to 'kubescape')"),
		),
		mcp.WithString("manifest_name",
			mcp.Required(),
			mcp.Description("Name of the configuration manifest to get details for (get this from the list_configuration_security_scan_manifests tool)"),
		),
	)

	ksServer.s.AddTool(getConfigDetailsTool, ksServer.toolHandler(getConfigDetailsTool.Name))

	configManifestTemplate := mcp.NewResourceTemplate(
		"kubescape://configuration-manifests/{namespace}/{manifest_name}",
		"Configuration Security Scan Manifest",
		mcp.WithTemplateDescription("Complete configuration scan manifest for a specific workload. Use 'list_configuration_security_scan_manifests' tool to discover available manifests."),
		mcp.WithTemplateMIMEType("application/json"),
	)

	ksServer.s.AddResourceTemplate(configManifestTemplate, ksServer.ReadConfigurationResource)
}

func createRuntimeToolsAndResources(ksServer *KubescapeMcpserver) {
	// Tool to list container profiles
	listContainerProfilesTool := mcp.NewTool(
		"list_container_profiles",
		mcp.WithDescription("Discover available container profiles at workload level (this returns a list of profiles, not the profile results themselves, to get the profile results, use the get_container_profile tool)"),
		mcp.WithString("namespace",
			mcp.Description("Filter by namespace (optional)"),
		),
	)

	ksServer.s.AddTool(listContainerProfilesTool, ksServer.toolHandler(listContainerProfilesTool.Name))

	getContainerProfileTool := mcp.NewTool(
		"get_container_profile",
		mcp.WithDescription("Get details of a specific container profile"),
		mcp.WithString("namespace",
			mcp.Description("Namespace of the profile (optional, defaults to 'kubescape')"),
		),
		mcp.WithString("profile_name",
			mcp.Required(),
			mcp.Description("Name of the container profile to get details for (get this from the list_container_profiles tool)"),
		),
	)

	ksServer.s.AddTool(getContainerProfileTool, ksServer.toolHandler(getContainerProfileTool.Name))

	getConfigurationDriftTool := mcp.NewTool(
		"get_configuration_drift",
		mcp.WithDescription("Get configuration drift patches (e.g. readOnlyRootFilesystem, drop capabilities) by comparing a workload's runtime ContainerProfile against its static manifest. Useful for suggesting security posture hardening."),
		mcp.WithString("namespace",
			mcp.Description("Namespace of the profile/workload (optional, defaults to 'default')"),
		),
		mcp.WithString("profile_name",
			mcp.Required(),
			mcp.Description("Name of the container profile to compute drift for."),
		),
		mcp.WithString("workload_name",
			mcp.Required(),
			mcp.Description("Name of the workload to compare against (e.g., my-deployment)."),
		),
		mcp.WithString("workload_kind",
			mcp.Required(),
			mcp.Description("Kind of the workload (e.g., Pod, Deployment, DaemonSet, StatefulSet)."),
		),
	)

	ksServer.s.AddTool(getConfigurationDriftTool, ksServer.toolHandler(getConfigurationDriftTool.Name))

	containerProfileTemplate := mcp.NewResourceTemplate(
		"kubescape://container-profiles/{namespace}/{profile_name}",
		"Container Profile",
		mcp.WithTemplateDescription("Complete container profile for a specific workload. Use 'list_container_profiles' tool to discover available profiles."),
		mcp.WithTemplateMIMEType("application/json"),
	)

	ksServer.s.AddResourceTemplate(containerProfileTemplate, ksServer.ReadContainerProfileResource)
}

// vulnManifestURI holds the parsed components of a vulnerability manifest resource URI.
type vulnManifestURI struct {
	namespace    string
	manifestName string
	cveID        string // empty for cve_list requests
}

// parseVulnManifestURI parses a kubescape://vulnerability-manifests/... URI into its components.
// Valid forms:
//
//	kubescape://vulnerability-manifests/{namespace}/{manifest_name}                          (defaults to cve_list)
//	kubescape://vulnerability-manifests/{namespace}/{manifest_name}/cve_list
//	kubescape://vulnerability-manifests/{namespace}/{manifest_name}/cve_details/{cve_id}
func parseVulnManifestURI(uri string) (*vulnManifestURI, error) {
	const prefix = "kubescape://vulnerability-manifests/"
	if !strings.HasPrefix(uri, prefix) {
		return nil, fmt.Errorf("invalid URI: %s", uri)
	}

	parts := strings.Split(uri[len(prefix):], "/")
	// base:        {namespace}/{manifest_name}                   -> 2 parts (defaults to cve_list)
	// cve_list:    {namespace}/{manifest_name}/cve_list          -> 3 parts
	// cve_details: {namespace}/{manifest_name}/cve_details/{id}  -> 4 parts
	if len(parts) < 2 || len(parts) > 4 {
		return nil, fmt.Errorf("invalid URI: %s", uri)
	}

	namespace := parts[0]
	manifestName := parts[1]
	if namespace == "" || manifestName == "" {
		return nil, fmt.Errorf("invalid URI: %s", uri)
	}

	parsed := &vulnManifestURI{namespace: namespace, manifestName: manifestName}
	if len(parts) == 2 {
		// Base URI defaults to cve_list behavior
		return parsed, nil
	}

	action := parts[2]
	switch {
	case len(parts) == 3 && action == "cve_list":
		// no cveID needed
	case len(parts) == 4 && action == "cve_details" && parts[3] != "":
		parsed.cveID = parts[3]
	default:
		return nil, fmt.Errorf("invalid URI: %s", uri)
	}

	return parsed, nil
}

// parseControlIDs extracts a list of trimmed, non-empty control IDs from an
// argument value that may be either a comma-separated string or a JSON array
// of strings. It returns a ToolResultError when the value is absent, has the
// wrong type, or yields no valid IDs after trimming.
func parseControlIDs(raw any, present bool) ([]string, *mcp.CallToolResult) {
	if !present {
		return nil, mcp.NewToolResultError("control_ids argument is required")
	}
	var ids []string
	switch v := raw.(type) {
	case string:
		for _, id := range strings.Split(v, ",") {
			if id = strings.TrimSpace(id); id != "" {
				ids = append(ids, id)
			}
		}
	case []interface{}:
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, mcp.NewToolResultError("control_ids array elements must be strings")
			}
			if s = strings.TrimSpace(s); s != "" {
				ids = append(ids, s)
			}
		}
	default:
		return nil, mcp.NewToolResultError("control_ids must be a comma-separated string or array")
	}
	if len(ids) == 0 {
		return nil, mcp.NewToolResultError("control_ids must contain at least one control ID")
	}
	return ids, nil
}

// withControlIDsProperty adds control_ids to the tool schema as a required
// property that accepts either a comma-separated string or an array of strings.
func withControlIDsProperty(desc string) mcp.ToolOption {
	return func(t *mcp.Tool) {
		t.InputSchema.Properties["control_ids"] = map[string]any{
			"anyOf": []any{
				map[string]any{"type": "string"},
				map[string]any{
					"type":  "array",
					"items": map[string]any{"type": "string"},
				},
			},
			"description": desc,
		}
		t.InputSchema.Required = append(t.InputSchema.Required, "control_ids")
	}
}

func (ksServer *KubescapeMcpserver) ReadResource(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	uri := request.Params.URI

	parsed, err := parseVulnManifestURI(uri)
	if err != nil {
		return nil, err
	}

	namespace := parsed.namespace
	manifestName := parsed.manifestName
	cveID := parsed.cveID

	// Get the vulnerability manifest
	client, ksErr := ksServer.getKsClient()
	if ksErr != nil {
		return nil, fmt.Errorf("failed to connect to Kubernetes cluster: %w", ksErr)
	}
	manifest, err := client.VulnerabilityManifests(namespace).Get(ctx, manifestName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerability manifest: %w", err)
	}

	var responseJson []byte
	if cveID == "" {
		// CVE list
		var cveList []v1beta1.Vulnerability
		for _, match := range manifest.Spec.Payload.Matches {
			cveList = append(cveList, match.Vulnerability)
		}
		responseJson, err = json.Marshal(cveList)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal cve list: %w", err)
		}
	} else {
		// CVE details
		var match []v1beta1.Match
		for _, m := range manifest.Spec.Payload.Matches {
			if m.Vulnerability.ID == cveID {
				match = append(match, m)
			}
		}
		responseJson, err = json.Marshal(match)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal cve details: %w", err)
		}
	}

	return []mcp.ResourceContents{mcp.TextResourceContents{
		URI:  uri,
		Text: string(responseJson),
	}}, nil
}

func (ksServer *KubescapeMcpserver) ReadConfigurationResource(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	uri := request.Params.URI
	if !strings.HasPrefix(uri, "kubescape://configuration-manifests/") {
		return nil, fmt.Errorf("invalid URI: %s", uri)
	}
	parts := strings.Split(uri[len("kubescape://configuration-manifests/"):], "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("invalid URI: %s", uri)
	}
	namespace := parts[0]
	manifestName := parts[1]
	client, ksErr := ksServer.getKsClient()
	if ksErr != nil {
		return nil, fmt.Errorf("failed to connect to Kubernetes cluster: %w", ksErr)
	}
	manifest, err := client.WorkloadConfigurationScans(namespace).Get(ctx, manifestName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get configuration manifest: %w", err)
	}
	responseJson, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal configuration manifest: %w", err)
	}
	return []mcp.ResourceContents{mcp.TextResourceContents{
		URI:  uri,
		Text: string(responseJson),
	}}, nil
}

func (ksServer *KubescapeMcpserver) ReadContainerProfileResource(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	uri := request.Params.URI
	if !strings.HasPrefix(uri, "kubescape://container-profiles/") {
		return nil, fmt.Errorf("invalid URI: %s", uri)
	}
	parts := strings.Split(uri[len("kubescape://container-profiles/"):], "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("invalid URI: %s", uri)
	}
	namespace := parts[0]
	profileName := parts[1]
	client, ksErr := ksServer.getKsClient()
	if ksErr != nil {
		return nil, fmt.Errorf("failed to connect to Kubernetes cluster: %w", ksErr)
	}
	profile, err := client.ContainerProfiles(namespace).Get(ctx, profileName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get container profile: %w", err)
	}
	responseJson, err := json.Marshal(profile)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal container profile: %w", err)
	}
	return []mcp.ResourceContents{mcp.TextResourceContents{
		URI:  uri,
		Text: string(responseJson),
	}}, nil
}

func (ksServer *KubescapeMcpserver) CallTool(ctx context.Context, name string, arguments map[string]any) (*mcp.CallToolResult, error) {
	switch name {
	case "run_rbac_security_scan":
		namespace := ""
		if ns, ok := arguments["namespace"]; ok {
			nsStr, ok := ns.(string)
			if !ok {
				return mcp.NewToolResultError("namespace argument must be a string"), nil
			}
			namespace = nsStr
		}
		if namespace == "*" {
			namespace = ""
		}
		key := fmt.Sprintf("rbac_scan:%s", namespace)
		v, err := ksServer.doScanChan(ctx, key, func(scanCtx context.Context) (interface{}, error) {
			return ksServer.RunRBACScan(scanCtx, namespace)
		})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to run RBAC scan: %v", err)), nil
		}
		responseBytes := v.([]byte)
		return mcp.NewToolResultText(string(responseBytes)), nil
	case "scan_local_iac":
		path := ""
		if p, ok := arguments["path"]; ok {
			pStr, ok := p.(string)
			if !ok {
				return mcp.NewToolResultError("path argument must be a string"), nil
			}
			path = strings.TrimSpace(pStr)
		}
		if path == "" {
			return mcp.NewToolResultError("path argument is required and cannot be empty"), nil
		}
		framework := ""
		if fw, ok := arguments["framework"]; ok {
			fwStr, ok := fw.(string)
			if !ok {
				return mcp.NewToolResultError("framework argument must be a string"), nil
			}
			framework = strings.TrimSpace(fwStr)
		}

		key := fmt.Sprintf("scan_local_iac:%s:%s", url.QueryEscape(path), url.QueryEscape(framework))
		v, err := ksServer.doScanChan(ctx, key, func(scanCtx context.Context) (interface{}, error) {
			return ksServer.runIaCScan(scanCtx, path, framework)
		})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to run IaC scan: %v", err)), nil
		}
		responseBytes := v.([]byte)
		return mcp.NewToolResultText(string(responseBytes)), nil
	case "scan_local_iac_controls":
		path := ""
		if p, ok := arguments["path"]; ok {
			pStr, ok := p.(string)
			if !ok {
				return mcp.NewToolResultError("path argument must be a string"), nil
			}
			path = strings.TrimSpace(pStr)
		}
		if path == "" {
			return mcp.NewToolResultError("path argument is required and cannot be empty"), nil
		}
		rawControlIDs, hasControlIDs := arguments["control_ids"]
		controlIDs, toolErr := parseControlIDs(rawControlIDs, hasControlIDs)
		if toolErr != nil {
			return toolErr, nil
		}
		key := fmt.Sprintf("scan_local_iac_controls:%s:%s", url.QueryEscape(path), url.QueryEscape(strings.Join(controlIDs, ",")))
		v, err := ksServer.doScanChan(ctx, key, func(scanCtx context.Context) (interface{}, error) {
			return ksServer.runIaCScanControls(scanCtx, path, controlIDs)
		})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to run IaC control scan: %v", err)), nil
		}
		return mcp.NewToolResultText(string(v.([]byte))), nil
	case "run_network_security_scan":
		namespace := ""
		if ns, ok := arguments["namespace"]; ok {
			nsStr, ok := ns.(string)
			if !ok {
				return mcp.NewToolResultError("namespace argument must be a string"), nil
			}
			namespace = nsStr
		}
		if namespace == "*" {
			namespace = ""
		}
		key := fmt.Sprintf("network_scan:%s", namespace)
		v, err := ksServer.doScanChan(ctx, key, func(scanCtx context.Context) (interface{}, error) {
			return ksServer.RunNetworkScan(scanCtx, namespace)
		})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to run Network scan: %v", err)), nil
		}
		responseBytes := v.([]byte)
		return mcp.NewToolResultText(string(responseBytes)), nil
	case "list_vulnerability_manifests":
		namespace := metav1.NamespaceAll
		if ns, ok := arguments["namespace"]; ok {
			nsStr, ok := ns.(string)
			if !ok {
				return nil, fmt.Errorf("namespace must be a string")
			}
			if nsStr != "" {
				namespace = nsStr
			}
		}
		level, ok := arguments["level"]
		if !ok {
			level = "both"
		}

		result := map[string]any{
			"vulnerability_manifests": map[string]any{},
		}

		// Get workload-level manifests
		labelSelector := ""
		switch level {
		case "workload":
			labelSelector = "kubescape.io/context=filtered"
		case "image":
			labelSelector = "kubescape.io/context=non-filtered"
		}

		var manifests *v1beta1.VulnerabilityManifestList
		var err error
		if labelSelector == "" {
			client, ksErr := ksServer.getKsClient()
			if ksErr != nil {
				return nil, fmt.Errorf("failed to connect to Kubernetes cluster: %w", ksErr)
			}
			manifests, err = client.VulnerabilityManifests(namespace).List(ctx, metav1.ListOptions{})
		} else {
			client, ksErr := ksServer.getKsClient()
			if ksErr != nil {
				return nil, fmt.Errorf("failed to connect to Kubernetes cluster: %w", ksErr)
			}
			manifests, err = client.VulnerabilityManifests(namespace).List(ctx, metav1.ListOptions{
				LabelSelector: labelSelector,
			})
		}
		if err != nil {
			return nil, err
		}

		logger.L().Info(fmt.Sprintf("Found %d manifests", len(manifests.Items)))

		vulnerabilityManifests := []map[string]any{}
		for _, manifest := range manifests.Items {
			isImageLevel := manifest.Annotations[helpersv1.WlidMetadataKey] == ""
			manifestMap := map[string]any{
				"type":                    "workload",
				"namespace":               manifest.Namespace,
				"manifest_name":           manifest.Name,
				"image-level":             isImageLevel,
				"workload-level":          !isImageLevel,
				"image-id":                manifest.Annotations[helpersv1.ImageIDMetadataKey],
				"image-tag":               manifest.Annotations[helpersv1.ImageTagMetadataKey],
				"workload-id":             manifest.Annotations[helpersv1.WlidMetadataKey],
				"workload-container-name": manifest.Annotations[helpersv1.ContainerNameMetadataKey],
				"resource_uri": fmt.Sprintf("kubescape://vulnerability-manifests/%s/%s",
					manifest.Namespace, manifest.Name),
			}
			vulnerabilityManifests = append(vulnerabilityManifests, manifestMap)
		}
		result["vulnerability_manifests"].(map[string]any)["manifests"] = vulnerabilityManifests

		// Add template information
		result["available_templates"] = map[string]string{
			"vulnerability_manifest_cve_list":    "kubescape://vulnerability-manifests/{namespace}/{manifest_name}/cve_list",
			"vulnerability_manifest_cve_details": "kubescape://vulnerability-manifests/{namespace}/{manifest_name}/cve_details/{cve_id}",
		}

		content, err := json.Marshal(result)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal result: %w", err)
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.TextContent{
					Type: "text",
					Text: string(content),
				},
			},
		}, nil
	case "list_vulnerabilities_in_manifest":
		namespace, ok := arguments["namespace"]
		if !ok {
			namespace = "kubescape"
		}
		namespaceStr, ok := namespace.(string)
		if !ok {
			return nil, fmt.Errorf("namespace must be a string")
		}
		manifestName, ok := arguments["manifest_name"]
		if !ok {
			return nil, fmt.Errorf("manifest_name is required")
		}
		manifestNameStr, ok := manifestName.(string)
		if !ok {
			return nil, fmt.Errorf("manifest_name must be a string")
		}
		client, ksErr := ksServer.getKsClient()
		if ksErr != nil {
			return nil, fmt.Errorf("failed to connect to Kubernetes cluster: %w", ksErr)
		}
		manifest, err := client.VulnerabilityManifests(namespaceStr).Get(ctx, manifestNameStr, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get vulnerability manifest: %w", err)
		}
		var cveList []v1beta1.Vulnerability
		for _, match := range manifest.Spec.Payload.Matches {
			cveList = append(cveList, match.Vulnerability)
		}
		responseJson, err := json.Marshal(cveList)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal cve list: %w", err)
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.TextContent{
					Type: "text",
					Text: string(responseJson),
				},
			},
		}, nil
	case "list_vulnerability_matches_for_cve":
		namespace, ok := arguments["namespace"]
		if !ok {
			namespace = "kubescape"
		}
		namespaceStr, ok := namespace.(string)
		if !ok {
			return nil, fmt.Errorf("namespace must be a string")
		}
		manifestName, ok := arguments["manifest_name"]
		if !ok {
			return nil, fmt.Errorf("manifest_name is required")
		}
		manifestNameStr, ok := manifestName.(string)
		if !ok {
			return nil, fmt.Errorf("manifest_name must be a string")
		}
		cveID, ok := arguments["cve_id"]
		if !ok {
			return nil, fmt.Errorf("cve_id is required")
		}
		cveIDStr, ok := cveID.(string)
		if !ok {
			return nil, fmt.Errorf("cve_id must be a string")
		}
		client, ksErr := ksServer.getKsClient()
		if ksErr != nil {
			return nil, fmt.Errorf("failed to connect to Kubernetes cluster: %w", ksErr)
		}
		manifest, err := client.VulnerabilityManifests(namespaceStr).Get(ctx, manifestNameStr, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get vulnerability manifest: %w", err)
		}
		var match []v1beta1.Match
		for _, m := range manifest.Spec.Payload.Matches {
			if m.Vulnerability.ID == cveIDStr {
				match = append(match, m)
			}
		}
		responseJson, err := json.Marshal(match)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal cve details: %w", err)
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.TextContent{
					Type: "text",
					Text: string(responseJson),
				},
			},
		}, nil
	case "list_configuration_security_scan_manifests":
		namespace, ok := arguments["namespace"]
		if !ok {
			namespace = "kubescape"
		}
		namespaceStr, ok := namespace.(string)
		if !ok {
			return nil, fmt.Errorf("namespace must be a string")
		}
		client, ksErr := ksServer.getKsClient()
		if ksErr != nil {
			return nil, fmt.Errorf("failed to connect to Kubernetes cluster: %w", ksErr)
		}
		manifests, err := client.WorkloadConfigurationScans(namespaceStr).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		logger.L().Info(fmt.Sprintf("Found %d configuration manifests", len(manifests.Items)))
		configManifests := []map[string]any{}
		for _, manifest := range manifests.Items {
			item := map[string]any{
				"namespace":     manifest.Namespace,
				"manifest_name": manifest.Name,
				"resource_uri":  fmt.Sprintf("kubescape://configuration-manifests/%s/%s", manifest.Namespace, manifest.Name),
			}
			configManifests = append(configManifests, item)
		}
		result := map[string]any{
			"configuration_manifests": map[string]any{
				"manifests": configManifests,
			},
			"available_templates": map[string]string{
				"configuration_manifest_details": "kubescape://configuration-manifests/{namespace}/{manifest_name}",
			},
		}
		content, err := json.Marshal(result)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal result: %w", err)
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.TextContent{
					Type: "text",
					Text: string(content),
				},
			},
		}, nil
	case "get_configuration_security_scan_manifest":
		namespace, ok := arguments["namespace"]
		if !ok {
			namespace = "kubescape"
		}
		namespaceStr, ok := namespace.(string)
		if !ok {
			return nil, fmt.Errorf("namespace must be a string")
		}
		manifestName, ok := arguments["manifest_name"]
		if !ok {
			return nil, fmt.Errorf("manifest_name is required")
		}
		manifestNameStr, ok := manifestName.(string)
		if !ok {
			return nil, fmt.Errorf("manifest_name must be a string")
		}
		client, ksErr := ksServer.getKsClient()
		if ksErr != nil {
			return nil, fmt.Errorf("failed to connect to Kubernetes cluster: %w", ksErr)
		}
		manifest, err := client.WorkloadConfigurationScans(namespaceStr).Get(ctx, manifestNameStr, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get configuration manifest: %w", err)
		}
		responseJson, err := json.Marshal(manifest)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal configuration manifest: %w", err)
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.TextContent{
					Type: "text",
					Text: string(responseJson),
				},
			},
		}, nil
	case "list_container_profiles":
		namespace := metav1.NamespaceAll
		if ns, ok := arguments["namespace"]; ok {
			nsStr, ok := ns.(string)
			if !ok {
				return nil, fmt.Errorf("namespace must be a string")
			}
			if nsStr != "" {
				namespace = nsStr
			}
		}
		client, ksErr := ksServer.getKsClient()
		if ksErr != nil {
			return nil, fmt.Errorf("failed to connect to Kubernetes cluster: %w", ksErr)
		}
		profiles, err := client.ContainerProfiles(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		logger.L().Info(fmt.Sprintf("Found %d container profiles", len(profiles.Items)))
		containerProfilesList := []map[string]any{}
		for _, profile := range profiles.Items {
			item := map[string]any{
				"namespace":    profile.Namespace,
				"profile_name": profile.Name,
				"resource_uri": fmt.Sprintf("kubescape://container-profiles/%s/%s", profile.Namespace, profile.Name),
			}
			containerProfilesList = append(containerProfilesList, item)
		}
		result := map[string]any{
			"container_profiles": map[string]any{
				"profiles": containerProfilesList,
			},
			"available_templates": map[string]string{
				"container_profile_details": "kubescape://container-profiles/{namespace}/{profile_name}",
			},
		}
		content, err := json.Marshal(result)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal result: %w", err)
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.TextContent{
					Type: "text",
					Text: string(content),
				},
			},
		}, nil
	case "get_container_profile":
		namespace, ok := arguments["namespace"]
		if !ok {
			namespace = "kubescape"
		}
		namespaceStr, ok := namespace.(string)
		if !ok {
			return nil, fmt.Errorf("namespace must be a string")
		}
		profileName, ok := arguments["profile_name"]
		if !ok {
			return nil, fmt.Errorf("profile_name is required")
		}
		profileNameStr, ok := profileName.(string)
		if !ok {
			return nil, fmt.Errorf("profile_name must be a string")
		}
		client, ksErr := ksServer.getKsClient()
		if ksErr != nil {
			return nil, fmt.Errorf("failed to connect to Kubernetes cluster: %w", ksErr)
		}
		profile, err := client.ContainerProfiles(namespaceStr).Get(ctx, profileNameStr, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get container profile: %w", err)
		}
		responseJson, err := json.Marshal(profile)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal container profile: %w", err)
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.TextContent{
					Type: "text",
					Text: string(responseJson),
				},
			},
		}, nil
	case "get_configuration_drift":
		namespace, ok := arguments["namespace"]
		if !ok {
			namespace = "default"
		}
		namespaceStr, ok := namespace.(string)
		if !ok {
			return mcp.NewToolResultError("namespace must be a string"), nil
		}
		profileName, ok := arguments["profile_name"]
		if !ok {
			return mcp.NewToolResultError("profile_name is required"), nil
		}
		profileNameStr, ok := profileName.(string)
		if !ok {
			return mcp.NewToolResultError("profile_name must be a string"), nil
		}
		workloadName, ok := arguments["workload_name"]
		if !ok {
			return mcp.NewToolResultError("workload_name is required"), nil
		}
		workloadNameStr, ok := workloadName.(string)
		if !ok {
			return mcp.NewToolResultError("workload_name must be a string"), nil
		}
		workloadKind, ok := arguments["workload_kind"]
		if !ok {
			return mcp.NewToolResultError("workload_kind is required"), nil
		}
		workloadKindStr, ok := workloadKind.(string)
		if !ok {
			return mcp.NewToolResultError("workload_kind must be a string"), nil
		}

		ksClient, ksErr := ksServer.getKsClient()
		if ksErr != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to connect to storage client: %v", ksErr)), nil
		}
		profile, err := ksClient.ContainerProfiles(namespaceStr).Get(ctx, profileNameStr, metav1.GetOptions{})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to get container profile: %v", err)), nil
		}

		var rawManifest []byte
		var workloadObj any
		k8sClient, k8sErr := ksServer.getK8sClient()
		if k8sErr != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to connect to Kubernetes cluster: %v", k8sErr)), nil
		}
		switch strings.ToLower(workloadKindStr) {
		case "pod":
			workloadObj, err = k8sClient.KubernetesClient.CoreV1().Pods(namespaceStr).Get(ctx, workloadNameStr, metav1.GetOptions{})
		case "deployment":
			workloadObj, err = k8sClient.KubernetesClient.AppsV1().Deployments(namespaceStr).Get(ctx, workloadNameStr, metav1.GetOptions{})
		case "daemonset":
			workloadObj, err = k8sClient.KubernetesClient.AppsV1().DaemonSets(namespaceStr).Get(ctx, workloadNameStr, metav1.GetOptions{})
		case "statefulset":
			workloadObj, err = k8sClient.KubernetesClient.AppsV1().StatefulSets(namespaceStr).Get(ctx, workloadNameStr, metav1.GetOptions{})
		default:
			return mcp.NewToolResultError(fmt.Sprintf("unsupported workload kind: %s", workloadKindStr)), nil
		}

		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to get workload manifest: %v", err)), nil
		}
		rawManifest, err = jsonMarshal(workloadObj)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to marshal workload manifest: %v", err)), nil
		}

		containerName := ""
		if profile.GetLabels() != nil {
			containerName = profile.GetLabels()["kubescape.io/workload-container-name"]
			profileKind := profile.GetLabels()["kubescape.io/workload-kind"]
			profileName := profile.GetLabels()["kubescape.io/workload-name"]

			if profileKind != "" && !strings.EqualFold(profileKind, workloadKindStr) {
				return mcp.NewToolResultError(fmt.Sprintf("profile workload kind mismatch: expected %s, got %s", workloadKindStr, profileKind)), nil
			}
			if profileName != "" && profileName != workloadNameStr {
				return mcp.NewToolResultError(fmt.Sprintf("profile workload name mismatch: expected %s, got %s", workloadNameStr, profileName)), nil
			}
		}
		fixes := fixhandler.DetectProfileDrift(rawManifest, profile, workloadKindStr, containerName, 0)
		fixesJson, err := json.MarshalIndent(fixes, "", "  ")
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to marshal drift result: %v", err)), nil
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.TextContent{
					Type: "text",
					Text: string(fixesJson),
				},
			},
		}, nil
	case "run_framework_security_scan":
		namespace := ""
		if ns, ok := arguments["namespace"]; ok {
			nsStr, ok := ns.(string)
			if !ok {
				return mcp.NewToolResultError("namespace argument must be a string"), nil
			}
			namespace = nsStr
		}
		frameworkName, ok := arguments["framework_name"]
		if !ok {
			return mcp.NewToolResultError("framework_name argument is required"), nil
		}
		frameworkNameStr, ok := frameworkName.(string)
		if !ok {
			return mcp.NewToolResultError("framework_name argument must be a string"), nil
		}
		frameworkNameStr = strings.TrimSpace(frameworkNameStr)
		if frameworkNameStr == "" {
			return mcp.NewToolResultError("framework_name argument must not be empty"), nil
		}
		if namespace == "*" {
			namespace = ""
		}
		key := fmt.Sprintf("framework_scan:%s:%s", namespace, url.QueryEscape(frameworkNameStr))
		v, err := ksServer.doScanChan(ctx, key, func(scanCtx context.Context) (interface{}, error) {
			return ksServer.RunFrameworkScan(scanCtx, namespace, frameworkNameStr)
		})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to run framework scan: %v", err)), nil
		}
		responseBytes := v.([]byte)
		return mcp.NewToolResultText(string(responseBytes)), nil
	case "scan_controls":
		namespace := ""
		if ns, ok := arguments["namespace"]; ok {
			nsStr, ok := ns.(string)
			if !ok {
				return mcp.NewToolResultError("namespace argument must be a string"), nil
			}
			namespace = nsStr
		}
		if namespace == "*" {
			namespace = ""
		}
		rawControlIDs, hasControlIDs := arguments["control_ids"]
		controlIDs, toolErr := parseControlIDs(rawControlIDs, hasControlIDs)
		if toolErr != nil {
			return toolErr, nil
		}
		key := fmt.Sprintf("control_scan:%s:%s", namespace, url.QueryEscape(strings.Join(controlIDs, ",")))
		v, err := ksServer.doScanChan(ctx, key, func(scanCtx context.Context) (interface{}, error) {
			return ksServer.ScanControls(scanCtx, namespace, controlIDs)
		})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to run control scan: %v", err)), nil
		}
		return mcp.NewToolResultText(string(v.([]byte))), nil
	case "list_frameworks":
		result, err := ksServer.ListFrameworks(ctx)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to list frameworks: %v", err)), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	case "list_controls":
		result, err := ksServer.ListControls(ctx)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to list controls: %v", err)), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	default:
		return nil, fmt.Errorf("unknown tool: %s", name)
	}
}

func mcpServerEntrypoint(transport string, port int) error {
	logger.L().Info("Starting MCP server...")

	// Create a new MCP server
	s := server.NewMCPServer(
		"Kubescape MCP Server",
		"0.0.1",
		server.WithToolCapabilities(false),
		server.WithRecovery(),
	)

	ksServer := &KubescapeMcpserver{
		s:            s,
		policyGetter: getter.NewDownloadReleasedPolicy(),
	}

	// Initialize the policy getter to load the local ~/.kubescape cache.
	// Without this, the getter will always hit the GitHub API directly for every scan,
	// defeating offline scanning and causing rate limits.
	if _, err := ksServer.policyGetter.SetRegoObjectsWithFallback(); err != nil {
		logger.L().Warning("Failed to initialize policy store at startup (falling back to direct download later)", helpers.Error(err))
	}

	// Creating Kubescape tools and resources

	createVulnerabilityToolsAndResources(ksServer)
	createConfigurationsToolsAndResources(ksServer)
	createRuntimeToolsAndResources(ksServer)
	createRBACScanningTools(ksServer)
	createNetworkScanningTools(ksServer)
	createFrameworkScanningTools(ksServer)
	createIaCScanningTools(ksServer)
	createIaCControlScanningTool(ksServer)
	createControlScanningTools(ksServer)
	createPolicyListingTools(ksServer)
	createAdvancedTools(ksServer)

	// Start the server
	if transport == "sse" {
		sseServer := server.NewSSEServer(s)
		addr := fmt.Sprintf(":%d", port)
		logger.L().Info("Starting SSE server", helpers.String("addr", addr))
		if err := sseServer.Start(addr); err != nil {
			return fmt.Errorf("sse server error: %w", err)
		}
		return nil
	} else {
		if err := server.ServeStdio(s); err != nil {
			return fmt.Errorf("server error: %w", err)
		}
		return nil
	}
}

func createRBACScanningTools(ksServer *KubescapeMcpserver) {
	runRBACScanTool := mcp.NewTool(
		"run_rbac_security_scan",
		mcp.WithDescription("Run an on-demand, live RBAC security scan (evaluating only over-permissive cluster bindings) and return the failed resources."),
		mcp.WithString("namespace",
			mcp.Description("Namespace to scope the RBAC scan (optional, defaults to cluster-wide if omitted)"),
		),
	)

	ksServer.s.AddTool(runRBACScanTool, ksServer.toolHandler(runRBACScanTool.Name))
}

func createNetworkScanningTools(ksServer *KubescapeMcpserver) {
	runNetworkScanTool := mcp.NewTool(
		"run_network_security_scan",
		mcp.WithDescription("Run an on-demand, live Network security scan (evaluating only ingress and egress block policies) and return the failed resources."),
		mcp.WithString("namespace",
			mcp.Description("Namespace to scope the Network scan (optional, defaults to cluster-wide if omitted)"),
		),
	)

	ksServer.s.AddTool(runNetworkScanTool, ksServer.toolHandler(runNetworkScanTool.Name))
}

func createFrameworkScanningTools(ksServer *KubescapeMcpserver) {
	runFrameworkScanTool := mcp.NewTool(
		"run_framework_security_scan",
		mcp.WithDescription("Run an on-demand, live Framework security scan (e.g. nsa, mitre) and return the failed resources along with the compliance score."),
		mcp.WithString("namespace",
			mcp.Description("Namespace to scope the Framework scan (optional, defaults to cluster-wide if omitted)"),
		),
		mcp.WithString("framework_name",
			mcp.Required(),
			mcp.Description("Name of the framework to scan (e.g. nsa, mitre, cis-v1.23-t1.0.1)"),
		),
	)

	ksServer.s.AddTool(runFrameworkScanTool, ksServer.toolHandler(runFrameworkScanTool.Name))
}

func createIaCScanningTools(ksServer *KubescapeMcpserver) {
	iacScanTool := mcp.NewTool(
		"scan_local_iac",
		mcp.WithDescription("Scan local Infrastructure-as-Code (Helm charts, Kustomize, YAML) for security misconfigurations"),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Absolute or relative path to the local directory or file (e.g., /path/to/helm-chart or /path/to/manifest.yaml)"),
		),
		mcp.WithString("framework",
			mcp.Description("Framework to scan against (optional, defaults to nsa)"),
		),
	)

	ksServer.s.AddTool(iacScanTool, ksServer.toolHandler(iacScanTool.Name))
}

func createIaCControlScanningTool(ksServer *KubescapeMcpserver) {
	iacControlScanTool := mcp.NewTool(
		"scan_local_iac_controls",
		mcp.WithDescription("Scan local Infrastructure-as-Code (Helm charts, Kustomize, YAML) for specific controls by control ID. Use list_controls to discover valid IDs. Prefer scan_local_iac when you want full framework coverage."),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Absolute or relative path to the local directory or file (e.g., /path/to/helm-chart or /path/to/manifest.yaml)"),
		),
		withControlIDsProperty("Control IDs to scan against: a comma-separated string (e.g. \"C-0012,C-0017\") or an array of strings (e.g. [\"C-0012\",\"C-0017\"]). At least one ID is required."),
	)
	ksServer.s.AddTool(iacControlScanTool, ksServer.toolHandler(iacControlScanTool.Name))
}

func createControlScanningTools(ksServer *KubescapeMcpserver) {
	runControlScanTool := mcp.NewTool(
		"scan_controls",
		mcp.WithDescription("Run an on-demand, live security scan restricted to a given set of controls by control ID (e.g. C-0012, C-0017) and return the failed resources. Use list_controls to discover valid IDs first."),
		withControlIDsProperty("Control IDs to scan: a comma-separated string (e.g. \"C-0012,C-0017\") or an array of strings (e.g. [\"C-0012\",\"C-0017\"]). At least one ID is required."),
		mcp.WithString("namespace",
			mcp.Description("Namespace to scope the scan (optional, defaults to cluster-wide if omitted)"),
		),
	)
	ksServer.s.AddTool(runControlScanTool, ksServer.toolHandler(runControlScanTool.Name))
}

func createPolicyListingTools(ksServer *KubescapeMcpserver) {
	listFrameworksTool := mcp.NewTool(
		"list_frameworks",
		mcp.WithDescription("List the names of all security frameworks available for scanning (e.g. nsa, mitre, cis-v1.23-t1.0.1). Use a returned name as the framework_name argument to run_framework_security_scan."),
	)
	listControlsTool := mcp.NewTool(
		"list_controls",
		mcp.WithDescription("List all available security controls with their IDs, names, and the frameworks they belong to. Use a returned ID as a control_ids value in scan_controls."),
	)
	ksServer.s.AddTool(listFrameworksTool, ksServer.toolHandler(listFrameworksTool.Name))
	ksServer.s.AddTool(listControlsTool, ksServer.toolHandler(listControlsTool.Name))
}

func GetMCPServerCmd() *cobra.Command {
	var transport string
	var port int
	cmd := &cobra.Command{
		Use:   "mcpserver",
		Short: "Start the Kubescape MCP server",
		Long:  `Start the Kubescape MCP server`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return mcpServerEntrypoint(transport, port)
		},
	}
	cmd.Flags().StringVarP(&transport, "transport", "t", "stdio", "Transport protocol to use (stdio or sse)")
	cmd.Flags().IntVarP(&port, "port", "p", 8080, "Port to use for SSE transport")
	return cmd
}
