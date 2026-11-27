package mcpserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	spdxv1beta1 "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/kubescape/v4/core/pkg/fixhandler"
	"github.com/kubescape/kubescape/v4/core/pkg/pathcontainment"
	"golang.org/x/sync/semaphore"
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

// Scan implementations are package-level vars so CallTool tests can observe
// namespace mapping without running a cluster scan.
var rbacScanFn = func(s *KubescapeMcpserver, ctx context.Context, namespace string, filters ...scanFilterArgs) ([]byte, error) {
	return s.RunRBACScan(ctx, namespace, filters...)
}

var networkScanFn = func(s *KubescapeMcpserver, ctx context.Context, namespace string, filters ...scanFilterArgs) ([]byte, error) {
	return s.RunNetworkScan(ctx, namespace, filters...)
}

var frameworkScanFn = func(s *KubescapeMcpserver, ctx context.Context, namespace, frameworkName string, filters ...scanFilterArgs) ([]byte, error) {
	return s.RunFrameworkScan(ctx, namespace, frameworkName, filters...)
}

var localIaCScanFn = func(s *KubescapeMcpserver, ctx context.Context, path, framework string, filters ...scanFilterArgs) ([]byte, error) {
	return s.runIaCScan(ctx, path, framework, filters...)
}

var localIaCControlsScanFn = func(s *KubescapeMcpserver, ctx context.Context, path string, controlIDs []string, filters ...scanFilterArgs) ([]byte, error) {
	return s.runIaCScanControls(ctx, path, controlIDs, filters...)
}

var manifestScanFn = func(s *KubescapeMcpserver, ctx context.Context, manifest, framework string, controlIDs []string, filters ...scanFilterArgs) ([]byte, error) {
	return s.runManifestScan(ctx, manifest, framework, controlIDs, filters...)
}
var controlsScanFn = func(s *KubescapeMcpserver, ctx context.Context, namespace string, controlIDs []string, filters ...scanFilterArgs) ([]byte, error) {
	return s.ScanControls(ctx, namespace, controlIDs, filters...)
}

// mcpScanNamespace reads the optional CallTool namespace argument. "*" means
// cluster-wide, the same as omitting the argument. Like mcpStringArg, it
// treats a JSON null as an omitted argument and trims the value, so the scan
// tools accept the same spellings of "no namespace" as the tools that read
// namespace through mcpStringArg.
func mcpScanNamespace(arguments map[string]any) (string, error) {
	namespace := ""
	if ns, ok := arguments["namespace"]; ok && ns != nil {
		nsStr, ok := ns.(string)
		if !ok {
			return "", fmt.Errorf("namespace argument must be a string")
		}
		namespace = strings.TrimSpace(nsStr)
	}
	if namespace == "*" {
		namespace = ""
	}
	return namespace, nil
}

// mcpStringArg reads an optional string tool argument and trims it. An argument
// that is present but not a string is reported rather than ignored: silently
// falling back to the empty string would widen a scan the caller meant to
// narrow, the same reasoning behind mcpScanNamespace's type check.
//
// A JSON null is treated as absent, not as a type error. Clients routinely send
// null for an optional parameter they are not setting, and refusing the whole
// call because an unset argument was spelled null rather than omitted would be
// hostile to exactly the callers these optional arguments exist for.
//
// Note: for required arguments, use mcpRequiredStringArg instead. mcpStringArg
// returns ("", nil) when an argument is missing or null, which requires manual
// empty-string validation and is prone to omission bugs.
func mcpStringArg(arguments map[string]any, name string) (string, *mcp.CallToolResult) {
	raw, ok := arguments[name]
	if !ok || raw == nil {
		return "", nil
	}
	s, ok := raw.(string)
	if !ok {
		return "", mcpToolError(ErrCodeInvalidArgument, fmt.Sprintf("%s argument must be a string", name), map[string]any{"argument": name})
	}
	return strings.TrimSpace(s), nil
}

// mcpRequiredStringArg reads a required string tool argument. Returns a
// structured INVALID_ARGUMENT error if the argument is absent, null,
// non-string, or empty after trimming. This eliminates the footgun where
// a caller of mcpStringArg forgets to check for empty string after a nil
// toolErr return.
func mcpRequiredStringArg(arguments map[string]any, name string) (string, *mcp.CallToolResult) {
	s, toolErr := mcpStringArg(arguments, name)
	if toolErr != nil {
		return "", toolErr
	}
	if s == "" {
		return "", mcpToolError(ErrCodeInvalidArgument,
			fmt.Sprintf("%s argument is required and cannot be empty", name),
			map[string]any{"argument": name})
	}
	return s, nil
}

// mcpBoolArg reads an optional boolean tool argument. Like mcpStringArg, a JSON
// null is treated as absent.
func mcpBoolArg(arguments map[string]any, name string) (bool, *mcp.CallToolResult) {
	raw, ok := arguments[name]
	if !ok || raw == nil {
		return false, nil
	}
	b, ok := raw.(bool)
	if !ok {
		return false, mcpToolError(ErrCodeInvalidArgument, fmt.Sprintf("%s argument must be a boolean", name), map[string]any{"argument": name})
	}
	return b, nil
}

// mcpIntArg reads an optional integer tool argument (JSON numbers arrive as
// float64). It reports whether the argument was set; a JSON null is treated as
// absent.
func mcpIntArg(arguments map[string]any, name string) (int, bool, *mcp.CallToolResult) {
	raw, ok := arguments[name]
	if !ok || raw == nil {
		return 0, false, nil
	}
	switch v := raw.(type) {
	case float64:
		if v != float64(int(v)) {
			return 0, false, mcpToolError(ErrCodeInvalidArgument, fmt.Sprintf("%s argument must be an integer", name), map[string]any{"argument": name})
		}
		return int(v), true, nil
	case int:
		return v, true, nil
	default:
		return 0, false, mcpToolError(ErrCodeInvalidArgument, fmt.Sprintf("%s argument must be an integer", name), map[string]any{"argument": name})
	}
}

// jsonMarshal is a package-level var so tests can inject marshal failures.
var jsonMarshal = json.Marshal

type scanCtxState struct {
	ctx    context.Context
	cancel context.CancelFunc
	count  int

	// done is closed after val and err are set by the generation's single
	// execution.
	done chan struct{}
	val  interface{}
	err  error
}

type KubescapeMcpserver struct {
	scanResults scanResultStore
	s           *server.MCPServer
	ksClientMu  sync.Mutex
	ksClient    spdxv1beta1.SpdxV1beta1Interface
	// ksClientInit overrides newKsClient for this server instance; used by
	// tests. Nil means use newKsClient.
	ksClientInit   func() (spdxv1beta1.SpdxV1beta1Interface, error)
	k8sClientMu    sync.Mutex
	k8sClient      *k8sinterface.KubernetesApi
	policyGetterMu sync.Mutex
	policyGetter   getter.IPolicyGetter
	scanSemMu      sync.Mutex
	scanSem        *semaphore.Weighted
	scanCtxMu      sync.Mutex
	scanCtxs       map[string]*scanCtxState

	// storageToolList holds storage's read tools; see storageTools.
	storageToolsOnce sync.Once
	storageToolList  []server.ServerTool

	// policyReady is closed once the startup policy load has finished. It is
	// nil for a server that was given its policyGetter directly, which is
	// ready by definition. See startPolicyLoad.
	policyReady chan struct{}
	// policyReadyWait bounds how long a tool call waits for policyReady.
	// Zero means defaultPolicyReadyWait.
	policyReadyWait time.Duration

	// work tracks in-flight MCP work so shutdown can drain, cancel and join
	// it. See workLifecycle.
	work workLifecycle

	// workspaceDir is the allowed root directory for local file scans.
	// Empty means unconstrained mode.
	workspaceDir  string
	workspaceRoot *os.Root
}

// getPolicyGetter lazily constructs policyGetter on first use, guarded so
// concurrent MCP tool calls can't race on the check-then-set (the underlying
// server dispatches each request on its own goroutine, same reason the
// ksClient/k8sClient/scanSem/scanCtxs fields on this struct are already
// guarded - this field wasn't, which was a real data race: go test -race
// flags concurrent calls immediately, see #3444). A plain mutex, not
// sync.Once, because mcpServerEntrypoint pre-populates policyGetter directly
// in the struct literal and warms it via SetRegoObjectsWithFallback before
// any tool call can reach this method - sync.Once wouldn't know that
// initialization already happened, and would discard the warmed instance on
// the first concurrent call.
func (ksServer *KubescapeMcpserver) getPolicyGetter() getter.IPolicyGetter {
	ksServer.policyGetterMu.Lock()
	defer ksServer.policyGetterMu.Unlock()
	if ksServer.policyGetter == nil {
		ksServer.policyGetter = getter.NewDownloadReleasedPolicy()
	}
	return ksServer.policyGetter
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
// Scans are additionally limited to the scan semaphore's capacity.
func (ksServer *KubescapeMcpserver) doScanChan(ctx context.Context, key string, scanFunc func(context.Context) (interface{}, error)) (interface{}, error) {
	return ksServer.doSharedChan(ctx, key, true, scanFunc)
}

// doSharedChan is the coordination core behind doScanChan: overlapping calls
// with the same key join one execution, each caller can stop waiting on its
// own, and the execution's context is cancelled once no caller is left. When
// limited is true the execution first takes a scan-semaphore slot; analysis
// tools pass false so cheap read-only requests never queue behind scans.
func (ksServer *KubescapeMcpserver) doSharedChan(ctx context.Context, key string, limited bool, scanFunc func(context.Context) (interface{}, error)) (interface{}, error) {
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
			done:   make(chan struct{}),
		}
		ksServer.scanCtxs[key] = state
		// A generation owns exactly one execution, started here while
		// scanCtxMu is held, so a joiner can never start a second one for the
		// same generation. The execution outlives callers that stop waiting,
		// so it is tracked for shutdown to join, and registered before the
		// last caller can leave: shutdown must not see the lifecycle idle
		// while it is pending. The execution goroutine ends it exactly once.
		ksServer.work.beginShared()
		go ksServer.runShared(key, state, limited, scanFunc)
	}
	state.count++
	ksServer.scanCtxMu.Unlock()

	defer func() {
		ksServer.scanCtxMu.Lock()
		defer ksServer.scanCtxMu.Unlock()
		state.count--
		if state.count <= 0 {
			state.cancel()
			// A finished execution already removed itself; only drop the
			// entry if it still belongs to this generation.
			if ksServer.scanCtxs[key] == state {
				delete(ksServer.scanCtxs, key)
			}
		}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-state.done:
		return state.val, state.err
	}
}

// runShared is the single execution of one shared generation. It publishes the
// result to every caller of the generation through state.done and, once it has
// returned, retires the generation so later callers start a fresh execution
// instead of reusing a finished result.
func (ksServer *KubescapeMcpserver) runShared(key string, state *scanCtxState, limited bool, scanFunc func(context.Context) (interface{}, error)) {
	defer ksServer.work.end()
	defer func() {
		ksServer.scanCtxMu.Lock()
		if ksServer.scanCtxs[key] == state {
			delete(ksServer.scanCtxs, key)
		}
		ksServer.scanCtxMu.Unlock()
		state.cancel()
		close(state.done)
	}()
	if limited {
		sem := ksServer.getScanSem()
		if err := sem.Acquire(state.ctx, 1); err != nil {
			state.err = err
			return
		}
		defer sem.Release(1)
	}
	state.val, state.err = scanFunc(state.ctx)
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
			return mcpToolError(ErrCodeInvalidArgument, "arguments must be a JSON object", nil), nil
		}
		if args == nil {
			args = map[string]any{}
		}
		res, err := ksServer.CallTool(ctx, name, args)
		if err != nil {
			code := classifyScanError(err)
			msg := classifyScanErrorMessage(code, name, err)
			return mcpToolError(code, msg, nil), nil
		}
		return res, nil
	}
}

func createVulnerabilityToolsAndResources(ksServer *KubescapeMcpserver) {
	// The read tools on stored data are storage's (storage_tools.go). They
	// dispatch through toolHandler and CallTool like every other tool.
	for _, t := range ksServer.storageTools() {
		ksServer.s.AddTool(t.Tool, ksServer.toolHandler(t.Tool.Name))
	}

	vulnerabilityManifestTemplate := mcp.NewResourceTemplate(
		"kubescape://vulnerability-manifests/{namespace}/{manifest_name}",
		"Vulnerability Manifest",
		mcp.WithTemplateDescription("Complete vulnerability manifest either for a specific workload or image. Use 'list_vulnerability_manifests' tool to discover available manifests."),
		mcp.WithTemplateMIMEType("application/json"),
	)

	ksServer.s.AddResourceTemplate(vulnerabilityManifestTemplate, ksServer.ReadResource)

}

func createConfigurationsToolsAndResources(ksServer *KubescapeMcpserver) {
	listConfigSummariesTool := mcp.NewTool(
		"list_configuration_security_scan_summaries",
		mcp.WithDescription("List configuration scan results per resource: the failed controls (ID and severity) and the number of controls by status. Summaries are stored on every install; the full manifests behind get_configuration_security_scan_manifest are stored only when continuous scanning is enabled. kind, name and workload_namespace identify the scanned resource; for RBAC subjects the exact name is not stored, so name_label gives the name as a label value instead (at most 63 characters, may differ from the real name). Use list_controls for what a control checks."),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithString("namespace",
			mcp.Description("Filter by namespace (optional, default all namespaces). A workload's summary is stored in the workload's namespace; summaries of cluster-scoped and RBAC resources are in 'kubescape'"),
		),
		mcp.WithString("min_severity",
			mcp.Description("Only list failed controls at or above this severity, and only resources that have one: Critical, High, Medium or Low (optional). A page can then be empty while continue is set"),
		),
		mcp.WithString("continue",
			mcp.Description("Optional Kubernetes continuation token for pagination"),
		),
	)

	ksServer.s.AddTool(listConfigSummariesTool, ksServer.toolHandler(listConfigSummariesTool.Name))

	configManifestTemplate := mcp.NewResourceTemplate(
		"kubescape://configuration-manifests/{namespace}/{manifest_name}",
		"Configuration Security Scan Manifest",
		mcp.WithTemplateDescription("Complete configuration scan manifest for a specific workload. Use 'list_configuration_security_scan_manifests' tool to discover available manifests."),
		mcp.WithTemplateMIMEType("application/json"),
	)

	ksServer.s.AddResourceTemplate(configManifestTemplate, ksServer.ReadConfigurationResource)
}

func createRuntimeToolsAndResources(ksServer *KubescapeMcpserver) {
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
			mcp.Description("Kind of the workload (e.g., Pod, Deployment, DaemonSet, StatefulSet, ReplicaSet, Job, CronJob)."),
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

// parseControlIDsNamed extracts a list of trimmed, non-empty control IDs from an
// argument value that may be either a comma-separated string or a JSON array
// of strings, attributing errors to argName.
func parseControlIDsNamed(argName string, raw any, present bool) ([]string, *mcp.CallToolResult) {
	if !present {
		return nil, mcpToolError(ErrCodeInvalidArgument, fmt.Sprintf("%s argument is required", argName), map[string]any{"argument": argName})
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
				return nil, mcpToolError(ErrCodeInvalidArgument, fmt.Sprintf("%s array elements must be strings", argName), map[string]any{"argument": argName})
			}
			if s = strings.TrimSpace(s); s != "" {
				ids = append(ids, s)
			}
		}
	default:
		return nil, mcpToolError(ErrCodeInvalidArgument, fmt.Sprintf("%s must be a comma-separated string or array", argName), map[string]any{"argument": argName})
	}
	if len(ids) == 0 {
		return nil, mcpToolError(ErrCodeInvalidArgument, fmt.Sprintf("%s must contain at least one control ID", argName), map[string]any{"argument": argName})
	}
	return ids, nil
}

// canonicalControlKey formats control IDs into a deterministic, query-escaped,
// sorted and deduplicated string for tool cache keys.
func canonicalControlKey(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	seen := make(map[string]struct{}, len(ids))
	sorted := make([]string, 0, len(ids))
	for _, id := range ids {
		trimmed := strings.TrimSpace(id)
		if trimmed == "" {
			continue
		}
		upper := strings.ToUpper(trimmed)
		if _, ok := seen[upper]; !ok {
			seen[upper] = struct{}{}
			sorted = append(sorted, upper)
		}
	}
	sort.Strings(sorted)
	return url.QueryEscape(strings.Join(sorted, ","))
}

// canonicalFrameworkName normalizes framework names to lowercase and applies
// the given default when the framework is omitted or empty.
func canonicalFrameworkName(framework, defaultName string) string {
	trimmed := strings.TrimSpace(framework)
	if trimmed == "" {
		return strings.ToLower(defaultName)
	}
	return strings.ToLower(trimmed)
}

// scanLocalIaCKey builds the coalescing cache key for scan_local_iac.
func scanLocalIaCKey(path, framework, suffix string) string {
	return fmt.Sprintf("scan_local_iac:%s:%s%s", url.QueryEscape(path), url.QueryEscape(canonicalFrameworkName(framework, "nsa")), suffix)
}

// scanLocalIaCControlsKey builds the coalescing cache key for scan_local_iac_controls.
func scanLocalIaCControlsKey(path string, controlIDs []string, suffix string) string {
	return fmt.Sprintf("scan_local_iac_controls:%s:%s%s", url.QueryEscape(path), canonicalControlKey(controlIDs), suffix)
}

// scanManifestKey builds the coalescing cache key for scan_manifest.
func scanManifestKey(manifest, framework string, controlIDs []string, suffix string) string {
	canonicalFramework := ""
	if len(controlIDs) == 0 {
		canonicalFramework = canonicalFrameworkName(framework, "nsa")
	}
	h := sha256.Sum256([]byte(manifest))
	return fmt.Sprintf("scan_manifest:%x:%s:%s%s", h[:8], url.QueryEscape(canonicalFramework), canonicalControlKey(controlIDs), suffix)
}

// scanFrameworkKey builds the coalescing cache key for run_framework_security_scan.
func scanFrameworkKey(namespace, frameworkName, suffix string) string {
	if namespace == "*" {
		namespace = ""
	}
	return fmt.Sprintf("framework_scan:%s:%s%s", url.QueryEscape(namespace), url.QueryEscape(strings.ToLower(frameworkName)), suffix)
}

// scanControlsKey builds the coalescing cache key for scan_controls.
func scanControlsKey(namespace string, controlIDs []string, suffix string) string {
	if namespace == "*" {
		namespace = ""
	}
	return fmt.Sprintf("control_scan:%s:%s%s", url.QueryEscape(namespace), canonicalControlKey(controlIDs), suffix)
}

// scanWorkloadKey builds the coalescing cache key for scan_workload.
func scanWorkloadKey(workload, namespace, path, framework, suffix string) string {
	return fmt.Sprintf("workload_scan:%s:%s:%s:%s%s",
		url.QueryEscape(workload), url.QueryEscape(namespace),
		url.QueryEscape(path), url.QueryEscape(strings.ToLower(framework)),
		suffix)
}

// scanRBACKey builds the coalescing cache key for run_rbac_security_scan.
func scanRBACKey(namespace, suffix string) string {
	return fmt.Sprintf("rbac_scan:%s%s", namespace, suffix)
}

// scanNetworkKey builds the coalescing cache key for run_network_security_scan.
func scanNetworkKey(namespace, suffix string) string {
	return fmt.Sprintf("network_scan:%s%s", namespace, suffix)
}

// parseControlIDs extracts a list of trimmed, non-empty control IDs from an
// argument value that may be either a comma-separated string or a JSON array
// of strings. It returns a ToolResultError when the value is absent, has the
// wrong type, or yields no valid IDs after trimming.
func parseControlIDs(raw any, present bool) ([]string, *mcp.CallToolResult) {
	return parseControlIDsNamed("control_ids", raw, present)
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

// withOptionalControlIDsProperty adds control_ids to the tool schema as an optional
// property that accepts either a comma-separated string or an array of strings.
func withOptionalControlIDsProperty(desc string) mcp.ToolOption {
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

	matches := manifest.Spec.Payload.Matches
	var responseJson []byte
	if cveID == "" {
		// CVE list: pre-allocate exact capacity and index into matches to avoid copying large Match structs.
		var cveList []v1beta1.Vulnerability
		if len(matches) > 0 {
			cveList = make([]v1beta1.Vulnerability, len(matches))
			for i := range matches {
				cveList[i] = matches[i].Vulnerability
			}
		}
		responseJson, err = json.Marshal(cveList)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal cve list: %w", err)
		}
	} else {
		// CVE details
		var match []v1beta1.Match
		for i := range matches {
			if matches[i].Vulnerability.ID == cveID {
				match = append(match, matches[i])
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

// CallTool executes the named MCP tool with the supplied arguments.
func (ksServer *KubescapeMcpserver) CallTool(ctx context.Context, name string, arguments map[string]any) (*mcp.CallToolResult, error) {
	if res, ok, err := ksServer.callStorageTool(ctx, name, arguments); ok {
		return res, err
	}
	switch name {
	case "get_scan_results":
		return ksServer.getScanResults(ctx, arguments)
	case "run_rbac_security_scan":
		namespace, err := mcpScanNamespace(arguments)
		if err != nil {
			return mcpToolError(ErrCodeInvalidArgument, err.Error(), map[string]any{"argument": "namespace"}), nil
		}
		filters, toolErr := parseScanFilterArgs(arguments, namespace)
		if toolErr != nil {
			return toolErr, nil
		}
		key := scanRBACKey(namespace, filters.keySuffix())
		v, err := ksServer.doResultScan(ctx, key, func(scanCtx context.Context) (interface{}, error) {
			return rbacScanFn(ksServer, scanCtx, namespace, filters)
		}, filters.limit)
		if err != nil {
			code := classifyScanError(err)
			msg := classifyScanErrorMessage(code, "RBAC", err)
			return mcpToolError(code, msg, nil), nil
		}
		responseBytes := v.([]byte)
		return mcp.NewToolResultText(string(responseBytes)), nil
	case "scan_local_iac":
		path, toolErr := mcpRequiredStringArg(arguments, "path")
		if toolErr != nil {
			return toolErr, nil
		}
		framework, toolErr := mcpStringArg(arguments, "framework")
		if toolErr != nil {
			return toolErr, nil
		}
		filters, toolErr := parseLocalIaCFilterArgs(arguments)
		if toolErr != nil {
			return toolErr, nil
		}

		key := scanLocalIaCKey(path, framework, filters.keySuffix())
		v, err := ksServer.doResultScan(ctx, key, func(scanCtx context.Context) (interface{}, error) {
			return localIaCScanFn(ksServer, scanCtx, path, framework, filters)
		}, filters.limit)
		if err != nil {
			code := classifyScanError(err)
			msg := classifyScanErrorMessage(code, "IaC", err)
			return mcpToolError(code, msg, nil), nil
		}
		responseBytes := v.([]byte)
		return mcp.NewToolResultText(string(responseBytes)), nil
	case "scan_local_iac_controls":
		path, toolErr := mcpRequiredStringArg(arguments, "path")
		if toolErr != nil {
			return toolErr, nil
		}
		rawControlIDs, hasControlIDs := arguments["control_ids"]
		controlIDs, toolErr := parseControlIDs(rawControlIDs, hasControlIDs)
		if toolErr != nil {
			return toolErr, nil
		}
		filters, toolErr := parseLocalIaCFilterArgs(arguments)
		if toolErr != nil {
			return toolErr, nil
		}
		key := scanLocalIaCControlsKey(path, controlIDs, filters.keySuffix())
		v, err := ksServer.doResultScan(ctx, key, func(scanCtx context.Context) (interface{}, error) {
			return localIaCControlsScanFn(ksServer, scanCtx, path, controlIDs, filters)
		}, filters.limit)
		if err != nil {
			code := classifyScanError(err)
			msg := classifyScanErrorMessage(code, "IaC control", err)
			return mcpToolError(code, msg, nil), nil
		}
		return mcp.NewToolResultText(string(v.([]byte))), nil
	case "scan_manifest":
		rawManifest, ok := arguments["manifest"]
		if !ok || rawManifest == nil {
			return mcpToolError(ErrCodeInvalidArgument, "manifest argument is required and cannot be empty", map[string]any{"argument": "manifest"}), nil
		}
		manifest, ok := rawManifest.(string)
		if !ok {
			return mcpToolError(ErrCodeInvalidArgument, "manifest argument must be a string", map[string]any{"argument": "manifest"}), nil
		}
		if len(strings.TrimSpace(manifest)) == 0 {
			return mcpToolError(ErrCodeInvalidArgument, "manifest argument cannot be empty", map[string]any{"argument": "manifest"}), nil
		}
		if len(manifest) > maxManifestBytes {
			return mcpToolError(ErrCodeInvalidArgument, fmt.Sprintf("manifest argument exceeds maximum allowed size of %d bytes", maxManifestBytes), map[string]any{"argument": "manifest"}), nil
		}
		framework, toolErr := mcpStringArg(arguments, "framework")
		if toolErr != nil {
			return toolErr, nil
		}
		var controlIDs []string
		if rawControlIDs, hasControlIDs := arguments["control_ids"]; hasControlIDs && rawControlIDs != nil {
			controlIDs, toolErr = parseControlIDs(rawControlIDs, hasControlIDs)
			if toolErr != nil {
				return toolErr, nil
			}
		}
		filters, toolErr := parseLocalIaCFilterArgs(arguments)
		if toolErr != nil {
			return toolErr, nil
		}

		key := scanManifestKey(manifest, framework, controlIDs, filters.keySuffix())
		v, err := ksServer.doResultScan(ctx, key, func(scanCtx context.Context) (interface{}, error) {
			return manifestScanFn(ksServer, scanCtx, manifest, framework, controlIDs, filters)
		}, filters.limit)
		if err != nil {
			code := classifyScanError(err)
			msg := classifyScanErrorMessage(code, "manifest", err)
			return mcpToolError(code, msg, nil), nil
		}
		return mcp.NewToolResultText(string(v.([]byte))), nil
	case "apply_remediation", "suggest_fix":
		return ksServer.handleRemediationTool(ctx, name, arguments)
	case "verify_remediation":
		path, toolErr := mcpRequiredStringArg(arguments, "path")
		if toolErr != nil {
			return toolErr, nil
		}
		items, toolErr := parseVerifyItems(arguments)
		if toolErr != nil {
			return toolErr, nil
		}
		if len(items) == 0 {
			// Nothing to verify, so there is nothing to scan for.
			resBytes, err := json.MarshalIndent(verifyResponse{Results: []verifyResult{}}, "", "  ")
			if err != nil {
				return mcpToolError(ErrCodeMarshalError, fmt.Sprintf("failed to marshal result: %v", err), nil), nil
			}
			return mcp.NewToolResultText(string(resBytes)), nil
		}
		controlIDs := verifyControlIDs(items)
		v, err := ksServer.doScanChan(ctx, verifyScanKey(path, controlIDs), func(scanCtx context.Context) (interface{}, error) {
			return iacScanReportFn(ksServer, scanCtx, path, controlIDs)
		})
		if err != nil {
			code := classifyScanError(err)
			msg := fmt.Sprintf("failed to rescan for verification: %v", err)
			return mcpToolError(code, msg, nil), nil
		}
		resBytes, err := verifyRemediationReport(v.(*iacScanOutcome), items)
		if err != nil {
			return mcpToolError(ErrCodeScanFailed, err.Error(), nil), nil
		}
		return mcp.NewToolResultText(string(resBytes)), nil
	case webhookCoverageToolName:
		return ksServer.callWebhookCoverage(ctx, arguments)
	case "run_network_security_scan":
		namespace, err := mcpScanNamespace(arguments)
		if err != nil {
			return mcpToolError(ErrCodeInvalidArgument, err.Error(), map[string]any{"argument": "namespace"}), nil
		}
		filters, toolErr := parseScanFilterArgs(arguments, namespace)
		if toolErr != nil {
			return toolErr, nil
		}
		key := scanNetworkKey(namespace, filters.keySuffix())
		v, err := ksServer.doResultScan(ctx, key, func(scanCtx context.Context) (interface{}, error) {
			return networkScanFn(ksServer, scanCtx, namespace, filters)
		}, filters.limit)
		if err != nil {
			code := classifyScanError(err)
			msg := classifyScanErrorMessage(code, "Network", err)
			return mcpToolError(code, msg, nil), nil
		}
		responseBytes := v.([]byte)
		return mcp.NewToolResultText(string(responseBytes)), nil
	case "list_configuration_security_scan_summaries":
		namespaceStr, toolErr := mcpStringArg(arguments, "namespace")
		if toolErr != nil {
			return toolErr, nil
		}
		if namespaceStr == "" {
			namespaceStr = metav1.NamespaceAll
		}
		minSeverity, toolErr := parseControlMinSeverity(arguments)
		if toolErr != nil {
			return toolErr, nil
		}
		continueToken, toolErr := mcpStringArg(arguments, "continue")
		if toolErr != nil {
			return toolErr, nil
		}
		client, ksErr := ksServer.getKsClient()
		if ksErr != nil {
			return mcpToolError(ErrCodeK8sClientError, fmt.Sprintf("failed to connect to Kubernetes cluster: %v", ksErr), nil), nil
		}
		// Storage lists only metadata unless asked for the full spec.
		chunk, err := client.WorkloadConfigurationScanSummaries(namespaceStr).List(ctx, metav1.ListOptions{ResourceVersion: softwarecomposition.ResourceVersionFullSpec, Limit: 100, Continue: continueToken})
		if err != nil {
			return mcpToolError(classifyScanError(err), fmt.Sprintf("failed to list configuration scan summaries: %v", err), nil), nil
		}
		responseJson, err := json.Marshal(configScanSummaryListResponse{Summaries: listConfigScanSummaryEntries(chunk.Items, minSeverity), Continue: chunk.GetContinue()})
		if err != nil {
			return nil, fmt.Errorf("failed to marshal configuration scan summaries: %w", err)
		}
		return mcp.NewToolResultText(string(responseJson)), nil
	case "get_configuration_drift":
		namespaceStr, toolErr := mcpStringArg(arguments, "namespace")
		if toolErr != nil {
			return toolErr, nil
		}
		if namespaceStr == "" {
			namespaceStr = "default"
		}
		profileNameStr, toolErr := mcpRequiredStringArg(arguments, "profile_name")
		if toolErr != nil {
			return toolErr, nil
		}
		workloadNameStr, toolErr := mcpRequiredStringArg(arguments, "workload_name")
		if toolErr != nil {
			return toolErr, nil
		}
		workloadKindStr, toolErr := mcpRequiredStringArg(arguments, "workload_kind")
		if toolErr != nil {
			return toolErr, nil
		}

		ksClient, ksErr := ksServer.getKsClient()
		if ksErr != nil {
			return mcpToolError(ErrCodeK8sClientError, fmt.Sprintf("failed to connect to storage client: %v", ksErr), nil), nil
		}
		profile, err := ksClient.ContainerProfiles(namespaceStr).Get(ctx, profileNameStr, metav1.GetOptions{})
		if err != nil {
			return mcpToolError(
				classifyScanError(err),
				fmt.Sprintf("failed to get container profile: %v", err),
				map[string]any{
					"resource_type": "ContainerProfile",
					"namespace":     namespaceStr,
					"name":          profileNameStr,
				},
			), nil
		}

		var rawManifest []byte
		var workloadObj any
		k8sClient, k8sErr := ksServer.getK8sClient()
		if k8sErr != nil {
			return mcpToolError(ErrCodeK8sClientError, fmt.Sprintf("failed to connect to Kubernetes cluster: %v", k8sErr), nil), nil
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
		case "replicaset":
			workloadObj, err = k8sClient.KubernetesClient.AppsV1().ReplicaSets(namespaceStr).Get(ctx, workloadNameStr, metav1.GetOptions{})
		case "job":
			workloadObj, err = k8sClient.KubernetesClient.BatchV1().Jobs(namespaceStr).Get(ctx, workloadNameStr, metav1.GetOptions{})
		case "cronjob":
			workloadObj, err = k8sClient.KubernetesClient.BatchV1().CronJobs(namespaceStr).Get(ctx, workloadNameStr, metav1.GetOptions{})
		default:
			return mcpToolError(ErrCodeUnsupportedResource, fmt.Sprintf("unsupported workload kind: %s", workloadKindStr), map[string]any{"kind": workloadKindStr}), nil
		}

		if err != nil {
			return mcpToolError(
				classifyScanError(err),
				fmt.Sprintf("failed to get workload manifest: %v", err),
				map[string]any{
					"resource_type": strings.ToLower(workloadKindStr),
					"namespace":     namespaceStr,
					"name":          workloadNameStr,
				},
			), nil
		}
		rawManifest, err = jsonMarshal(workloadObj)
		if err != nil {
			return mcpToolError(ErrCodeMarshalError, fmt.Sprintf("failed to marshal workload manifest: %v", err), nil), nil
		}

		containerName := ""
		if profile.GetLabels() != nil {
			containerName = profile.GetLabels()["kubescape.io/workload-container-name"]
			profileKind := profile.GetLabels()["kubescape.io/workload-kind"]
			profileName := profile.GetLabels()["kubescape.io/workload-name"]

			if profileKind != "" && !strings.EqualFold(profileKind, workloadKindStr) {
				return mcpToolError(ErrCodeInvalidArgument, fmt.Sprintf("profile workload kind mismatch: expected %s, got %s", workloadKindStr, profileKind), map[string]any{"expected_kind": workloadKindStr, "got_kind": profileKind}), nil
			}
			if profileName != "" && profileName != workloadNameStr {
				return mcpToolError(ErrCodeInvalidArgument, fmt.Sprintf("profile workload name mismatch: expected %s, got %s", workloadNameStr, profileName), map[string]any{"expected_name": workloadNameStr, "got_name": profileName}), nil
			}
		}
		fixes := fixhandler.DetectProfileDrift(rawManifest, profile, workloadKindStr, containerName, 0)
		fixesJson, err := json.MarshalIndent(fixes, "", "  ")
		if err != nil {
			return mcpToolError(ErrCodeMarshalError, fmt.Sprintf("failed to marshal drift result: %v", err), nil), nil
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
		namespace, err := mcpScanNamespace(arguments)
		if err != nil {
			return mcpToolError(ErrCodeInvalidArgument, err.Error(), map[string]any{"argument": "namespace"}), nil
		}
		frameworkNameStr, toolErr := mcpRequiredStringArg(arguments, "framework_name")
		if toolErr != nil {
			return toolErr, nil
		}
		filters, toolErr := parseScanFilterArgs(arguments, namespace)
		if toolErr != nil {
			return toolErr, nil
		}
		key := scanFrameworkKey(namespace, frameworkNameStr, filters.keySuffix())
		v, err := ksServer.doResultScan(ctx, key, func(scanCtx context.Context) (interface{}, error) {
			return frameworkScanFn(ksServer, scanCtx, namespace, frameworkNameStr, filters)
		}, filters.limit)
		if err != nil {
			code := classifyScanError(err)
			msg := classifyScanErrorMessage(code, "framework", err)
			return mcpToolError(code, msg, nil), nil
		}
		responseBytes := v.([]byte)
		return mcp.NewToolResultText(string(responseBytes)), nil
	case "scan_controls":
		namespace, err := mcpScanNamespace(arguments)
		if err != nil {
			return mcpToolError(ErrCodeInvalidArgument, err.Error(), map[string]any{"argument": "namespace"}), nil
		}
		filters, toolErr := parseScanFilterArgs(arguments, namespace)
		if toolErr != nil {
			return toolErr, nil
		}
		rawControlIDs, hasControlIDs := arguments["control_ids"]
		controlIDs, toolErr := parseControlIDs(rawControlIDs, hasControlIDs)
		if toolErr != nil {
			return toolErr, nil
		}
		key := scanControlsKey(namespace, controlIDs, filters.keySuffix())
		v, err := ksServer.doResultScan(ctx, key, func(scanCtx context.Context) (interface{}, error) {
			return controlsScanFn(ksServer, scanCtx, namespace, controlIDs, filters)
		}, filters.limit)
		if err != nil {
			code := classifyScanError(err)
			msg := classifyScanErrorMessage(code, "control", err)
			return mcpToolError(code, msg, controlSelectionErrorDetails(code, err)), nil
		}
		return mcp.NewToolResultText(string(v.([]byte))), nil
	case "validate_scan_selection":
		rawControlIDs, hasControlIDs := arguments["control_ids"]
		controlIDs, toolErr := parseControlIDs(rawControlIDs, hasControlIDs)
		if toolErr != nil {
			return toolErr, nil
		}
		result, err := ksServer.ValidateScanSelection(ctx, controlIDs)
		if err != nil {
			return mcpToolError(classifyScanError(err), fmt.Sprintf("failed to validate scan selection: %v", err), nil), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	case "scan_workload":
		workload, toolErr := mcpRequiredStringArg(arguments, "workload")
		if toolErr != nil {
			return toolErr, nil
		}
		// Read namespace with mcpStringArg rather than mcpScanNamespace: this
		// tool has a second source of namespace (the workload identifier), so it
		// has to tell an omitted argument from an explicit "*". mcpScanNamespace
		// collapses the two. buildWorkloadScanRequest resolves the precedence.
		namespace, toolErr := mcpStringArg(arguments, "namespace")
		if toolErr != nil {
			return toolErr, nil
		}
		path, toolErr := mcpStringArg(arguments, "path")
		if toolErr != nil {
			return toolErr, nil
		}
		framework, toolErr := mcpStringArg(arguments, "framework")
		if toolErr != nil {
			return toolErr, nil
		}
		filters, toolErr := parseScanFilterArgs(arguments, namespace)
		if toolErr != nil {
			return toolErr, nil
		}
		// Every component here is caller-supplied, so each is escaped: an
		// unescaped separator in one argument could otherwise collide with a
		// different request's key and serve it that scan's results.
		key := scanWorkloadKey(workload, namespace, path, framework, filters.keySuffix())
		v, err := ksServer.doResultScan(ctx, key, func(scanCtx context.Context) (interface{}, error) {
			return workloadScanFn(ksServer, scanCtx, workload, namespace, path, framework, filters)
		}, filters.limit)
		if err != nil {
			code := classifyScanError(err)
			msg := classifyScanErrorMessage(code, "workload", err)
			var extra map[string]any
			var hinted interface{ Hint() string }
			if errors.As(err, &hinted) && code == ErrCodeResourceNotFound {
				msg = fmt.Sprintf("%s (%s)", msg, hinted.Hint())
				extra = map[string]any{"hint": hinted.Hint()}
			}
			return mcpToolError(code, msg, extra), nil
		}
		return mcp.NewToolResultText(string(v.([]byte))), nil
	case "list_frameworks":
		search, toolErr := mcpStringArg(arguments, "search")
		if toolErr != nil {
			return toolErr, nil
		}
		result, err := ksServer.ListFrameworks(ctx, search)
		if err != nil {
			return mcpToolError(classifyScanError(err), fmt.Sprintf("failed to list frameworks: %v", err), nil), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	case "list_controls_config":
		controlID, toolErr := mcpStringArg(arguments, "control_id")
		if toolErr != nil {
			return toolErr, nil
		}
		search, toolErr := mcpStringArg(arguments, "search")
		if toolErr != nil {
			return toolErr, nil
		}
		result, err := ksServer.ListControlsConfig(ctx, search, controlID)
		if err != nil {
			return mcpToolError(classifyScanError(err), fmt.Sprintf("failed to list controls config: %v", err), nil), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	case "list_controls":
		framework, toolErr := mcpStringArg(arguments, "framework")
		if toolErr != nil {
			return toolErr, nil
		}
		search, toolErr := mcpStringArg(arguments, "search")
		if toolErr != nil {
			return toolErr, nil
		}
		limit := defaultControlsListLimit
		if requestedLimit, set, argErr := mcpIntArg(arguments, "limit"); argErr != nil {
			return argErr, nil
		} else if set {
			if requestedLimit < 1 || requestedLimit > maxControlsListLimit {
				return mcpToolError(ErrCodeInvalidArgument,
					fmt.Sprintf("limit must be between 1 and %d", maxControlsListLimit),
					map[string]any{"argument": "limit"}), nil
			}
			limit = requestedLimit
		}
		offset, _, toolErr := mcpIntArg(arguments, "offset")
		if toolErr != nil {
			return toolErr, nil
		}
		if offset < 0 {
			return mcpToolError(ErrCodeInvalidArgument, "offset must not be negative", map[string]any{"argument": "offset"}), nil
		}
		result, err := ksServer.ListControls(ctx, framework, search, limit, offset)
		var unknown *unknownFrameworkError
		if errors.As(err, &unknown) {
			return mcpToolError(ErrCodeInvalidArgument, err.Error(),
				map[string]any{"argument": "framework", "supported_values": unknown.supported}), nil
		}
		if err != nil {
			return mcpToolError(classifyScanError(err), fmt.Sprintf("failed to list controls: %v", err), nil), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	case "list_admission_policies":
		result, err := ksServer.ListAdmissionPolicies(ctx)
		if err != nil {
			return mcpToolError(classifyScanError(err), fmt.Sprintf("failed to list admission policies: %v", err), nil), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	case "create_admission_policy_binding":
		return ksServer.CreateAdmissionPolicyBinding(ctx, arguments)
	case "generate_vap":
		return ksServer.GenerateVAP(ctx, arguments)
	case "explain_control":
		return ksServer.ExplainControl(ctx, arguments)
	default:
		return nil, fmt.Errorf("unknown tool: %s", name)
	}
}

// registerTools adds every Kubescape tool and resource to ksServer's MCP
// server. It only registers definitions; it starts no transport and contacts
// no cluster, so tests can use it to enumerate the served tool surface.
func registerTools(ksServer *KubescapeMcpserver) {
	createScanResultsTool(ksServer)
	createVulnerabilityToolsAndResources(ksServer)
	createConfigurationsToolsAndResources(ksServer)
	createRuntimeToolsAndResources(ksServer)
	createRBACScanningTools(ksServer)
	createNetworkScanningTools(ksServer)
	createNetworkReachabilityTools(ksServer)
	createWebhookCoverageTools(ksServer)
	createMutatingAdmissionPolicyTools(ksServer)
	createVulnerabilityExposureTools(ksServer)
	createServiceExposureTools(ksServer)
	createPSSPredictorTools(ksServer)
	createRBACEscalationTools(ksServer)
	createDiffReportsTools(ksServer)
	createFrameworkScanningTools(ksServer)
	createIaCScanningTools(ksServer)
	createIaCControlScanningTool(ksServer)
	createManifestScanningTool(ksServer)
	createRemediationTools(ksServer)
	createSuggestFixTools(ksServer)
	createVerifyRemediationTools(ksServer)
	createControlScanningTools(ksServer)
	createWorkloadScanningTools(ksServer)
	createPolicyListingTools(ksServer)
	createAdvancedTools(ksServer)
	createSecretExposureTools(ksServer)
	createExplainControlTools(ksServer)
}

// validateMCPOptions validates and normalizes the transport and port arguments before
// starting the server or launching background tasks.
func validateMCPOptions(transport string, port int) (string, error) {
	normTransport := strings.ToLower(strings.TrimSpace(transport))
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid port %d: must be between 1 and 65535", port)
	}
	switch normTransport {
	case "sse", "stdio":
		return normTransport, nil
	default:
		return "", fmt.Errorf("unsupported transport '%s': must be 'sse' or 'stdio'", transport)
	}
}

func mcpServerEntrypoint(ctx context.Context, transport string, port int, workspaceOpt ...string) error {
	normTransport, err := validateMCPOptions(transport, port)
	if err != nil {
		return err
	}
	transport = normTransport

	var workspace string
	var workspaceRoot *os.Root
	if len(workspaceOpt) > 0 && strings.TrimSpace(workspaceOpt[0]) != "" {
		workspace = workspaceOpt[0]
	} else if envWorkspace := os.Getenv("KUBESCAPE_WORKSPACE_DIR"); strings.TrimSpace(envWorkspace) != "" {
		workspace = envWorkspace
	}
	if workspace != "" {
		canonWorkspace, err := pathcontainment.ResolveBaseDir(workspace)
		if err != nil {
			return fmt.Errorf("failed to resolve workspace directory %q: %w", workspace, err)
		}
		workspace = canonWorkspace
		workspaceRoot, err = os.OpenRoot(workspace)
		if err != nil {
			return fmt.Errorf("failed to open workspace directory %q: %w", workspace, err)
		}
		defer workspaceRoot.Close()
		logger.L().Info("Workspace root containment enabled", helpers.String("workspace", workspace))
	} else {
		logger.L().Warning("No --workspace configured: local IaC scans will run in unconstrained mode")
	}

	logger.L().Info("Starting MCP server...")

	// ksServer is created below, once the MCP server exists; the lifecycle
	// middleware only dereferences it when a request arrives.
	var ksServer *KubescapeMcpserver

	// Create a new MCP server. WithRecovery must stay first so it wraps the
	// tool-call recorder (which only observes a panic, never recovers it).
	serverOptions := []server.ServerOption{
		server.WithToolCapabilities(false),
		server.WithRecovery(),
	}
	serverOptions = append(serverOptions, toolCallObserverOptions(logger.L().GetLevel(), transport)...)
	serverOptions = append(serverOptions, lifecycleServerOptions(transport, func() *workLifecycle { return &ksServer.work })...)
	s := server.NewMCPServer(
		"Kubescape MCP Server",
		"0.0.1",
		serverOptions...,
	)

	drp := getter.NewDownloadReleasedPolicy()

	ksServer = &KubescapeMcpserver{
		s:             s,
		policyGetter:  drp,
		workspaceDir:  workspace,
		workspaceRoot: workspaceRoot,
	}

	// The policy bundle download can take well over a minute. Load it in the
	// background so the MCP initialize handshake and tool discovery are not
	// held up behind it; tools that need policies wait for it (see
	// readyPolicyGetter).
	ksServer.startPolicyLoad(func() getter.IPolicyGetter {
		return loadPolicyGetter(drp)
	})

	registerTools(ksServer)

	// Start the server
	switch transport {
	case "sse":
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("sse server error: %w", err)
		}
		logger.L().Info("Starting SSE server", helpers.String("addr", addr))
		if err := serveSSEUntilShutdown(ctx, newSSETransport(s, addr), ln, &ksServer.work, mcpDrainPeriod, mcpShutdownTimeout); err != nil {
			return fmt.Errorf("sse server error: %w", err)
		}
		return nil
	case "stdio":
		if err := server.ServeStdio(s); err != nil {
			return fmt.Errorf("server error: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported transport '%s': must be 'sse' or 'stdio'", transport)
	}
}

func createRBACScanningTools(ksServer *KubescapeMcpserver) {
	opts := []mcp.ToolOption{
		mcp.WithDescription("Run an on-demand, live RBAC security scan (evaluating only over-permissive cluster bindings) and return the failed resources."),
		mcp.WithString("namespace",
			mcp.Description("Namespace to scope the RBAC scan (optional, defaults to cluster-wide if omitted)"),
		),
	}
	opts = append(opts, scanFilterOptions()...)
	runRBACScanTool := mcp.NewTool("run_rbac_security_scan", opts...)
	ksServer.s.AddTool(runRBACScanTool, ksServer.toolHandler(runRBACScanTool.Name))
}

func createNetworkScanningTools(ksServer *KubescapeMcpserver) {
	opts := []mcp.ToolOption{
		mcp.WithDescription("Run an on-demand, live Network security scan (evaluating only ingress and egress block policies) and return the failed resources."),
		mcp.WithString("namespace",
			mcp.Description("Namespace to scope the Network scan (optional, defaults to cluster-wide if omitted)"),
		),
	}
	opts = append(opts, scanFilterOptions()...)
	runNetworkScanTool := mcp.NewTool("run_network_security_scan", opts...)
	ksServer.s.AddTool(runNetworkScanTool, ksServer.toolHandler(runNetworkScanTool.Name))
}

func createFrameworkScanningTools(ksServer *KubescapeMcpserver) {
	opts := []mcp.ToolOption{
		mcp.WithDescription("Run an on-demand, live Framework security scan (e.g. nsa, mitre) and return the failed resources along with the compliance score."),
		mcp.WithString("namespace",
			mcp.Description("Namespace to scope the Framework scan (optional, defaults to cluster-wide if omitted)"),
		),
		mcp.WithString("framework_name",
			mcp.Required(),
			mcp.Description("Name of the framework to scan (e.g. nsa, mitre, cis-v1.23-t1.0.1)"),
		),
	}
	opts = append(opts, scanFilterOptions()...)
	runFrameworkScanTool := mcp.NewTool("run_framework_security_scan", opts...)
	ksServer.s.AddTool(runFrameworkScanTool, ksServer.toolHandler(runFrameworkScanTool.Name))
}

func createIaCScanningTools(ksServer *KubescapeMcpserver) {
	opts := []mcp.ToolOption{
		mcp.WithDescription("Scan local Infrastructure-as-Code (Helm charts, Kustomize, YAML) for security misconfigurations"),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Absolute or relative path to the local directory or file (e.g., /path/to/helm-chart or /path/to/manifest.yaml)"),
		),
		mcp.WithString("framework",
			mcp.Description("Framework to scan against (optional, defaults to nsa)"),
		),
	}
	opts = append(opts, iacScanFilterOptions()...)
	iacScanTool := mcp.NewTool("scan_local_iac", opts...)
	ksServer.s.AddTool(iacScanTool, ksServer.toolHandler(iacScanTool.Name))
}

func createIaCControlScanningTool(ksServer *KubescapeMcpserver) {
	opts := []mcp.ToolOption{
		mcp.WithDescription("Scan local Infrastructure-as-Code (Helm charts, Kustomize, YAML) for specific controls by control ID. Use list_controls to discover valid IDs. Prefer scan_local_iac when you want full framework coverage."),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Absolute or relative path to the local directory or file (e.g., /path/to/helm-chart or /path/to/manifest.yaml)"),
		),
		withControlIDsProperty("Control IDs to scan against: a comma-separated string (e.g. \"C-0012,C-0017\") or an array of strings (e.g. [\"C-0012\",\"C-0017\"]). At least one ID is required."),
	}
	opts = append(opts, iacScanFilterOptions()...)
	iacControlScanTool := mcp.NewTool("scan_local_iac_controls", opts...)
	ksServer.s.AddTool(iacControlScanTool, ksServer.toolHandler(iacControlScanTool.Name))
}

func createManifestScanningTool(ksServer *KubescapeMcpserver) {
	opts := []mcp.ToolOption{
		mcp.WithDescription("Scan a Kubernetes YAML or JSON manifest string in memory for security misconfigurations, without requiring a file path. Supports multi-document YAML manifests."),
		mcp.WithString("manifest",
			mcp.Required(),
			mcp.Description("Raw YAML or JSON Kubernetes manifest content (can contain multiple documents separated by '---')"),
		),
		mcp.WithString("framework",
			mcp.Description("Framework to scan against (optional, defaults to nsa)"),
		),
		withOptionalControlIDsProperty("Control IDs to scan against: a comma-separated string (e.g. \"C-0012,C-0017\") or an array of strings (optional). Overrides framework when provided."),
	}
	opts = append(opts, iacScanFilterOptions()...)
	manifestScanTool := mcp.NewTool("scan_manifest", opts...)
	ksServer.s.AddTool(manifestScanTool, ksServer.toolHandler(manifestScanTool.Name))
}

func createControlScanningTools(ksServer *KubescapeMcpserver) {
	opts := []mcp.ToolOption{
		mcp.WithDescription("Run an on-demand, live security scan restricted to a given set of controls by control ID (e.g. C-0012, C-0017) and return the failed resources. Use list_controls to discover valid IDs first."),
		withControlIDsProperty("Control IDs to scan: a comma-separated string (e.g. \"C-0012,C-0017\") or an array of strings (e.g. [\"C-0012\",\"C-0017\"]). At least one ID is required."),
		mcp.WithString("namespace",
			mcp.Description("Namespace to scope the scan (optional, defaults to cluster-wide if omitted)"),
		),
	}
	opts = append(opts, scanFilterOptions()...)
	runControlScanTool := mcp.NewTool("scan_controls", opts...)
	ksServer.s.AddTool(runControlScanTool, ksServer.toolHandler(runControlScanTool.Name))
}

func createPolicyListingTools(ksServer *KubescapeMcpserver) {
	listFrameworksTool := mcp.NewTool(
		"list_frameworks",
		mcp.WithDescription("List the names of all security frameworks available for scanning (e.g. nsa, mitre, cis-v1.23-t1.0.1). Use a returned name as the framework_name argument to run_framework_security_scan."),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithString("search",
			mcp.Description("Optional substring to filter framework names case-insensitively (e.g. \"cis\")"),
		),
	)
	listControlsTool := mcp.NewTool(
		"list_controls",
		mcp.WithDescription("List the available security controls with their IDs, names, and the frameworks they belong to. Returns total, returned, truncated, and controls; pass framework or search to filter and use next_offset to request the next page. Use a returned ID as a control_ids value in scan_controls."),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithString("framework",
			mcp.Description("Only return the controls of this framework, e.g. \"NSA\" (optional, case-insensitive; see list_frameworks)"),
		),
		mcp.WithString("search",
			mcp.Description("Substring to search for in control IDs, names, or frameworks (optional, case-insensitive; e.g. \"privileged\", \"container\", \"CIS-1.1\")"),
		),
		mcp.WithNumber("limit",
			mcp.Description("Maximum number of controls to return (optional, default 100, maximum 500)"),
		),
		mcp.WithNumber("offset",
			mcp.Description("Number of controls to skip; pass the previous response's next_offset to get the next page (optional, default 0)"),
		),
	)
	listControlsConfigTool := mcp.NewTool(
		"list_controls_config",
		mcp.WithDescription("List configurable control parameters, their resolved values, descriptions, and the security controls that consume them. Pass control_id to inspect parameters affecting a specific control, or search to filter by keyword."),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithString("control_id",
			mcp.Description("Optional control ID (e.g. \"C-0016\") to only list configuration inputs read by that control"),
		),
		mcp.WithString("search",
			mcp.Description("Optional keyword to filter configuration entries by name, title, description, or control ID case-insensitively"),
		),
	)
	listAdmissionPoliciesTool := mcp.NewTool(
		"list_admission_policies",
		mcp.WithDescription("List the ValidatingAdmissionPolicies in the CEL admission policy library embedded in Kubescape, with the Kubescape control each one implements (controlID), whether it reads parameters (takesParams), its failurePolicy and the resources it matches. Read-only: it does not create, bind or apply any policy. Kubescape's ValidatingAdmissionPolicy support is experimental."),
		mcp.WithReadOnlyHintAnnotation(true),
	)
	createAdmissionPolicyBindingTool := mcp.NewTool(
		"create_admission_policy_binding",
		mcp.WithDescription("Generate a ValidatingAdmissionPolicyBinding manifest for a policy in the embedded CEL admission policy library, validated like `kubescape vap create-policy-binding`. Name the policy with exactly one of policy_name (see list_admission_policies) or control_id. Read-only: it returns the YAML in manifest and any scope warnings in warnings, and does not create or apply anything in a cluster. Kubescape's ValidatingAdmissionPolicy support is experimental."),
		mcp.WithString("binding_name", mcp.Required(), mcp.Description("Name of the binding (a DNS-1123 subdomain)")),
		mcp.WithString("policy_name", mcp.Description("Name of the ValidatingAdmissionPolicy to bind. Exactly one of policy_name or control_id is required")),
		mcp.WithString("control_id", mcp.Description("Kubescape control ID whose policy to bind (e.g. C-0016). Exactly one of policy_name or control_id is required")),
		mcp.WithArray("validation_actions", mcp.WithStringItems(), mcp.Description("Actions to take when the policy fails: Deny, Warn, Audit. Deny and Warn cannot be combined. Defaults to [\"Deny\"]")),
		mcp.WithString("parameter_reference", mcp.Description("Name of the object the policy reads as params. Required for a policy that declares a paramKind, rejected for one that declares none")),
		mcp.WithArray("namespaces", mcp.WithStringItems(), mcp.Description("Namespaces to narrow the binding to. Narrows only namespaced resources; cluster-scoped ones are never exempted")),
		mcp.WithArray("labels", mcp.WithStringItems(), mcp.Description("Object label selector entries as key=value or key==value")),
		mcp.WithArray("resource_rules", mcp.WithStringItems(), mcp.Description("Restrict the binding to group/version/resource entries the policy already matches (e.g. apps/v1/deployments, /v1/pods). Omit to bind everything the policy matches")),
		mcp.WithReadOnlyHintAnnotation(true),
	)
	generateVAPTool := mcp.NewTool(
		"generate_vap",
		mcp.WithDescription("Generate a ValidatingAdmissionPolicy manifest for a policy in the embedded CEL admission policy library, validated like `kubescape vap generate-policy`. Name the policy with exactly one of policy_name (see list_admission_policies) or control_id (e.g. C-0016). Only controls that already have a CEL/VAP implementation in the embedded library are supported; for anything else, an error is returned. Read-only: it returns the YAML in manifest and does not create or apply anything in a cluster. Kubescape's ValidatingAdmissionPolicy support is experimental."),
		mcp.WithString("control_id", mcp.Description("Kubescape control ID whose policy to generate (e.g. C-0016). Exactly one of control_id or policy_name is required")),
		mcp.WithString("policy_name", mcp.Description("Name of the ValidatingAdmissionPolicy to generate (see list_admission_policies). Exactly one of control_id or policy_name is required")),
		mcp.WithReadOnlyHintAnnotation(true),
	)
	validateScanSelectionTool := mcp.NewTool(
		"validate_scan_selection",
		mcp.WithDescription("Check, without running a scan, whether control identifiers resolve against the policy catalog the way scan_controls resolves them. Each identifier is a control ID (e.g. C-0286) or a framework section number (e.g. CIS-3.1.1), case-insensitive. Reports which identifiers resolve to which control, which are unknown, which section numbers are ambiguous, and which name a control already named by an earlier identifier. Read-only: it needs no cluster access. If the policy bundle is still loading or cannot be read it returns an error rather than reporting identifiers as unknown."),
		withControlIDsProperty("Control identifiers to check: a comma-separated string (e.g. \"C-0012,CIS-3.1.1\") or an array of strings. At least one is required."),
		mcp.WithReadOnlyHintAnnotation(true),
	)
	ksServer.s.AddTool(listFrameworksTool, ksServer.toolHandler(listFrameworksTool.Name))
	ksServer.s.AddTool(listControlsTool, ksServer.toolHandler(listControlsTool.Name))
	ksServer.s.AddTool(listControlsConfigTool, ksServer.toolHandler(listControlsConfigTool.Name))
	ksServer.s.AddTool(validateScanSelectionTool, ksServer.toolHandler(validateScanSelectionTool.Name))
	ksServer.s.AddTool(listAdmissionPoliciesTool, ksServer.toolHandler(listAdmissionPoliciesTool.Name))
	ksServer.s.AddTool(createAdmissionPolicyBindingTool, ksServer.toolHandler(createAdmissionPolicyBindingTool.Name))
	ksServer.s.AddTool(generateVAPTool, ksServer.toolHandler(generateVAPTool.Name))
}

func GetMCPServerCmd() *cobra.Command {
	var transport string
	var port int
	var workspace string
	cmd := &cobra.Command{
		Use:   "mcpserver",
		Short: "Start the Kubescape MCP server",
		Long:  `Start the Kubescape MCP server`,
		Args:  cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			norm, err := validateMCPOptions(transport, port)
			if err != nil {
				return err
			}
			transport = norm
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// The root command's context is cancelled on the first SIGINT or
			// SIGTERM (see main.go); SSE shuts down when it ends.
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			return mcpServerEntrypoint(ctx, transport, port, workspace)
		},
	}
	cmd.Flags().StringVarP(&transport, "transport", "t", "stdio", "Transport protocol to use (stdio or sse)")
	cmd.Flags().IntVarP(&port, "port", "p", 8080, "Port to use for SSE transport")
	cmd.Flags().StringVar(&workspace, "workspace", "", "Path to the allowed workspace root directory for local IaC scans [$KUBESCAPE_WORKSPACE_DIR]")
	return cmd
}
