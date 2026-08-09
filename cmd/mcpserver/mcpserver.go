package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kubescape/go-logger"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	spdxv1beta1 "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	"github.com/kubescape/kubescape/v3/pkg/imagescan"
)

type KubescapeMcpserver struct {
	s             *server.MCPServer
	ksClient      spdxv1beta1.SpdxV1beta1Interface
	ksClientOnce  sync.Once
	ksClientErr   error
	k8sClient     *k8sinterface.KubernetesApi
	k8sClientOnce sync.Once
	policyGetter  *getter.DownloadReleasedPolicy

	imageScanSvc   *imagescan.Service
	imageScanSvcMu sync.Mutex
	imageScanMu    sync.Mutex
	dbListingURL   string
}

func (ksServer *KubescapeMcpserver) getImageScanService(ctx context.Context) (*imagescan.Service, error) {
	ksServer.imageScanSvcMu.Lock()
	defer ksServer.imageScanSvcMu.Unlock()

	if ksServer.imageScanSvc != nil {
		return ksServer.imageScanSvc, nil
	}

	type initResult struct {
		svc *imagescan.Service
		err error
	}

	initCh := make(chan initResult, 1)
	go func() {
		distCfg, installCfg, _, err := imagescan.NewDefaultDBConfig(ksServer.dbListingURL)
		if err != nil {
			initCh <- initResult{err: fmt.Errorf("failed to initialize default Grype database configuration: %w", err)}
			return
		}
		svc, err := imagescan.NewRemoteOnlyScanService(distCfg, installCfg)
		if err != nil {
			initCh <- initResult{err: fmt.Errorf("failed to initialize image scan service: %w", err)}
			return
		}
		initCh <- initResult{svc: svc}
	}()

	select {
	case <-ctx.Done():
		go func() {
			res := <-initCh
			if res.svc == nil {
				return
			}
			ksServer.imageScanSvcMu.Lock()
			defer ksServer.imageScanSvcMu.Unlock()
			if ksServer.imageScanSvc == nil {
				ksServer.imageScanSvc = res.svc
			} else {
				res.svc.Close()
			}
		}()
		return nil, fmt.Errorf("image scan service initialization timed out or was canceled: %w", ctx.Err())
	case res := <-initCh:
		if res.err != nil {
			return nil, res.err
		}
		ksServer.imageScanSvc = res.svc
		return res.svc, nil
	}
}

func (ksServer *KubescapeMcpserver) getKsClient() (spdxv1beta1.SpdxV1beta1Interface, error) {
	ksServer.ksClientOnce.Do(func() {
		if ksServer.ksClient == nil {
			ksServer.ksClient, ksServer.ksClientErr = CreateKsObjectConnection("default", 10*time.Second)
		}
	})
	if ksServer.ksClientErr != nil {
		return nil, ksServer.ksClientErr
	}
	if ksServer.ksClient == nil {
		return nil, fmt.Errorf("kubernetes client initialization returned nil")
	}
	return ksServer.ksClient, nil
}

func (ksServer *KubescapeMcpserver) getK8sClient() *k8sinterface.KubernetesApi {
	ksServer.k8sClientOnce.Do(func() {
		if ksServer.k8sClient == nil {
			ksServer.k8sClient = k8sinterface.NewKubernetesApi()
		}
	})
	return ksServer.k8sClient
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
		return ksServer.CallTool(ctx, name, args)
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

		responseBytes, err := ksServer.RunRBACScan(ctx, namespace)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to run RBAC scan: %v", err)), nil
		}
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

		responseBytes, err := ksServer.runIaCScan(ctx, path, framework)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to run IaC scan: %v", err)), nil
		}
		return mcp.NewToolResultText(string(responseBytes)), nil
	case "run_network_security_scan":
		namespace := ""
		if ns, ok := arguments["namespace"]; ok {
			nsStr, ok := ns.(string)
			if !ok {
				return mcp.NewToolResultError("namespace argument must be a string"), nil
			}
			namespace = nsStr
		}

		responseBytes, err := ksServer.RunNetworkScan(ctx, namespace)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to run Network scan: %v", err)), nil
		}
		return mcp.NewToolResultText(string(responseBytes)), nil
	case "list_vulnerability_manifests":
		namespace := metav1.NamespaceAll
		if ns, ok := arguments["namespace"]; ok {
			nsStr, ok := ns.(string)
			if !ok {
				return mcp.NewToolResultError("namespace must be a string"), nil
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
				return mcp.NewToolResultError(fmt.Sprintf("failed to connect to Kubernetes cluster: %v", ksErr)), nil
			}
			manifests, err = client.VulnerabilityManifests(namespace).List(ctx, metav1.ListOptions{})
		} else {
			client, ksErr := ksServer.getKsClient()
			if ksErr != nil {
				return mcp.NewToolResultError(fmt.Sprintf("failed to connect to Kubernetes cluster: %v", ksErr)), nil
			}
			manifests, err = client.VulnerabilityManifests(namespace).List(ctx, metav1.ListOptions{
				LabelSelector: labelSelector,
			})
		}
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to list vulnerability manifests: %v", err)), nil
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
			return mcp.NewToolResultError(fmt.Sprintf("failed to marshal result: %v", err)), nil
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
			return mcp.NewToolResultError("namespace must be a string"), nil
		}
		manifestName, ok := arguments["manifest_name"]
		if !ok {
			return mcp.NewToolResultError("manifest_name is required"), nil
		}
		manifestNameStr, ok := manifestName.(string)
		if !ok {
			return mcp.NewToolResultError("manifest_name must be a string"), nil
		}
		client, ksErr := ksServer.getKsClient()
		if ksErr != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to connect to Kubernetes cluster: %v", ksErr)), nil
		}
		manifest, err := client.VulnerabilityManifests(namespaceStr).Get(ctx, manifestNameStr, metav1.GetOptions{})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to get vulnerability manifest: %v", err)), nil
		}
		var cveList []v1beta1.Vulnerability
		for _, match := range manifest.Spec.Payload.Matches {
			cveList = append(cveList, match.Vulnerability)
		}
		responseJson, err := json.Marshal(cveList)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to marshal cve list: %v", err)), nil
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
			return mcp.NewToolResultError("namespace must be a string"), nil
		}
		manifestName, ok := arguments["manifest_name"]
		if !ok {
			return mcp.NewToolResultError("manifest_name is required"), nil
		}
		manifestNameStr, ok := manifestName.(string)
		if !ok {
			return mcp.NewToolResultError("manifest_name must be a string"), nil
		}
		cveID, ok := arguments["cve_id"]
		if !ok {
			return mcp.NewToolResultError("cve_id is required"), nil
		}
		cveIDStr, ok := cveID.(string)
		if !ok {
			return mcp.NewToolResultError("cve_id must be a string"), nil
		}
		client, ksErr := ksServer.getKsClient()
		if ksErr != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to connect to Kubernetes cluster: %v", ksErr)), nil
		}
		manifest, err := client.VulnerabilityManifests(namespaceStr).Get(ctx, manifestNameStr, metav1.GetOptions{})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to get vulnerability manifest: %v", err)), nil
		}
		var match []v1beta1.Match
		for _, m := range manifest.Spec.Payload.Matches {
			if m.Vulnerability.ID == cveIDStr {
				match = append(match, m)
			}
		}
		responseJson, err := json.Marshal(match)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to marshal cve details: %v", err)), nil
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
			return mcp.NewToolResultError("namespace must be a string"), nil
		}
		client, ksErr := ksServer.getKsClient()
		if ksErr != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to connect to Kubernetes cluster: %v", ksErr)), nil
		}
		manifests, err := client.WorkloadConfigurationScans(namespaceStr).List(ctx, metav1.ListOptions{})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to list configuration scans: %v", err)), nil
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
			return mcp.NewToolResultError(fmt.Sprintf("failed to marshal result: %v", err)), nil
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
			return mcp.NewToolResultError("namespace must be a string"), nil
		}
		manifestName, ok := arguments["manifest_name"]
		if !ok {
			return mcp.NewToolResultError("manifest_name is required"), nil
		}
		manifestNameStr, ok := manifestName.(string)
		if !ok {
			return mcp.NewToolResultError("manifest_name must be a string"), nil
		}
		client, ksErr := ksServer.getKsClient()
		if ksErr != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to connect to Kubernetes cluster: %v", ksErr)), nil
		}
		manifest, err := client.WorkloadConfigurationScans(namespaceStr).Get(ctx, manifestNameStr, metav1.GetOptions{})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to get configuration manifest: %v", err)), nil
		}
		responseJson, err := json.Marshal(manifest)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to marshal configuration manifest: %v", err)), nil
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
				return mcp.NewToolResultError("namespace must be a string"), nil
			}
			if nsStr != "" {
				namespace = nsStr
			}
		}
		client, ksErr := ksServer.getKsClient()
		if ksErr != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to connect to Kubernetes cluster: %v", ksErr)), nil
		}
		profiles, err := client.ContainerProfiles(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to list container profiles: %v", err)), nil
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
			return mcp.NewToolResultError(fmt.Sprintf("failed to marshal result: %v", err)), nil
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
		client, ksErr := ksServer.getKsClient()
		if ksErr != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to connect to Kubernetes cluster: %v", ksErr)), nil
		}
		profile, err := client.ContainerProfiles(namespaceStr).Get(ctx, profileNameStr, metav1.GetOptions{})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to get container profile: %v", err)), nil
		}
		responseJson, err := json.Marshal(profile)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to marshal container profile: %v", err)), nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.TextContent{
					Type: "text",
					Text: string(responseJson),
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

		responseBytes, err := ksServer.RunFrameworkScan(ctx, namespace, frameworkNameStr)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to run framework scan: %v", err)), nil
		}
		return mcp.NewToolResultText(string(responseBytes)), nil
	case "scan_container_image":
		imageName := ""
		if img, ok := arguments["image_name"]; ok {
			imgStr, ok := img.(string)
			if !ok {
				return mcp.NewToolResultError("image_name argument must be a string"), nil
			}
			imageName = strings.TrimSpace(imgStr)
		}
		if imageName == "" {
			return mcp.NewToolResultError("image_name argument is required and cannot be empty"), nil
		}
		var regUsername string
		if u, ok := arguments["username"]; ok {
			uStr, ok := u.(string)
			if !ok {
				return mcp.NewToolResultError("username argument must be a string"), nil
			}
			regUsername = uStr
		}
		var regSecret string
		if p, ok := arguments["password"]; ok {
			pStr, ok := p.(string)
			if !ok {
				return mcp.NewToolResultError("password argument must be a string"), nil
			}
			regSecret = pStr
		}
		var includeMatches bool
		if inc, ok := arguments["include_matches"]; ok {
			incBool, ok := inc.(bool)
			if !ok {
				return mcp.NewToolResultError("include_matches argument must be a boolean"), nil
			}
			includeMatches = incBool
		}
		var severity string
		if sev, ok := arguments["severity"]; ok {
			sevStr, ok := sev.(string)
			if !ok {
				return mcp.NewToolResultError("severity argument must be a string"), nil
			}
			severity = strings.TrimSpace(sevStr)
			if err := validateSeverity(severity); err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
		}

		responseBytes, err := ksServer.runImageScan(ctx, imageName, regUsername, regSecret, includeMatches, severity)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to run container image scan: %v", err)), nil
		}
		return mcp.NewToolResultText(string(responseBytes)), nil
	default:
		return mcp.NewToolResultError(fmt.Sprintf("unknown tool: %s", name)), nil
	}
}

func mcpServerEntrypoint() error {
	logger.L().Info("Starting MCP server...")

	// Create a new MCP server
	s := server.NewMCPServer(
		"Kubescape MCP Server",
		"0.0.1",
		server.WithToolCapabilities(false),
		server.WithRecovery(),
	)

	// Build the k8s API client once at startup. IsConnectedToCluster() is checked
	// inside RunRBACScan before this is used, so it is safe to store here.
	var k8sApi *k8sinterface.KubernetesApi
	if k8sinterface.IsConnectedToCluster() {
		k8sApi = k8sinterface.NewKubernetesApi()
	}

	dbListingURL := os.Getenv("KS_GRYPE_LISTING_URL")

	ksServer := &KubescapeMcpserver{
		s:            s,
		k8sClient:    k8sApi,
		policyGetter: getter.NewDownloadReleasedPolicy(),
		dbListingURL: dbListingURL,
	}

	// Initialize the policy getter to load the local ~/.kubescape cache.
	// Without this, the getter will always hit the GitHub API directly for every scan,
	// defeating offline scanning and causing rate limits.
	_, _ = ksServer.policyGetter.SetRegoObjectsWithFallback()

	// Creating Kubescape tools and resources

	createVulnerabilityToolsAndResources(ksServer)
	createConfigurationsToolsAndResources(ksServer)
	createRuntimeToolsAndResources(ksServer)
	createRBACScanningTools(ksServer)
	createNetworkScanningTools(ksServer)
	createFrameworkScanningTools(ksServer)
	createIaCScanningTools(ksServer)
	createImageScanningTools(ksServer)

	// Start the server
	if err := server.ServeStdio(s); err != nil {
		return fmt.Errorf("server error: %w", err)
	}
	return nil
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

func createImageScanningTools(ksServer *KubescapeMcpserver) {
	scanImageTool := mcp.NewTool(
		"scan_container_image",
		mcp.WithDescription("Run an on-demand container image vulnerability scan. Note: this network-bound operation scans a container image and initializes/queries the vulnerability database."),
		mcp.WithString("image_name",
			mcp.Required(),
			mcp.Description("Name of the remote container image to scan (e.g., nginx:alpine)"),
		),
		mcp.WithString("username",
			mcp.Description("Username for registry authentication (optional)"),
		),
		mcp.WithString("password",
			mcp.Description("Password for registry authentication (optional)"),
		),
		mcp.WithBoolean("include_matches",
			mcp.Description("Include detailed match location and package info for each vulnerability (optional, defaults to false)"),
		),
		mcp.WithString("severity",
			mcp.Description("Minimum severity filter (e.g., Low, Medium, High, Critical) (optional)"),
		),
	)

	ksServer.s.AddTool(scanImageTool, ksServer.toolHandler(scanImageTool.Name))
}

func GetMCPServerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcpserver",
		Short: "Start the Kubescape MCP server",
		Long:  `Start the Kubescape MCP server`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return mcpServerEntrypoint()
		},
	}
	return cmd
}
