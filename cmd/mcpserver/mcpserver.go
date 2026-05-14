package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kubescape/go-logger"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	spdxv1beta1 "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type KubescapeMcpserver struct {
	s        *server.MCPServer
	ksClient spdxv1beta1.SpdxV1beta1Interface
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

	ksServer.s.AddTool(listManifestsTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return ksServer.CallTool(ctx, "list_vulnerability_manifests", request.Params.Arguments.(map[string]interface{}))
	})

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

	ksServer.s.AddTool(listVulnerabilitiesTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return ksServer.CallTool(ctx, "list_vulnerabilities_in_manifest", request.Params.Arguments.(map[string]interface{}))
	})

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

	ksServer.s.AddTool(listVulnerabilityMatchesForCVE, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return ksServer.CallTool(ctx, "list_vulnerability_matches_for_cve", request.Params.Arguments.(map[string]interface{}))
	})

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

	ksServer.s.AddTool(listConfigsTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return ksServer.CallTool(ctx, "list_configuration_security_scan_manifests", request.Params.Arguments.(map[string]interface{}))
	})

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

	ksServer.s.AddTool(getConfigDetailsTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return ksServer.CallTool(ctx, "get_configuration_security_scan_manifest", request.Params.Arguments.(map[string]interface{}))
	})

	configManifestTemplate := mcp.NewResourceTemplate(
		"kubescape://configuration-manifests/{namespace}/{manifest_name}",
		"Configuration Security Scan Manifest",
		mcp.WithTemplateDescription("Complete configuration scan manifest for a specific workload. Use 'list_configuration_security_scan_manifests' tool to discover available manifests."),
		mcp.WithTemplateMIMEType("application/json"),
	)

	ksServer.s.AddResourceTemplate(configManifestTemplate, ksServer.ReadConfigurationResource)
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
	manifest, err := ksServer.ksClient.VulnerabilityManifests(namespace).Get(ctx, manifestName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerability manifest: %s", err)
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
			return nil, fmt.Errorf("failed to marshal cve list: %s", err)
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
			return nil, fmt.Errorf("failed to marshal cve details: %s", err)
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
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid URI: %s", uri)
	}
	namespace := parts[0]
	manifestName := parts[1]
	manifest, err := ksServer.ksClient.WorkloadConfigurationScans(namespace).Get(ctx, manifestName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get configuration manifest: %s", err)
	}
	responseJson, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal configuration manifest: %s", err)
	}
	return []mcp.ResourceContents{mcp.TextResourceContents{
		URI:  uri,
		Text: string(responseJson),
	}}, nil
}

func (ksServer *KubescapeMcpserver) CallTool(ctx context.Context, name string, arguments map[string]interface{}) (*mcp.CallToolResult, error) {
	switch name {
	case "list_vulnerability_manifests":
		//namespace, ok := arguments["namespace"]
		//if !ok {
		//	namespace = ""
		//}
		level, ok := arguments["level"]
		if !ok {
			level = "both"
		}

		result := map[string]interface{}{
			"vulnerability_manifests": map[string]interface{}{},
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
			manifests, err = ksServer.ksClient.VulnerabilityManifests(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
		} else {
			manifests, err = ksServer.ksClient.VulnerabilityManifests(metav1.NamespaceAll).List(ctx, metav1.ListOptions{
				LabelSelector: labelSelector,
			})
		}
		if err != nil {
			return nil, err
		}

		logger.L().Info(fmt.Sprintf("Found %d manifests", len(manifests.Items)))

		vulnerabilityManifests := []map[string]interface{}{}
		for _, manifest := range manifests.Items {
			isImageLevel := manifest.Annotations[helpersv1.WlidMetadataKey] == ""
			manifestMap := map[string]interface{}{
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
		result["vulnerability_manifests"].(map[string]interface{})["manifests"] = vulnerabilityManifests

		// Add template information
		result["available_templates"] = map[string]string{
			"vulnerability_manifest_cve_list":    "kubescape://vulnerability-manifests/{namespace}/{manifest_name}/cve_list",
			"vulnerability_manifest_cve_details": "kubescape://vulnerability-manifests/{namespace}/{manifest_name}/cve_details/{cve_id}",
		}

		content, err := json.Marshal(result)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal result: %s", err)
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
		manifest, err := ksServer.ksClient.VulnerabilityManifests(namespaceStr).Get(ctx, manifestNameStr, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get vulnerability manifest: %s", err)
		}
		var cveList []v1beta1.Vulnerability
		for _, match := range manifest.Spec.Payload.Matches {
			cveList = append(cveList, match.Vulnerability)
		}
		responseJson, err := json.Marshal(cveList)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal cve list: %s", err)
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
		manifest, err := ksServer.ksClient.VulnerabilityManifests(namespaceStr).Get(ctx, manifestNameStr, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get vulnerability manifest: %s", err)
		}
		var match []v1beta1.Match
		for _, m := range manifest.Spec.Payload.Matches {
			if m.Vulnerability.ID == cveIDStr {
				match = append(match, m)
			}
		}
		responseJson, err := json.Marshal(match)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal cve details: %s", err)
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
		manifests, err := ksServer.ksClient.WorkloadConfigurationScans(namespaceStr).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		logger.L().Info(fmt.Sprintf("Found %d configuration manifests", len(manifests.Items)))
		configManifests := []map[string]interface{}{}
		for _, manifest := range manifests.Items {
			item := map[string]interface{}{
				"namespace":     manifest.Namespace,
				"manifest_name": manifest.Name,
				"resource_uri":  fmt.Sprintf("kubescape://configuration-manifests/%s/%s", manifest.Namespace, manifest.Name),
			}
			configManifests = append(configManifests, item)
		}
		result := map[string]interface{}{
			"configuration_manifests": map[string]interface{}{
				"manifests": configManifests,
			},
			"available_templates": map[string]string{
				"configuration_manifest_details": "kubescape://configuration-manifests/{namespace}/{manifest_name}",
			},
		}
		content, err := json.Marshal(result)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal result: %s", err)
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
		manifest, err := ksServer.ksClient.WorkloadConfigurationScans(namespaceStr).Get(ctx, manifestNameStr, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get configuration manifest: %s", err)
		}
		responseJson, err := json.Marshal(manifest)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal configuration manifest: %s", err)
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.TextContent{
					Type: "text",
					Text: string(responseJson),
				},
			},
		}, nil
	default:
		return nil, fmt.Errorf("unknown tool: %s", name)
	}
}

func mcpServerEntrypoint() error {
	logger.L().Info("Starting MCP server...")

	// Create a kubernetes client and verify it's working
	client, err := CreateKsObjectConnection("default", 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to create kubernetes client: %v", err)
	}

	// Create a new MCP server
	s := server.NewMCPServer(
		"Kubescape MCP Server",
		"0.0.1",
		server.WithToolCapabilities(false),
		server.WithRecovery(),
	)

	ksServer := &KubescapeMcpserver{
		s:        s,
		ksClient: client,
	}

	// Creating Kubescape tools and resources

	createVulnerabilityToolsAndResources(ksServer)
	createConfigurationsToolsAndResources(ksServer)

	// Start the server
	if err := server.ServeStdio(s); err != nil {
		return fmt.Errorf("server error: %v", err)
	}
	return nil
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
