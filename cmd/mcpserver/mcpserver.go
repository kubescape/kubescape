package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
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
)

type KubescapeMcpserver struct {
	s             *server.MCPServer
	ksClient      spdxv1beta1.SpdxV1beta1Interface
	k8sClient     *k8sinterface.KubernetesApi
	k8sClientOnce sync.Once
	policyGetter  *getter.DownloadReleasedPolicy
}

func (ksServer *KubescapeMcpserver) getK8sClient() *k8sinterface.KubernetesApi {
	ksServer.k8sClientOnce.Do(func() {
		if ksServer.k8sClient == nil {
			ksServer.k8sClient = k8sinterface.NewKubernetesApi()
		}
	})
	return ksServer.k8sClient
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
		return ksServer.CallTool(ctx, "list_vulnerability_manifests", request.Params.Arguments.(map[string]any))
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
		return ksServer.CallTool(ctx, "list_vulnerabilities_in_manifest", request.Params.Arguments.(map[string]any))
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
		return ksServer.CallTool(ctx, "list_vulnerability_matches_for_cve", request.Params.Arguments.(map[string]any))
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
		return ksServer.CallTool(ctx, "list_configuration_security_scan_manifests", request.Params.Arguments.(map[string]any))
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
		return ksServer.CallTool(ctx, "get_configuration_security_scan_manifest", request.Params.Arguments.(map[string]any))
	})

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

	ksServer.s.AddTool(listContainerProfilesTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]any)
		if !ok {
			args = map[string]any{}
		}
		return ksServer.CallTool(ctx, "list_container_profiles", args)
	})

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

	ksServer.s.AddTool(getContainerProfileTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]any)
		if !ok {
			args = map[string]any{}
		}
		return ksServer.CallTool(ctx, "get_container_profile", args)
	})

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
	manifest, err := ksServer.ksClient.VulnerabilityManifests(namespace).Get(ctx, manifestName, metav1.GetOptions{})
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
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid URI: %s", uri)
	}
	namespace := parts[0]
	manifestName := parts[1]
	manifest, err := ksServer.ksClient.WorkloadConfigurationScans(namespace).Get(ctx, manifestName, metav1.GetOptions{})
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
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid URI: %s", uri)
	}
	namespace := parts[0]
	profileName := parts[1]
	profile, err := ksServer.ksClient.ContainerProfiles(namespace).Get(ctx, profileName, metav1.GetOptions{})
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
			manifests, err = ksServer.ksClient.VulnerabilityManifests(namespace).List(ctx, metav1.ListOptions{})
		} else {
			manifests, err = ksServer.ksClient.VulnerabilityManifests(namespace).List(ctx, metav1.ListOptions{
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
		manifest, err := ksServer.ksClient.VulnerabilityManifests(namespaceStr).Get(ctx, manifestNameStr, metav1.GetOptions{})
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
		manifest, err := ksServer.ksClient.VulnerabilityManifests(namespaceStr).Get(ctx, manifestNameStr, metav1.GetOptions{})
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
		manifests, err := ksServer.ksClient.WorkloadConfigurationScans(namespaceStr).List(ctx, metav1.ListOptions{})
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
		manifest, err := ksServer.ksClient.WorkloadConfigurationScans(namespaceStr).Get(ctx, manifestNameStr, metav1.GetOptions{})
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
		profiles, err := ksServer.ksClient.ContainerProfiles(namespace).List(ctx, metav1.ListOptions{})
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
		profile, err := ksServer.ksClient.ContainerProfiles(namespaceStr).Get(ctx, profileNameStr, metav1.GetOptions{})
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
	default:
		return nil, fmt.Errorf("unknown tool: %s", name)
	}
}

func mcpServerEntrypoint() error {
	logger.L().Info("Starting MCP server...")

	// Create a kubernetes client and verify it's working
	client, err := CreateKsObjectConnection("default", 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to create kubernetes client: %w", err)
	}

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

	ksServer := &KubescapeMcpserver{
		s:            s,
		ksClient:     client,
		k8sClient:    k8sApi,
		policyGetter: getter.NewDownloadReleasedPolicy(),
	}

	// Creating Kubescape tools and resources

	createVulnerabilityToolsAndResources(ksServer)
	createConfigurationsToolsAndResources(ksServer)
	createRuntimeToolsAndResources(ksServer)
	createRBACScanningTools(ksServer)
	createNetworkScanningTools(ksServer)
	createFrameworkScanningTools(ksServer)

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

	ksServer.s.AddTool(runRBACScanTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Blocker 3 fix: use comma-ok pattern to prevent panic when namespace is
		// omitted (tool is callable with no arguments since namespace is optional).
		args, ok := request.Params.Arguments.(map[string]any)
		if !ok && request.Params.Arguments != nil {
			return mcp.NewToolResultError("arguments must be a JSON object"), nil
		}
		if args == nil {
			args = map[string]any{}
		}
		return ksServer.CallTool(ctx, "run_rbac_security_scan", args)
	})
}

func createNetworkScanningTools(ksServer *KubescapeMcpserver) {
	runNetworkScanTool := mcp.NewTool(
		"run_network_security_scan",
		mcp.WithDescription("Run an on-demand, live Network security scan (evaluating only ingress and egress block policies) and return the failed resources."),
		mcp.WithString("namespace",
			mcp.Description("Namespace to scope the Network scan (optional, defaults to cluster-wide if omitted)"),
		),
	)

	ksServer.s.AddTool(runNetworkScanTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]any)
		if !ok && request.Params.Arguments != nil {
			return mcp.NewToolResultError("arguments must be a JSON object"), nil
		}
		if args == nil {
			args = map[string]any{}
		}
		return ksServer.CallTool(ctx, "run_network_security_scan", args)
	})
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

	ksServer.s.AddTool(runFrameworkScanTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]any)
		if !ok && request.Params.Arguments != nil {
			return mcp.NewToolResultError("arguments must be a JSON object"), nil
		}
		if args == nil {
			args = map[string]any{}
		}
		return ksServer.CallTool(ctx, "run_framework_security_scan", args)
	})
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
