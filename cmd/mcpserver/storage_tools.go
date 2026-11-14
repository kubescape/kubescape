package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	spdxv1beta1 "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/mcp/tools"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The read tools on Kubescape's stored data (vulnerability manifests, SBOMs,
// configuration scans, container profiles) come from storage's
// pkg/mcp/tools, which storage also serves in-cluster on its mcpservers/mcp
// subresource. One copy of the tools, served two ways.

// defaultDataNamespace is where Kubescape stores vulnerability manifests and
// SBOMs; their get tools read there when no namespace is given.
const defaultDataNamespace = "kubescape"

// storageToolOptions describe the CLI's namespace defaults, which are not the
// endpoint's (the namespace in its URL), and add the kubescape:// links to
// the resource templates this server serves.
var storageToolOptions = []tools.Option{
	tools.WithResourceLinks(),
	tools.WithNamespaceDescription("list_vulnerability_manifests",
		"Namespace to list (optional, default all namespaces)"),
	tools.WithNamespaceDescription("list_vulnerabilities_in_manifest",
		"Namespace of the manifest (optional, default kubescape)"),
	tools.WithNamespaceDescription("list_vulnerability_matches_for_cve",
		"Namespace of the manifest (optional, default kubescape)"),
	tools.WithNamespaceDescription("list_sboms",
		"Namespace to list (optional, default all namespaces)"),
	tools.WithNamespaceDescription("list_sbom_packages",
		"Namespace of the SBOM (optional, default kubescape)"),
	tools.WithNamespaceDescription("list_configuration_security_scan_manifests",
		"Namespace to list (optional, default all namespaces). A workload's scan is stored in the workload's namespace; scans of cluster-scoped resources are in 'kubescape'"),
	tools.WithNamespaceDescription("get_configuration_security_scan_manifest",
		"Namespace of the manifest, as returned by list_configuration_security_scan_manifests (optional; if omitted, the manifest is looked up by name in every namespace)"),
	tools.WithNamespaceDescription("list_container_profiles",
		"Namespace to list (optional, default all namespaces). A container's profile is stored in its workload's namespace"),
	tools.WithNamespaceDescription("get_container_profile",
		"Namespace of the profile, as returned by list_container_profiles (optional; if omitted, the profile is looked up by name in every namespace)"),
}

// storageTools returns storage's read tools, reading through this server's
// storage client.
func (ksServer *KubescapeMcpserver) storageTools() []server.ServerTool {
	ksServer.storageToolsOnce.Do(func() {
		ksServer.storageToolList = tools.Tools(storageReader{ksServer}, storageToolOptions...)
	})
	return ksServer.storageToolList
}

// callStorageTool runs the storage read tool called name; ok is false when
// there is none.
func (ksServer *KubescapeMcpserver) callStorageTool(ctx context.Context, name string, arguments map[string]any) (res *mcp.CallToolResult, ok bool, err error) {
	for _, t := range ksServer.storageTools() {
		if t.Tool.Name != name {
			continue
		}
		req := mcp.CallToolRequest{}
		req.Params.Name = name
		req.Params.Arguments = trimStringArguments(arguments)
		res, err = t.Handler(ctx, req)
		var toolErr *toolResultError
		if errors.As(err, &toolErr) {
			return toolErr.result, true, nil
		}
		return res, true, err
	}
	return nil, false, nil
}

// trimStringArguments returns arguments with the spaces around each string
// value removed, as mcpStringArg does for the CLI's other tools; storage's
// tools take strings as they are.
func trimStringArguments(arguments map[string]any) map[string]any {
	trimmed := make(map[string]any, len(arguments))
	for k, v := range arguments {
		if s, ok := v.(string); ok {
			v = strings.TrimSpace(s)
		}
		trimmed[k] = v
	}
	return trimmed
}

// toolResultError carries a tool error result out of storageReader, through
// the storage tool, back to callStorageTool.
type toolResultError struct {
	result *mcp.CallToolResult
}

func (e *toolResultError) Error() string {
	return "tool error"
}

// storageReader is the tools.Reader of the CLI: it reads with the storage
// client of the kubeconfig. An empty namespace lists every namespace; a get
// with no namespace reads vulnerability manifests and SBOMs in kubescape, and
// finds configuration scans and container profiles by name, since those are
// stored in the workload's own namespace.
type storageReader struct {
	ks *KubescapeMcpserver
}

var _ tools.Reader = storageReader{}

func (r storageReader) client() (spdxv1beta1.SpdxV1beta1Interface, error) {
	client, err := r.ks.getKsClient()
	if err != nil {
		return nil, &toolResultError{mcpToolError(ErrCodeK8sClientError, fmt.Sprintf("failed to connect to Kubernetes cluster: %v", err), nil)}
	}
	return client, nil
}

func (r storageReader) ListVulnerabilityManifests(ctx context.Context, namespace string, opts metav1.ListOptions) (*v1beta1.VulnerabilityManifestList, error) {
	client, err := r.client()
	if err != nil {
		return nil, err
	}
	return client.VulnerabilityManifests(namespace).List(ctx, opts)
}

func (r storageReader) GetVulnerabilityManifest(ctx context.Context, namespace, name string) (*v1beta1.VulnerabilityManifest, error) {
	client, err := r.client()
	if err != nil {
		return nil, err
	}
	if namespace == "" {
		namespace = defaultDataNamespace
	}
	return client.VulnerabilityManifests(namespace).Get(ctx, name, metav1.GetOptions{})
}

func (r storageReader) ListSBOMSyfts(ctx context.Context, namespace string, opts metav1.ListOptions) (*v1beta1.SBOMSyftList, error) {
	client, err := r.client()
	if err != nil {
		return nil, err
	}
	return client.SBOMSyfts(namespace).List(ctx, opts)
}

func (r storageReader) GetSBOMSyft(ctx context.Context, namespace, name string) (*v1beta1.SBOMSyft, error) {
	client, err := r.client()
	if err != nil {
		return nil, err
	}
	if namespace == "" {
		namespace = defaultDataNamespace
	}
	return client.SBOMSyfts(namespace).Get(ctx, name, metav1.GetOptions{})
}

func (r storageReader) ListWorkloadConfigurationScans(ctx context.Context, namespace string, opts metav1.ListOptions) (*v1beta1.WorkloadConfigurationScanList, error) {
	client, err := r.client()
	if err != nil {
		return nil, err
	}
	return client.WorkloadConfigurationScans(namespace).List(ctx, opts)
}

func (r storageReader) GetWorkloadConfigurationScan(ctx context.Context, namespace, name string) (*v1beta1.WorkloadConfigurationScan, error) {
	client, err := r.client()
	if err != nil {
		return nil, err
	}
	if namespace == "" {
		scans, err := client.WorkloadConfigurationScans(metav1.NamespaceAll).List(ctx, nameSelector(name))
		if err != nil {
			return nil, fmt.Errorf("failed to find configuration manifest: %w", err)
		}
		found := make([]metav1.ObjectMeta, len(scans.Items))
		for i := range scans.Items {
			found[i] = scans.Items[i].ObjectMeta
		}
		if namespace, err = findNamespace("configuration manifest", name, found); err != nil {
			return nil, err
		}
	}
	return client.WorkloadConfigurationScans(namespace).Get(ctx, name, metav1.GetOptions{})
}

func (r storageReader) ListContainerProfiles(ctx context.Context, namespace string, opts metav1.ListOptions) (*v1beta1.ContainerProfileList, error) {
	client, err := r.client()
	if err != nil {
		return nil, err
	}
	return client.ContainerProfiles(namespace).List(ctx, opts)
}

func (r storageReader) GetContainerProfile(ctx context.Context, namespace, name string) (*v1beta1.ContainerProfile, error) {
	client, err := r.client()
	if err != nil {
		return nil, err
	}
	if namespace == "" {
		profiles, err := client.ContainerProfiles(metav1.NamespaceAll).List(ctx, nameSelector(name))
		if err != nil {
			return nil, fmt.Errorf("failed to find container profile: %w", err)
		}
		found := make([]metav1.ObjectMeta, len(profiles.Items))
		for i := range profiles.Items {
			found[i] = profiles.Items[i].ObjectMeta
		}
		if namespace, err = findNamespace("container profile", name, found); err != nil {
			return nil, err
		}
	}
	return client.ContainerProfiles(namespace).Get(ctx, name, metav1.GetOptions{})
}

// findNamespace is pickNamespace for a Reader: its tool error goes back as a
// toolResultError.
func findNamespace(kind, name string, objects []metav1.ObjectMeta) (string, error) {
	namespace, toolErr := pickNamespace(kind, name, objects)
	if toolErr != nil {
		return "", &toolResultError{toolErr}
	}
	return namespace, nil
}
