package mcpserver

import (
	"context"
	"errors"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resourcehandler"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/objectsenvelopes"
)

// workloadScanFrameworks mirrors the policy scope of `kubescape scan workload`
// (cmd/scan/workload.go).
//
// run_framework_security_scan refuses allcontrols as too heavy, which looks
// contradictory until you notice that guard protects namespace- and
// cluster-wide scans. A single-resource scan is a different cost profile:
// getQueryableResourceMapFromPoliciesWithWarned drops every rule whose Match
// does not cover the target's kind before a single query is issued, and scopes
// the survivors to the target's namespace
// (core/pkg/resourcehandler/resourcehandlerutils.go). What remains is a small
// fraction of what a namespace scan would pull.
var workloadScanFrameworks = []string{"workloadscan", "allcontrols"}

const mcpNamespaceDefaultedHint = "namespace defaulted to 'default'; pass namespace: '*' to search cluster-wide"

type defaultedNamespaceError struct {
	err  error
	hint string
}

func (e *defaultedNamespaceError) Error() string {
	return e.err.Error()
}

func (e *defaultedNamespaceError) Unwrap() error {
	return e.err
}

func (e *defaultedNamespaceError) Hint() string {
	return e.hint
}

// buildWorkloadScanRequest translates the tool arguments into a scanRequest.
//
// It is separate from RunWorkloadScan so the identifier parsing, the namespace
// precedence rule and the choice between the cluster and file resource handlers
// can be asserted without standing up a scan.
func buildWorkloadScanRequest(workload, namespace, path, frameworkName string) (scanRequest, error) {
	identNamespace, kind, name, apiVersion, err := cautils.ParseWorkloadIdentifierString(strings.TrimSpace(workload))
	if err != nil {
		return scanRequest{}, err
	}

	isClusterScan := strings.TrimSpace(path) == ""
	targetNamespace, namespaceDefaulted, err := cautils.ResolveWorkloadNamespace(identNamespace, namespace, isClusterScan)
	if err != nil {
		return scanRequest{}, err
	}

	scanObject := &objectsenvelopes.ScanObject{}
	scanObject.SetNamespace(targetNamespace)
	scanObject.SetKind(kind)
	scanObject.SetName(name)
	// Left unset for a bare kind so the cluster handler can fall back to
	// discovery. It is required for CRDs, which discovery cannot disambiguate.
	if apiVersion != "" {
		scanObject.SetApiVersion(apiVersion)
	}

	frameworks := workloadScanFrameworks
	if frameworkName = strings.TrimSpace(frameworkName); frameworkName != "" {
		frameworks = []string{frameworkName}
	}

	req := scanRequest{
		namespace:          targetNamespace,
		namespaceDefaulted: namespaceDefaulted,
		policyIdentifiers:  cautils.BuildPolicyIdentifiers(frameworks, apisv1.KindFramework),
		label:              "Workload",
		scanObject:         scanObject,
	}

	if path = strings.TrimSpace(path); path != "" {
		req.rsrcHandler = resourcehandler.NewFileResourceHandler()
		req.inputPatterns = []string{path}
		// FileResourceHandler has no namespace collection filter — the namespace
		// is applied when matching the loaded manifests against scanObject.
		// Leaving it on the request would only narrow ScanInfo.IncludeNamespaces,
		// which nothing on this path reads.
		req.namespace = ""
	}

	return req, nil
}

// RunWorkloadScan scans a single named workload and returns the summarized
// scanResponse JSON. When path is non-empty the workload is resolved from local
// manifests, otherwise it is fetched from the live cluster.
func (ksServer *KubescapeMcpserver) RunWorkloadScan(ctx context.Context, workload, namespace, path, frameworkName string) ([]byte, error) {
	req, err := buildWorkloadScanRequest(workload, namespace, path, frameworkName)
	if err != nil {
		return nil, err
	}
	resp, err := runScan(ctx, ksServer, req)
	if err != nil {
		if req.namespaceDefaulted && (errors.Is(err, resourcehandler.ErrResourceNotFound) || errors.Is(err, resourcehandler.ErrResourceNotInDiscovery)) {
			return nil, &defaultedNamespaceError{err: err, hint: mcpNamespaceDefaultedHint}
		}
		return nil, err
	}
	return resp, nil
}

// workloadScanFn is a package-level var so CallTool tests can observe argument
// mapping without running a scan, matching rbacScanFn and its siblings.
var workloadScanFn = func(s *KubescapeMcpserver, ctx context.Context, workload, namespace, path, frameworkName string) ([]byte, error) {
	return s.RunWorkloadScan(ctx, workload, namespace, path, frameworkName)
}

func createWorkloadScanningTools(ksServer *KubescapeMcpserver) {
	runWorkloadScanTool := mcp.NewTool(
		"scan_workload",
		mcp.WithDescription("Scan a single named Kubernetes workload (e.g. one Deployment) for misconfigurations and return its failed controls. Prefer this over scan_controls or run_framework_security_scan when you already know which workload you care about: only the rules that apply to that resource's kind are evaluated, so it is much cheaper and returns far fewer results. Scans the live cluster by default, or local manifests when path is given."),
		mcp.WithString("workload",
			mcp.Required(),
			mcp.Description("Workload identifier as <kind>[.<version>[.<group>]]/<name>, optionally namespace-qualified: \"Deployment/nginx\", \"default/Deployment/nginx\", or \"Deployment.v1.apps/nginx\". A non-built-in kind (CRD) must include its version and group."),
		),
		mcp.WithString("namespace",
			mcp.Description("Namespace of the workload (optional; defaults to 'default' for live-cluster scans, or unconstrained when path is provided). Pass '*' to search across all namespaces in a live cluster (requires cluster-wide list permissions). Note: the workload identifier prefix (if any) and this parameter must not conflict."),
		),
		mcp.WithString("path",
			mcp.Description("Optional path to local YAML manifests. When set, the workload is resolved from those files instead of the live cluster."),
		),
		mcp.WithString("framework",
			mcp.Description("Framework to scan against (optional, defaults to the full workload control set)."),
		),
	)
	ksServer.s.AddTool(runWorkloadScanTool, ksServer.toolHandler(runWorkloadScanTool.Name))
}
