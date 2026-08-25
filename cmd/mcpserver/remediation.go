package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"

	ksmetav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v4/core/pkg/fixhandler"
)

// iacScanReportFn produces the PostureReport the remediation flow feeds to the
// fixhandler. Package-level so tests can supply a canned report instead of
// running a real scan.
var iacScanReportFn = func(s *KubescapeMcpserver, ctx context.Context, path string, controlIDs []string) ([]byte, error) {
	return s.runIaCScanControlsReport(ctx, path, controlIDs)
}

// remediationFileResult is the patched content for one file. Multiple entries
// appear when path is a directory whose resources span several files.
type remediationFileResult struct {
	FilePath           string   `json:"file_path"`
	PatchedYAML        string   `json:"patched_yaml"`
	AppliedExpressions []string `json:"applied_expressions"`
}

type remediationResponse struct {
	Files []remediationFileResult `json:"files"`
	// FixedControlInstances counts (resource, control) tuples that produced at
	// least one edit.
	FixedControlInstances int `json:"fixed_control_instances"`
	// UnfixedControls tells the caller which controls have no deterministic
	// fix — the signal that stops an agent inventing one.
	UnfixedControls []fixhandler.UnfixedControl `json:"unfixed_controls,omitempty"`
}

func createRemediationTools(ksServer *KubescapeMcpserver) {
	applyRemediationTool := mcp.NewTool(
		"apply_remediation",
		mcp.WithDescription("Compute the exact, deterministic YAML patch for failed controls in local IaC. Scans the given path for the given controls, derives Kubescape's official yq-based fixes, and returns the fully patched YAML as a string. DOES NOT modify any file on disk — the caller decides whether to write the returned content. Controls with no automatic fix are listed in unfixed_controls and must not be fixed by guesswork. Use list_controls to discover valid IDs."),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Absolute or relative path to the local YAML file or directory to remediate (e.g., /path/to/manifest.yaml)"),
		),
		withControlIDsProperty("Control IDs to remediate: a comma-separated string (e.g. \"C-0013,C-0017\") or an array of strings (e.g. [\"C-0013\"]). At least one ID is required."),
	)
	ksServer.s.AddTool(applyRemediationTool, ksServer.toolHandler(applyRemediationTool.Name))
}

func (ksServer *KubescapeMcpserver) runApplyRemediation(ctx context.Context, path string, controlIDs []string) ([]byte, error) {
	// 1. Scan in memory.
	reportBytes, err := iacScanReportFn(ksServer, ctx, path, controlIDs)
	if err != nil {
		return nil, err
	}

	// 2. NewFixHandler only accepts a report on disk, so stage one. Write and
	//    close before handing it over — NewFixHandler opens and reads it
	//    synchronously in the constructor (fixhandler.go:42-47), so removal is
	//    safe on every path after that.
	tempFile, err := os.CreateTemp("", "kubescape-mcp-remediation-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp report file: %w", err)
	}
	tempName := tempFile.Name()
	defer os.Remove(tempName)
	if _, err := tempFile.Write(reportBytes); err != nil {
		tempFile.Close()
		return nil, fmt.Errorf("failed to write temp report file: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return nil, fmt.Errorf("failed to close temp report file: %w", err)
	}

	// 3. Instantiate the fixer in a dry-run configuration.
	handler, err := fixhandler.NewFixHandler(&ksmetav1.FixInfo{
		ReportFile: tempName,
		DryRun:     true, // documents intent; ApplyChanges is never called
		NoConfirm:  true,
		// SkipUserValues stays false: fixes whose value is a YOUR_* placeholder
		// are still returned, because the calling agent is exactly the party
		// that can substitute a real value.
		// BasePath stays empty: the report was generated in-process from the
		// caller's own path, so this is not the untrusted-report case BasePath
		// guards against.
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize fix handler: %w", err)
	}

	// 4. Plan the fixes. This writes nothing.
	resourcesToFix := handler.PrepareResourcesToFix(ctx)

	// 5. Group expressions per file and apply them in memory. Mirrors
	//    getFileYamlExpressions/reduceYamlExpressions (fixhandler.go:818, :989)
	//    without their disk write. Each key is already scoped with
	//    select(di==N), so multi-document files compose under one " | " pipeline.
	fileExprs := make(map[string][]string)
	for _, rfi := range resourcesToFix {
		exprs := make([]string, 0, len(rfi.YamlExpressions))
		for expr := range rfi.YamlExpressions {
			exprs = append(exprs, expr)
		}
		sort.Strings(exprs) // map iteration order is random; output must be stable
		fileExprs[rfi.FilePath] = append(fileExprs[rfi.FilePath], exprs...)
	}

	filePaths := make([]string, 0, len(fileExprs))
	for fp := range fileExprs {
		filePaths = append(filePaths, fp)
	}
	sort.Strings(filePaths)

	files := make([]remediationFileResult, 0, len(filePaths))
	for _, fp := range filePaths {
		joined := strings.Join(fileExprs[fp], " | ")
		fileAsString, err := fixhandler.GetFileString(fp)
		if err != nil {
			return nil, err
		}
		patched, err := fixhandler.ApplyFixToContent(ctx, fileAsString, joined)
		if err != nil {
			return nil, fmt.Errorf("failed to compute fix for %s: %w", fp, err)
		}
		files = append(files, remediationFileResult{
			FilePath:           fp,
			PatchedYAML:        patched,
			AppliedExpressions: fileExprs[fp],
		})
	}

	// 6. Always return the envelope, even with zero files: unfixed_controls
	//    then explains why nothing was fixable, which is more useful to an
	//    agent than an error.
	resp := remediationResponse{
		Files:                 files,
		FixedControlInstances: handler.FixedControlsCount(),
		UnfixedControls:       handler.UnfixedControls(),
	}
	return json.MarshalIndent(resp, "", "  ")
}
