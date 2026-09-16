package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/core"
	"github.com/kubescape/kubescape/v4/core/meta"
	"github.com/kubescape/kubescape/v4/core/pkg/fleet"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
	"github.com/spf13/cobra"
)

// validateKubeContextsSupported rejects --kube-contexts up front for any
// invocation that won't actually reach fleetScan, instead of silently
// accepting the flag and scanning only one (default) context - the same
// silently-wrong-cluster failure mode #3217/#3218 closed for sequential
// scans in one process, recurring here as "the flag had no effect."
//
// --kube-contexts is registered on scanCmd's persistent flags, so cobra
// inherits it onto every subcommand (control/framework/workload/image) and
// it's accepted by --view=resource|control too, but only the default
// security view's securityScan, plus the framework/control/workload
// subcommands, currently call fleetScan. cmd here is the actual leaf
// command being invoked (cobra passes the target command to an inherited
// PersistentPreRunE, not the command it's defined on), so cmd.Name()
// reliably reports which one that is.
func validateKubeContextsSupported(cmd *cobra.Command, scanInfo *cautils.ScanInfo) error {
	if err := validateFleetReportValue(scanInfo.FleetReport); err != nil {
		return err
	}
	if fleetReportRequested(scanInfo.FleetReport) {
		if err := validateFleetReportPrivacyModes(scanInfo); err != nil {
			return err
		}
		if len(scanInfo.KubeContexts) == 0 {
			return fmt.Errorf("--fleet-report requires --kube-contexts: it aggregates the reports of a multi-context scan, so with a single context there is nothing to combine")
		}
	}
	if len(scanInfo.KubeContexts) == 0 {
		return nil
	}
	switch cmd.Name() {
	case "scan":
		if scanInfo.View != string(cautils.SecurityViewType) {
			return fmt.Errorf("--kube-contexts is not yet supported with --view=%s; only the default security view (no --view, or --view=%s) supports scanning multiple contexts in one run", scanInfo.View, cautils.SecurityViewType)
		}
	case "framework", "control", "workload":
		// These subcommands wire --kube-contexts through to fleetScan
		// themselves; nothing more to reject here.
	default:
		return fmt.Errorf("--kube-contexts is not yet supported for 'scan %s'; only the default 'scan' command (security view), 'scan framework', 'scan control', and 'scan workload' support scanning multiple contexts in one run", cmd.Name())
	}
	return nil
}

// fleetRunner runs one cluster's scan to completion for a specific scan
// subcommand - Scan/ScanContext, HandleResults, and every threshold/drift
// enforcement that subcommand's non-fleet RunE performs - exactly as if
// scanInfo.KubeContexts had never been set. securityScan, the framework
// command, the control command, and the workload command each pass their
// own such function (runSecurityScan, runFrameworkScan, runControlScan,
// runWorkloadScan) to fleetScan so every --kube-contexts-aware subcommand
// runs the exact per-cluster behavior its single-context path always ran,
// instead of a parallel, divergent copy of that logic.
//
// The results come back alongside the error rather than being consumed inside
// the runner, because --fleet-report aggregates them after every context has
// run. The two return values are independent: a non-nil ResultsHandler means
// the scan ran to completion and produced a report, whether or not the error is
// nil. A threshold breach, a coverage gate, or baseline drift all return the
// results together with the error that describes the breach, since the cluster
// was measured and the measurement is what the fleet report exists to carry. A
// nil ResultsHandler means the scan never produced one, and the error says why.
type fleetRunner func(ctx context.Context, scanInfo *cautils.ScanInfo, ks meta.IKubescape, policyIdentifiers []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error)

// fleetScan runs run once for every context in baseScanInfo.KubeContexts,
// sequentially, writing one report per context. It's the --kube-contexts
// entry point shared by every scan subcommand that supports fleet mode.
//
// Contexts are scanned one at a time, not concurrently: k8sinterface's
// process-global connection state (K8SConfig, clientConfigAPI,
// clusterContextName) has no locking around it, confirmed by go test -race
// while working on #3237 — running two contexts' scans concurrently would
// race on that state regardless of cautils.EnterClusterContext, which only
// makes *sequential* context switches safe.
//
// One context failing (connection error, threshold breach, degraded policy
// inputs, etc.) does not stop the remaining contexts from being attempted:
// a fleet scan should surface as much of the fleet's posture as it can
// rather than aborting on the first bad cluster. The command's overall
// error - and therefore its exit code - reflects whether any context
// failed, matching the single-context command's existing all-or-nothing
// exit-code semantics from the caller's point of view.
// validateFleetScanInvocation checks the CLI requirements for --kube-contexts
// before a fleet scan starts: live-cluster only, non-empty --output, and no
// colliding per-context output paths. Call sites that set SilenceUsage after
// validation use this so invalid fleet invocations still print usage.
// fleetReportRequested is the single definition of whether a fleet report was
// asked for, so validation and execution can never disagree about it.
//
// They did once. Validation tested the trimmed value while fleetScan tested the
// raw one, and --fleet-report " " fell through the gap: validation read it as
// absent and skipped the privacy check, then fleetScan read it as present and
// wrote a file named " " carrying the raw identifiers --hide exists to remove.
// validateFleetReportValue rejects that value outright, and everything else
// asks this one function.
func fleetReportRequested(fleetReport string) bool {
	return fleetReport != ""
}

// validateFleetReportValue rejects a --fleet-report that was given but holds
// only whitespace. Trimming it to empty and carrying on would silently drop a
// report the operator asked for; writing to it would create a file whose name
// is a space. Neither is what they meant, so it is an error rather than a
// guess.
func validateFleetReportValue(fleetReport string) error {
	if fleetReport != "" && strings.TrimSpace(fleetReport) == "" {
		return fmt.Errorf("--fleet-report %q is blank: it needs a path to write the combined report to", fleetReport)
	}
	return nil
}

// validateFleetReportPrivacyModes refuses --fleet-report alongside --hide or
// --encrypt.
//
// Both modes are applied per scan: anonymizer.Apply builds a fresh Mapping for
// each call, and the encrypted path generates a new DEK per context. The
// pseudonym or ciphertext standing for one cluster therefore has no relation to
// the one standing for the same cluster in another context's report, so nothing
// in the envelope could be joined across clusters anyway.
//
// Worse, the envelope's own identifiers do not go through either transform at
// all. ClusterID, Context, Metadata.Contexts and every matrix key come from the
// raw kubeconfig label, which for a provider-generated context routinely
// carries the project, account and cluster name. Writing those beside reports
// whose cluster metadata was deliberately pseudonymised would put back exactly
// what the operator asked to have removed, and would do it in the one file that
// spans the whole fleet.
//
// Supporting this properly means one mapping, or one key, shared across every
// context in the run, so the matrix still joins. That is a feature in its own
// right rather than something to infer here, so for now the combination is
// refused rather than silently under-protected.
func validateFleetReportPrivacyModes(scanInfo *cautils.ScanInfo) error {
	switch {
	case scanInfo.EncryptionEnabled:
		return fmt.Errorf("--fleet-report is not supported with --encrypt: each context's scan encrypts with its own key, so the combined report could not join them, and the fleet envelope's own cluster identifiers are not encrypted at all")
	case scanInfo.Hide:
		return fmt.Errorf("--fleet-report is not supported with --hide: each context's scan builds its own pseudonyms, so the combined report could not join them, and the fleet envelope's own cluster identifiers are taken from the kube context name rather than being hidden")
	}
	return nil
}

// printerDestinations returns every file the printers will actually write for
// one context's --output path, one per requested format.
//
// This is not the same as the --output path itself. Each printer passes the
// path through printer.ResolveOutputFile, which appends the format's extension
// when it is missing, so "--format json --output report" writes "report.json".
// Comparing the unresolved path would let two contexts, or a context and the
// fleet report, agree on a real destination while looking distinct.
//
// Formats that print to stdout contribute no destination.
func printerDestinations(outputPath string, formats []string) []string {
	if len(formats) == 0 {
		return []string{outputPath}
	}

	seen := make(map[string]struct{}, len(formats))
	destinations := make([]string, 0, len(formats))
	for _, format := range formats {
		resolved, explicit := printer.ResolveOutputFile(format, outputPath, "")
		if !explicit || resolved == "" {
			continue
		}
		if _, ok := seen[resolved]; ok {
			continue
		}
		seen[resolved] = struct{}{}
		destinations = append(destinations, resolved)
	}
	return destinations
}

func validateFleetScanInvocation(scanInfo *cautils.ScanInfo) (map[string]string, error) {
	if scanInfo.GetScanningContext() != cautils.ContextCluster {
		return nil, fmt.Errorf("--kube-contexts requires a live-cluster scan: it selects which cluster to connect to, so it can't be combined with scanning local files/directories")
	}
	if strings.TrimSpace(scanInfo.Output) == "" {
		return nil, fmt.Errorf("--kube-contexts requires --output: each context's report is written to its own file, derived from --output, since only one context's results can be printed to stdout at a time")
	}
	if err := validateFleetReportValue(scanInfo.FleetReport); err != nil {
		return nil, err
	}
	// Re-checked here rather than trusted from PersistentPreRunE, so the
	// privacy boundary holds for every path that reaches fleetScan.
	if fleetReportRequested(scanInfo.FleetReport) {
		if err := validateFleetReportPrivacyModes(scanInfo); err != nil {
			return nil, err
		}
	}

	formats := scanInfo.Formats()
	outputPaths, err := perContextOutputPaths(scanInfo.Output, scanInfo.KubeContexts, formats)
	if err != nil {
		return nil, err
	}
	if err := validateFleetReportPath(scanInfo.FleetReport, outputPaths, formats); err != nil {
		return nil, err
	}
	return outputPaths, nil
}

// validateFleetReportPath rejects a --fleet-report path that would land on top
// of one of the per-context reports. The per-context file is written first,
// during that context's scan, and the fleet report is written last, so the
// collision would not fail: the fleet report would silently replace one
// cluster's own report and both writes would look successful.
//
// It compares against the destinations the printers resolve to, not the raw
// --output paths, since those differ whenever a format appends an extension.
func validateFleetReportPath(fleetReport string, outputPaths map[string]string, formats []string) error {
	if !fleetReportRequested(fleetReport) {
		return nil
	}
	return fleetReportAliasesPerContextReport(fleetReport, outputPaths, formats)
}

// fleetReportAliasesPerContextReport catches aliases that string comparison
// cannot. Atomic publication replaces a symlink in the final path component,
// but a symlinked parent directory can still route the write onto a
// per-context report. Existing files may also alias through hard links.
//
// Both sides are reduced to the same canonical form before comparing, see
// resolvePath, so it does not matter whether the link is the final component,
// a parent directory, dangling, or on the --output side rather than the
// --fleet-report side. File identity via os.SameFile is kept as a second check
// for what a path walk cannot see, such as a hard link; it only applies when
// both files exist.
func fleetReportAliasesPerContextReport(fleetReport string, outputPaths map[string]string, formats []string) error {
	target, err := resolvePath(fleetReport)
	if err != nil {
		return fmt.Errorf("--fleet-report %q: %w", fleetReport, err)
	}
	fleetInfo, fleetExists := existingFileTarget(fleetReport)

	for kubeContext, path := range outputPaths {
		for _, destination := range printerDestinations(path, formats) {
			resolved, err := resolvePath(destination)
			if err != nil {
				return fmt.Errorf("--output for %q: %w", kubeContext, err)
			}
			if resolved == target {
				return fmt.Errorf("--fleet-report %q resolves to the per-context report for %q; the fleet report would overwrite it", fleetReport, kubeContext)
			}
			if !fleetExists {
				continue
			}
			if info, ok := existingFileTarget(destination); ok && os.SameFile(fleetInfo, info) {
				return fmt.Errorf("--fleet-report %q resolves to the per-context report for %q; the fleet report would overwrite it", fleetReport, kubeContext)
			}
		}
	}
	return nil
}

// resolvePath returns the file a create at path would actually land on,
// whether or not anything exists there yet.
//
// It walks the components left to right and resolves each one as the kernel
// does when it opens the path, because the order matters and no amount of
// string tidying reproduces it. filepath.Abs and filepath.Clean collapse
// "link/.." lexically, dropping the link before it is ever followed, while an
// open resolves "link" to its target first and only then applies "..". For a
// link pointing at target/sub the two disagree completely: cleaning says the
// directory holding the link, the kernel says target.
//
// A component that does not exist is taken as itself. The fleet report's
// directory is created before the write, so a missing directory here is one
// that will exist by then, and a missing final component is the file about to
// be created.
func resolvePath(path string) (string, error) {
	const maxHops = 64

	anchor := path
	remaining := splitPath(path)
	if !filepath.IsAbs(path) {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		// The components are concatenated rather than the paths, because
		// filepath.Join would clean the result and undo the very distinction
		// this function exists to preserve.
		anchor = cwd
		remaining = append(splitPath(cwd), remaining...)
	}

	resolved := rootOf(anchor)
	hops := 0

	for len(remaining) > 0 {
		component := remaining[0]
		remaining = remaining[1:]

		switch component {
		case ".", "":
			continue
		case "..":
			resolved = filepath.Dir(resolved)
			continue
		}

		next := filepath.Join(resolved, component)
		info, err := os.Lstat(next)
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			resolved = next
			continue
		}

		hops++
		if hops > maxHops {
			return "", fmt.Errorf("too many levels of symbolic links resolving %q", path)
		}
		target, err := os.Readlink(next)
		if err != nil {
			return "", err
		}
		if filepath.IsAbs(target) {
			resolved = rootOf(target)
		}
		// Splice the link's own components in front of what is left, so a ".."
		// that followed the link is applied to where the link actually led.
		remaining = append(splitPath(target), remaining...)
	}

	return resolved, nil
}

// splitPath breaks path into its components, dropping the leading root and any
// empty segments left by repeated or trailing separators.
func splitPath(path string) []string {
	normalised := strings.ReplaceAll(path, "\\", "/")
	trimmed := strings.TrimPrefix(normalised, strings.ReplaceAll(rootOf(path), "\\", "/"))
	components := make([]string, 0, 8)
	for _, part := range strings.Split(trimmed, "/") {
		if part != "" {
			components = append(components, part)
		}
	}
	return components
}

// rootOf returns the anchor a walk over path starts from: the volume name plus
// separator on Windows, and the separator elsewhere.
func rootOf(path string) string {
	if volume := filepath.VolumeName(path); volume != "" {
		return volume + string(os.PathSeparator)
	}
	return string(os.PathSeparator)
}

// existingFileTarget follows path through any symlinks to the file it names
// and reports whether such a file exists. Every failure, a missing file, a
// dangling link, a parent that is not a directory, means the same thing to the
// identity check: there is no existing file here to compare against.
func existingFileTarget(path string) (os.FileInfo, bool) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, false
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return nil, false
	}
	return info, true
}

// fleetScan runs run once for every context in baseScanInfo.KubeContexts,
// sequentially, writing one report per context and, when --fleet-report is
// set, one combined fleet.FleetReport across all of them afterwards.
//
// The per-context behaviour is unchanged by the fleet report. Each context's
// own file is still written by its runner, a failing context still does not
// stop the ones after it, and the returned error still reflects whether any
// context failed, so the exit code a CI job sees is the same with or without
// --fleet-report. Failing to write the fleet report is reported through the
// same error, since a run that scanned everything but could not save the
// result it was asked for has not done what was asked.
func fleetScan(baseScanInfo cautils.ScanInfo, ks meta.IKubescape, policyIdentifiers []cautils.PolicyIdentifier, run fleetRunner) error {
	outputPaths, err := validateFleetScanInvocation(&baseScanInfo)
	if err != nil {
		return err
	}

	// Per-cluster results are only retained when a fleet report was asked for.
	// A plain --kube-contexts run keeps its memory profile: each context's
	// results are released as soon as that context is done, exactly as before.
	wantFleetReport := fleetReportRequested(baseScanInfo.FleetReport)

	var failed []string
	var clusters []fleet.ClusterResult
	if wantFleetReport {
		clusters = make([]fleet.ClusterResult, 0, len(baseScanInfo.KubeContexts))
	}
	for _, kubeContext := range baseScanInfo.KubeContexts {
		outputPath := outputPaths[kubeContext]

		contextScanInfo := baseScanInfo.CloneForContext(kubeContext, outputPath)

		logger.L().Info("fleet scan: scanning context", helpers.String("context", kubeContext), helpers.String("output", outputPath))

		results, elapsed, err := runFleetContext(kubeContext, contextScanInfo, ks, policyIdentifiers, run)

		if wantFleetReport {
			clusters = append(clusters, newClusterResult(kubeContext, results, err, elapsed))
		}

		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: %s", kubeContext, err))
			logger.L().Error("fleet scan: context failed", helpers.String("context", kubeContext), helpers.Error(err))
			continue
		}
		logger.L().Success("fleet scan: context completed", helpers.String("context", kubeContext))
	}

	var fleetReportErr error
	if wantFleetReport {
		report := fleet.FleetReport{
			Metadata: fleet.FleetMetadata{
				GeneratedAt:      time.Now().UTC(),
				KubescapeVersion: versioncheck.BuildNumber,
				Contexts:         baseScanInfo.KubeContexts,
			},
			Clusters: clusters,
			// --fail-coverage-below is the operator's own statement of the
			// coverage they are prepared to stand behind, so the rollup reuses
			// it rather than introducing a second, separate threshold that
			// could contradict it. Unset means no floor.
			Compliance:    fleet.BuildComplianceRollup(clusters, baseScanInfo.FailCoverageThreshold),
			ControlMatrix: fleet.BuildControlMatrix(clusters),
		}
		// Re-check after the per-context files exist so os.SameFile can detect
		// hard-link aliases that were not observable before the scans ran.
		fleetReportErr = fleetReportAliasesPerContextReport(baseScanInfo.FleetReport, outputPaths, baseScanInfo.Formats())
		if fleetReportErr == nil {
			fleetReportErr = writeFleetReport(baseScanInfo.FleetReport, &report)
		}
		if fleetReportErr == nil {
			logger.L().Success("fleet scan: fleet report written", helpers.String("output", baseScanInfo.FleetReport))
		} else {
			logger.L().Error("fleet scan: fleet report not written", helpers.String("output", baseScanInfo.FleetReport), helpers.Error(fleetReportErr))
		}
	}

	// The fleet report is not a context, so its failure is reported beside the
	// context tally rather than inside it. Folding it into the count would
	// print "1 of 1 context(s) failed" for a run in which the only context
	// succeeded.
	switch {
	case len(failed) > 0 && fleetReportErr != nil:
		return fmt.Errorf("fleet scan: %d of %d context(s) failed:\n%s\nfleet report: %w", len(failed), len(baseScanInfo.KubeContexts), strings.Join(failed, "\n"), fleetReportErr)
	case len(failed) > 0:
		return fmt.Errorf("fleet scan: %d of %d context(s) failed:\n%s", len(failed), len(baseScanInfo.KubeContexts), strings.Join(failed, "\n"))
	case fleetReportErr != nil:
		return fmt.Errorf("fleet scan: every context was scanned but the fleet report was not written: %w", fleetReportErr)
	}
	return nil
}

// runFleetContext scopes the Kubernetes context and timeout to one fleet
// iteration. The deferred cleanup satisfies EnterClusterContext's contract on
// normal returns, errors and panics without deferring across the whole loop.
func runFleetContext(kubeContext string, scanInfo *cautils.ScanInfo, ks meta.IKubescape, policyIdentifiers []cautils.PolicyIdentifier, run fleetRunner) (results *resultshandling.ResultsHandler, elapsed time.Duration, err error) {
	leave := cautils.EnterClusterContext(kubeContext)
	defer leave()

	ctx, cancel := deriveTimeoutContext(scanInfo, ks)
	defer cancel()

	started := time.Now()
	results, err = run(ctx, scanInfo, ks, policyIdentifiers)
	return results, time.Since(started), err
}

// newClusterResult turns one context's outcome into the row the fleet report
// carries for it.
//
// Whether the cluster counts as scanned is decided by the results, not by the
// error. Every runner returns its results together with an error for a
// threshold breach, a coverage gate or baseline drift, and in all of those the
// cluster was measured. Classifying on the error alone would drop exactly the
// clusters an operator most needs to see, the ones that failed their gate,
// from the matrix, and leave them with no report and no cells.
//
// Only a run that produced nothing is classified by its error. A cancelled or
// expired context means the run was interrupted, so nothing was learned about
// the cluster; a per-cluster --scan-timeout firing lands here for the same
// reason, since the deadline says how long the operator was prepared to wait
// rather than anything about the cluster. core.ErrClusterConnection means the
// API server was never reached. Anything else is an error inside the scan.
//
// The embedded report is the full one. --min-severity and --max-severity are
// output-only by design: HandleResults applies them for the printers and then
// restores the report, so that thresholds, coverage and telemetry all see the
// complete result. The fleet report sits on the same side of that line as the
// thresholds do, since an aggregate built from a narrowed view would compare
// clusters on whatever each run happened to be asked to display.
//
// Raw resources are dropped from the embedded report. Each context's own
// output file already carries them, and keeping every cluster's manifests
// resident until the last context finishes would make the fleet report's
// memory cost scale with the size of the fleet rather than with the size of
// its largest cluster. The summary and the per-resource results stay, which is
// what the aggregation reads.
func newClusterResult(kubeContext string, results *resultshandling.ResultsHandler, err error, elapsed time.Duration) fleet.ClusterResult {
	cluster := fleet.ClusterResult{
		ClusterID: kubeContext,
		Context:   kubeContext,
		Duration:  elapsed.String(),
	}

	if results == nil {
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			cluster.Status = fleet.ClusterCancelled
		case errors.Is(err, core.ErrClusterConnection):
			cluster.Status = fleet.ClusterUnreachable
		default:
			cluster.Status = fleet.ClusterError
		}
		if err != nil {
			cluster.Error = err.Error()
		}
		return cluster
	}

	report := results.GetResults()
	report.Resources = nil

	score := results.GetComplianceScore()
	coverage := results.GetData().ScanCoverage

	cluster.Status = fleet.ClusterScanned
	cluster.Report = report
	cluster.ComplianceScore = &score
	cluster.Coverage = &coverage
	return cluster
}

// writeFleetReport serialises the report to path as indented JSON. The
// destination is replaced atomically only after the complete report has been
// encoded and flushed, so a failed write cannot destroy a previous good
// report or leave a truncated report that still looks like the latest run.
func writeFleetReport(path string, report *fleet.FleetReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("encode fleet report %q: %w", path, err)
	}
	data = append(data, '\n')
	if err := cautils.WriteFileAtomically(path, data, 0o644); err != nil {
		return fmt.Errorf("write fleet report %q: %w", path, err)
	}
	return nil
}

// perContextOutputPaths derives every context's own report path from the
// --output the user gave for the fleet as a whole, and rejects the whole
// batch up front if any two contexts would derive the same path. Two
// distinct context names can sanitize to the same string (e.g.
// "prod/us-east-1" and "prod_us-east-1" both become "prod_us-east-1"), which
// would otherwise make the second scan's report silently overwrite the
// first's - both scans "succeed" from fleetScan's point of view, so nothing
// would ever surface the clobbered report as an error. Failing fast here
// with the colliding context names named explicitly is far more useful than
// discovering it later from a report that doesn't match its own context.
func perContextOutputPaths(output string, kubeContexts, formats []string) (map[string]string, error) {
	paths := make(map[string]string, len(kubeContexts))
	collisions := make(map[string][]string) // destination -> contexts that derived it

	for _, kubeContext := range kubeContexts {
		path, err := perContextOutputPath(output, kubeContext)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", kubeContext, err)
		}
		paths[kubeContext] = path
		// Keyed on what the printers actually write, so two contexts whose
		// --output paths differ only by an extension a format then appends,
		// such as "report.prod" and "report.prod.json" under --format json,
		// are still caught.
		for _, destination := range printerDestinations(path, formats) {
			collisions[destination] = append(collisions[destination], kubeContext)
		}
	}

	// printerDestinations already de-duplicates within one context, so a
	// context appears at most once under any destination.
	var conflicts []string
	for path, contexts := range collisions {
		if len(contexts) > 1 {
			conflicts = append(conflicts, fmt.Sprintf("%s -> %s", strings.Join(contexts, ", "), path))
		}
	}
	if len(conflicts) > 0 {
		sort.Strings(conflicts)
		return nil, fmt.Errorf("--kube-contexts: %d context(s) derive a colliding --output path with another context, so their reports would silently overwrite each other:\n%s", len(conflicts), strings.Join(conflicts, "\n"))
	}

	return paths, nil
}

// perContextOutputPath derives context's own report path from the
// --output the user gave for the fleet as a whole, by inserting a
// filesystem-safe form of context before the final extension: report.json +
// "kind-fleet-test-a" -> report.kind-fleet-test-a.json. Path separators in
// context (which kube context names can technically contain, e.g. some
// cloud-provider-generated names) are replaced so the result can't escape
// the output directory or be misread as one. Callers scanning a batch of
// contexts should use perContextOutputPaths instead, which also rejects
// collisions between two different contexts' derived paths.
func perContextOutputPath(output, kubeContext string) (string, error) {
	sanitized := strings.NewReplacer("/", "_", "\\", "_", string(filepath.Separator), "_").Replace(kubeContext)
	sanitized = strings.TrimSpace(sanitized)
	if sanitized == "" {
		return "", fmt.Errorf("empty kube context name")
	}

	dir, base := filepath.Split(output)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	return filepath.Join(dir, stem+"."+sanitized+ext), nil
}
