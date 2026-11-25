package scan

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"maps"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/core"
	"github.com/kubescape/kubescape/v4/core/pkg/resourcehandler"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/diff"
	"github.com/kubescape/kubescape/v4/core/pkg/watch"
	"github.com/spf13/cobra"
)

// maxListedFindings is how many findings of one kind a scan lists before it
// says how many more there are.
const maxListedFindings = 20

// watchIncompatibleFlags are the flags that shape the report a scan writes, or
// the exit code it gives, or send its results somewhere. A watch has none of
// those: it reads what changed between scans from memory and prints it, so a flag
// that would be silently ignored is refused instead.
var watchIncompatibleFlags = []string{
	"format", "output", "notify", "submit",
	"min-severity", "max-severity",
	"baseline", "baseline-fail-on-new", "baseline-severity-threshold", "baseline-granularity",
	"compliance-threshold", "severity-threshold", "fail-coverage-below", "fail-on-degraded-config",
	"scan-images", "dry-run", "encrypt",
	"kube-context", "kube-contexts", "fleet-config", "fleet-report",
}

// validateWatchFlags refuses the invocations that --watch cannot serve, before
// anything is prepared or scanned.
func validateWatchFlags(cmd *cobra.Command, scanInfo *cautils.ScanInfo, args []string) error {
	for _, name := range watchIncompatibleFlags {
		if flag := cmd.Flags().Lookup(name); flag != nil && flag.Changed {
			return fmt.Errorf("invalid arguments: --%s cannot be used with --watch", name)
		}
	}
	if len(scanInfo.KubeContexts) > 0 || scanInfo.ScanImages || scanInfo.DryRun || scanInfo.EncryptionEnabled {
		return errors.New("invalid arguments: --watch scans local manifests only, with no cluster, image scan, dry run or encryption")
	}
	// The effective value, which a scan contract can set as well as the flag: a
	// watch tells one finding from another by the resources the report holds.
	if scanInfo.OmitRawResources {
		return errors.New("invalid arguments: --omit-raw-resources cannot be used with --watch: a watch compares scans by the resources in their reports, which this option leaves out")
	}
	if scanInfo.View != string(cautils.SecurityViewType) {
		return fmt.Errorf("invalid arguments: --watch supports only the default --view=%s", cautils.SecurityViewType)
	}
	inputs := args
	if scanInfo.FilePath != "" {
		inputs = append([]string{scanInfo.FilePath}, args...)
	}
	if len(inputs) == 0 && len(scanInfo.InputPatterns) == 0 {
		return errors.New("invalid arguments: --watch needs the files or directories to watch, as in 'scan ./manifests --watch'; a cluster cannot be watched")
	}
	for _, input := range inputs {
		if input == "-" {
			return errors.New("invalid arguments: --watch cannot watch standard input")
		}
	}
	return nil
}

// localScannerFactory is the part of the scan engine a watch uses. It is not
// part of meta.IKubescape, which would have every implementation of it follow.
type localScannerFactory interface {
	NewLocalScanner(base *cautils.ScanInfo, ids []cautils.PolicyIdentifier) (*core.LocalScanner, error)
}

// watchRoots are the files and directories to watch for the scan's inputs. A
// glob input, as in ./manifests/*.yaml, is not a path that can be watched: it is
// watched through the directory the scanner lists it from, and a directory that
// several inputs share is watched once. A kustomization or a Terraform file is
// rendered with the rest of its directory (the resources and patches it lists,
// the other .tf and .tfvars files), so it is watched through that directory too.
func watchRoots(inputs []string) []string {
	roots := make([]string, 0, len(inputs))
	seen := make(map[string]struct{}, len(inputs))
	for _, input := range inputs {
		root, _ := cautils.GlobInputRoot(input)
		if cautils.IsKustomizeFile(root) || cautils.IsTerraformFile(root) {
			root = filepath.Dir(root)
		}
		key := filepath.Clean(root)
		if abs, err := filepath.Abs(root); err == nil {
			key = abs
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		roots = append(roots, root)
	}
	return roots
}

// inKustomizationBelow reports whether path is in a kustomization's directory,
// its own or one between it and root. A directory scan renders every
// kustomization it finds below root, not only one at root, and a kustomization
// reads the files at or below its own directory.
func inKustomizationBelow(root, path string) bool {
	return inDirectoryBelow(root, path, cautils.IsKustomizeDirectory)
}

// inHelmChartBelow reports whether path is in a Helm chart's directory, its own
// or one between it and root. A directory scan renders every chart it finds
// below root, and a chart's templates read the chart's own files through .Files
// (configuration files, scripts) and its vendored subcharts from charts/,
// whatever their extension, so a change to any of them can change what is
// scanned.
func inHelmChartBelow(root, path string) bool {
	return inDirectoryBelow(root, path, isHelmChartDirectory)
}

// isHelmChartDirectory is the chart check chart discovery uses.
func isHelmChartDirectory(dir string) bool {
	isChart, err := cautils.IsHelmDirectory(dir)
	return err == nil && isChart
}

// inDirectoryBelow reports whether path is in a directory that rendered
// reports as rendered input, its own or one between it and root.
func inDirectoryBelow(root, path string, rendered func(dir string) bool) bool {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}

	root = filepath.Clean(absRoot)
	for dir := filepath.Dir(filepath.Clean(absPath)); ; dir = filepath.Dir(dir) {
		if rendered(dir) {
			return true
		}
		if dir == root || filepath.Dir(dir) == dir {
			return false
		}
	}
}

func isRenderedDirectory(root string, inputs []string) bool {
	cleaned := filepath.Clean(root)
	for _, input := range inputs {
		inputRoot, _ := cautils.GlobInputRoot(input)
		if cautils.IsKustomizeFile(inputRoot) || cautils.IsTerraformFile(inputRoot) {
			if filepath.Clean(filepath.Dir(inputRoot)) == cleaned {
				return true
			}
		}
	}
	return cautils.IsKustomizeDirectory(root)
}

// watchSecurityScan runs `kubescape scan <paths> --watch`: it scans the local
// inputs, and again whenever one of them changes, until the context ends.
func watchSecurityScan(cmd *cobra.Command, ks interface{ Context() context.Context }, scanInfo *cautils.ScanInfo, ids []cautils.PolicyIdentifier) error {
	factory, ok := ks.(localScannerFactory)
	if !ok {
		return errors.New("--watch is not supported by this build")
	}
	switch scanInfo.GetScanningContext() {
	case cautils.ContextDir, cautils.ContextFile, cautils.ContextGitLocal:
	default:
		return errors.New("invalid arguments: --watch needs local files or directories to watch")
	}
	roots := watchRoots(scanInfo.InputPatterns)
	scanner, err := factory.NewLocalScanner(scanInfo, ids)
	if err != nil {
		return err
	}

	cmd.SilenceUsage = true
	timeout := scanInfo.ScanTimeout
	return runWatch(ks.Context(), watchConfig{
		Roots:                      roots,
		TrackKustomizeDependencies: true,
		AcceptDependencies: func(root, path string) bool {
			return isRenderedDirectory(root, scanInfo.InputPatterns) || inKustomizationBelow(root, path) || inHelmChartBelow(root, path)
		},
		Exclude: func(root string) (func(string, bool) bool, error) {
			filter, err := newReloadingFilter(root, scanInfo.ExcludePaths, !scanInfo.NoIgnoreFile)
			if err != nil {
				return nil, err
			}
			return filter.Excluded, nil
		},
		Scan: func(ctx context.Context) (*watchScan, error) {
			if timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, timeout)
				defer cancel()
			}
			result, err := scanner.Scan(ctx, core.LocalInput{})
			if err != nil {
				return nil, err
			}
			return watchScanOf(result)
		},
		Out:    cmd.OutOrStdout(),
		ErrOut: cmd.ErrOrStderr(),
	})
}

// reloadingFilter is the scan's path filter for a watched root, made again when
// the root's ignore file changes: the scan reads that file on every run, so the
// watch has to exclude what the next scan excludes, not what the first one did.
type reloadingFilter struct {
	root          string
	patterns      []string
	useIgnoreFile bool
	ignoreFile    string

	mu      sync.Mutex
	version string // digest of the ignore file's lines when filter was made
	filter  *cautils.PathFilter
}

func newReloadingFilter(root string, patterns []string, useIgnoreFile bool) (*reloadingFilter, error) {
	f := &reloadingFilter{root: root, patterns: patterns, useIgnoreFile: useIgnoreFile}
	if useIgnoreFile {
		f.ignoreFile = filepath.Join(cautils.IgnoreRoot(root), cautils.IgnoreFileName)
	}
	f.version = f.ignoreFileVersion()
	filter, err := cautils.NewScanPathFilter(root, patterns, useIgnoreFile)
	if err != nil {
		return nil, err
	}
	f.filter = filter
	return f, nil
}

func (f *reloadingFilter) ignoreFileVersion() string {
	if f.ignoreFile == "" {
		return ""
	}
	// Use the scan's bounded reader, including its regular-file checks. File
	// size and mtime alone miss edits made by timestamp-preserving tools.
	patterns, err := cautils.LoadIgnoreFilePatterns(filepath.Dir(f.ignoreFile))
	if err != nil {
		return f.version // retain the last usable filter until the file is readable
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(patterns, "\n"))))
}

// Excluded is (*cautils.PathFilter).Excluded with the filter made again first if
// the ignore file changed. A file that cannot be read or parsed as it is now, as
// in the middle of an edit, leaves the previous filter in place.
func (f *reloadingFilter) Excluded(path string, isDir bool) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if version := f.ignoreFileVersion(); version != f.version {
		if filter, err := cautils.NewScanPathFilter(f.root, f.patterns, f.useIgnoreFile); err == nil {
			f.filter, f.version = filter, version
		}
	}
	return f.filter.Excluded(path, isDir)
}

// watchScanOf takes from a scan's result what a watch needs of it. The report is
// made once here, and it is what the baseline reads.
func watchScanOf(result *core.ScanResult) (*watchScan, error) {
	reportJSON, err := result.JSON()
	if err != nil {
		return nil, err
	}
	scan := &watchScan{ReportJSON: reportJSON}
	if result.Session != nil && result.Session.Report != nil {
		summary := &result.Session.Report.SummaryDetails
		scan.FailedControls = summary.NumberOfControls().Failed()
		scan.FailedResources = summary.NumberOfResources().Failed()
	}
	return scan, nil
}

// watchScan is what a watch needs of one scan: its report, for the baseline, and
// the totals to tell of a first scan, which has nothing to be compared with.
type watchScan struct {
	ReportJSON      []byte
	FailedControls  int
	FailedResources int
}

type watchConfig struct {
	// Roots are the files and directories scanned, and watched.
	Roots []string
	// TrackKustomizeDependencies watches inputs consulted by the render as
	// well as paths selected for scan discovery.
	TrackKustomizeDependencies bool
	// AcceptDependencies reports whether a file at path, in the watch of root,
	// should be accepted as a dependency regardless of its extension, because
	// a render reads its directory. It is consulted as files change, so a
	// directory that becomes one when a kustomization appears, or stops being
	// one when it is removed, is classified as it is at that moment.
	AcceptDependencies func(root, path string) bool
	// Exclude gives the filter of what a root leaves out of the watch, the one
	// its scan applies. Nil leaves nothing out.
	Exclude func(root string) (func(path string, isDir bool) bool, error)
	// Scan scans the roots. It returns when its context ends.
	Scan func(ctx context.Context) (*watchScan, error)
	// Debounce is how long after the last change the next scan waits. Zero is
	// the scheduler's default.
	Debounce time.Duration
	// Out is where the progress and the findings are written, ErrOut where the
	// problems are.
	Out, ErrOut io.Writer
}

// runWatch is the watch: a FileWatcher for each root signals into one channel, a
// Scheduler scans on that channel, and a Baseline says what each scan changed.
// It returns nil when ctx ends, which is how a watch is stopped, and an error
// when the watch could not start or could not go on: a root that cannot be
// watched, a watcher that stopped, a first scan that failed. Every watcher and
// goroutine it started has ended when it returns.
func runWatch(ctx context.Context, cfg watchConfig) error {
	out := &lockedWriter{w: cfg.Out}
	errOut := &lockedWriter{w: cfg.ErrOut}

	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	var watchers []*watch.FileWatcher
	closeWatchers := func() {
		for _, watcher := range watchers {
			_ = watcher.Close()
		}
	}
	defer closeWatchers()
	for _, root := range cfg.Roots {
		var exclude func(string, bool) bool
		if cfg.Exclude != nil {
			var err error
			if exclude, err = cfg.Exclude(root); err != nil {
				return fmt.Errorf("--watch: %w", err)
			}
		}
		var acceptDependencies func(string) bool
		if cfg.AcceptDependencies != nil {
			acceptDependencies = func(path string) bool { return cfg.AcceptDependencies(root, path) }
		}
		watcher, err := watch.NewFileWatcher(ctx, root, watch.FileWatcherOptions{
			AcceptDependencies: acceptDependencies,
			Exclude:            exclude,
			OnError:            func(err error) { fmt.Fprintf(errOut, "Warning: %v\n", err) },
		})
		if err != nil {
			return fmt.Errorf("--watch: %w", err)
		}
		watchers = append(watchers, watcher)
	}

	// One signal, however many roots changed: the watchers' channels are merged
	// into one of capacity one that is sent to without blocking, which is what the
	// scheduler expects of its channel.
	changes := make(chan struct{}, 1)
	signal := func() {
		select {
		case changes <- struct{}{}:
		default:
		}
	}
	var forwarders sync.WaitGroup
	for _, watcher := range watchers {
		forwarders.Add(1)
		go func() {
			defer forwarders.Done()
			for range watcher.Changes() {
				signal()
			}
			// The channel closes when the watcher ends: with the context, which is
			// the end of the watch, or on its own, which is a watch that can no
			// longer see changes and says why.
			if ctx.Err() == nil {
				cancel(fmt.Errorf("the watch ended: %w", watcher.Err()))
			}
		}()
	}

	scan := cfg.Scan
	if cfg.TrackKustomizeDependencies {
		var lastFiles, lastCharts map[string]struct{}
		scan = func(ctx context.Context) (*watchScan, error) {
			files, charts := make(map[string]struct{}), make(map[string]struct{})
			result, scanErr := cfg.Scan(cautils.WithKustomizeDependencyObserver(ctx, func(path string, chart bool) {
				if chart {
					charts[path] = struct{}{}
				} else {
					files[path] = struct{}{}
				}
			}))
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if scanErr != nil {
				// A failed scan can stop before it reads any render inputs.
				// Keep the prior watches and add paths that could repair it.
				if len(files) == 0 && len(charts) == 0 {
					return result, scanErr
				}
				maps.Copy(files, lastFiles)
				maps.Copy(charts, lastCharts)
			}
			added, err := watch.ReplaceRenderDependencies(ctx, watchers, files, charts)
			if err != nil {
				return nil, err
			}
			lastFiles, lastCharts = files, charts
			if added {
				// Reread inputs that could have changed before their new
				// watches were installed, using the normal scan budget.
				signal()
			}
			return result, scanErr
		}
	}

	session := &watchSession{
		scan:     scan,
		baseline: watch.NewBaseline(),
		out:      out,
		errOut:   errOut,
		cancel:   cancel,
	}
	scheduler := watch.NewScheduler(changes, session.scanOnce, watch.SchedulerOptions{
		Debounce: cfg.Debounce,
		OnError:  func(err error) { fmt.Fprintf(errOut, "Scan failed: %v\n", err) },
	})

	fmt.Fprintf(out, "Watching %s for changes. Press Ctrl+C to stop.\n", strings.Join(cfg.Roots, ", "))
	runErr := scheduler.Run(ctx)

	cancel(nil)
	closeWatchers()
	forwarders.Wait()

	if cause := context.Cause(ctx); cause != nil && !errors.Is(cause, context.Canceled) {
		fmt.Fprintln(out, "Watch stopped.")
		return cause
	}
	if runErr != nil && !errors.Is(runErr, context.Canceled) && !errors.Is(runErr, context.DeadlineExceeded) {
		fmt.Fprintln(out, "Watch stopped.")
		return runErr
	}
	fmt.Fprintln(out, "Watch stopped.")
	return nil
}

// watchSession is the state of a watch between scans.
type watchSession struct {
	scan     func(ctx context.Context) (*watchScan, error)
	baseline *watch.Baseline
	out      io.Writer
	errOut   io.Writer
	cancel   context.CancelCauseFunc
	scans    int // scans that were started, the first one included
}

// scanOnce is what the scheduler runs: one scan, then what it made of the
// baseline. It is only called from the scheduler's goroutine, one at a time.
func (s *watchSession) scanOnce(ctx context.Context) error {
	first := s.scans == 0
	s.scans++
	if first {
		fmt.Fprintln(s.out, "Running the initial scan...")
	} else {
		fmt.Fprintln(s.out, "Change detected, scanning again...")
	}

	scan, scanErr := s.scan(ctx)
	var reportJSON []byte
	if scan != nil {
		reportJSON = scan.ReportJSON
	}
	if scanErr != nil && ctx.Err() != nil {
		return ctx.Err() // cut short by the end of the watch: not a scan, and not reported
	}
	if scanErr != nil && first {
		if !isInputError(scanErr) {
			// A first scan that fails is a watch that was set up wrong, such as policies
			// that cannot be loaded, and not one a change to a manifest would mend.
			s.cancel(fmt.Errorf("the initial scan failed: %w", scanErr))
			return scanErr
		}
		return fmt.Errorf("the initial scan found nothing it could scan yet, so the watch waits for a change: %w", scanErr)
	}
	observation, err := s.baseline.Observe(reportJSON, scanErr, diff.Options{Granularity: diff.GranularityEvidence})
	if err != nil {
		return err
	}
	s.report(scan, observation)
	return nil
}

// isInputError reports whether a scan failed on what it was given to read: no
// manifest yet, one that does not parse, or no Kubernetes object in the files.
// An edit to a manifest mends each of them, so the watch keeps watching, even
// when the first scan is the one that failed.
func isInputError(err error) bool {
	return errors.Is(err, cautils.ErrNoManifestFiles) ||
		errors.Is(err, cautils.ErrManifestsNotLoaded) ||
		errors.Is(err, resourcehandler.ErrNoScannableResources)
}

// report says what a scan found, in terms of the baseline it was compared with.
func (s *watchSession) report(scan *watchScan, observation *watch.Observation) {
	if len(observation.Gaps) > 0 {
		fmt.Fprintf(s.out, "Scan incomplete, so it is not kept as the baseline: %s.\n", strings.Join(observation.Gaps, "; "))
	}
	for _, note := range observation.Notes {
		fmt.Fprintf(s.out, "Note: %s.\n", note)
	}

	result := observation.Result
	if result == nil {
		if observation.Initial {
			fmt.Fprintf(s.out, "Initial scan complete: %d failing control(s) on %d resource(s). Later scans are compared with it.\n", scan.FailedControls, scan.FailedResources)
		} else {
			fmt.Fprintf(s.out, "Scan complete: %d failing control(s) on %d resource(s). There is no baseline yet to compare with.\n", scan.FailedControls, scan.FailedResources)
		}
		return
	}

	for _, warning := range result.Warnings {
		fmt.Fprintf(s.out, "Warning: %s\n", warning)
	}
	changed := len(result.New) + len(result.Changed) + len(result.Resolved) + len(result.Removed) + len(result.Renamed) + len(result.Incomparable)
	if changed == 0 {
		fmt.Fprintf(s.out, "No change in findings (%d existing).\n", len(result.Existing))
		return
	}
	fmt.Fprintf(s.out, "Findings: %d new, %d resolved, %d changed, %d removed, %d renamed, %d existing, %d not comparable.\n",
		len(result.New), len(result.Resolved), len(result.Changed), len(result.Removed), len(result.Renamed), len(result.Existing), len(result.Incomparable))
	s.list("new", "+", result.New)
	s.list("resolved", "-", result.Resolved)
	s.list("removed with their resource", "-", result.Removed)
	s.list("not comparable", "?", result.Incomparable)
	for _, finding := range limit(result.Changed) {
		fmt.Fprintf(s.out, "  ~ %s\n      moved from %q to %q\n", describe(finding.After), finding.Before.Path, finding.After.Path)
	}
	for _, finding := range limit(result.Renamed) {
		fmt.Fprintf(s.out, "  > %s\n      moved with its resource from %s\n", describe(finding.Finding), finding.From)
	}
}

func (s *watchSession) list(title, marker string, findings []diff.ControlChange) {
	if len(findings) == 0 {
		return
	}
	fmt.Fprintf(s.out, "%s%s:\n", strings.ToUpper(title[:1]), title[1:])
	for _, finding := range limit(findings) {
		line := fmt.Sprintf("  %s %s", marker, describe(finding))
		if finding.Reason != "" {
			line += " (" + finding.Reason + ")"
		}
		fmt.Fprintln(s.out, line)
	}
	if more := len(findings) - maxListedFindings; more > 0 {
		fmt.Fprintf(s.out, "  ... and %d more\n", more)
	}
}

func limit[T any](items []T) []T {
	if len(items) > maxListedFindings {
		return items[:maxListedFindings]
	}
	return items
}

func describe(change diff.ControlChange) string {
	text := fmt.Sprintf("[%s] %s", change.ControlID, change.ControlName)
	if change.Severity != "" {
		text += " (" + change.Severity + ")"
	}
	text += " on " + change.ResourceID
	if change.Path != "" {
		text += " at " + change.Path
	}
	return text
}

// lockedWriter makes a writer safe for the goroutines of a watch, which write
// from the scheduler's and from a watcher's.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
