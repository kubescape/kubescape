package core

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/kubescape/v4/core/pkg/anonymizer"
	"github.com/kubescape/kubescape/v4/core/pkg/hostsensorutils"
	"github.com/kubescape/kubescape/v4/core/pkg/opaprocessor"
	"github.com/kubescape/kubescape/v4/core/pkg/policyhandler"
	"github.com/kubescape/kubescape/v4/core/pkg/reportcrypto"
	"github.com/kubescape/kubescape/v4/core/pkg/resourcehandler"
	"github.com/kubescape/kubescape/v4/core/pkg/resourcesprioritization"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/reporter"
	"github.com/kubescape/kubescape/v4/core/pkg/scancache"
	"github.com/kubescape/kubescape/v4/pkg/imagescan"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/resources"
	"go.opentelemetry.io/otel"
	"k8s.io/client-go/kubernetes"
)

// ErrClusterConnection is returned when a cluster scan cannot reach the
// Kubernetes API server. Callers embedding Kubescape.Scan can test for it with
// errors.Is to distinguish an unreachable cluster from other scan failures.
var ErrClusterConnection = errors.New("failed connecting to Kubernetes cluster")

type componentInterfaces struct {
	tenantConfig      cautils.ITenantConfig
	resourceHandler   resourcehandler.IResourceHandler
	report            reporter.IReport
	uiPrinter         printer.IPrinter
	hostSensorHandler hostsensorutils.IHostSensor
	outputPrinters    []printer.IPrinter
	k8s               *k8sinterface.KubernetesApi
}

func (interfaces componentInterfaces) closePrinters() error {
	return errors.Join(closePrinters(interfaces.uiPrinter), closePrinters(interfaces.outputPrinters...))
}

// closePrinters supports both printer close contracts while the migration to
// error-returning CloseWriter methods is in progress.
func closePrinters(printers ...printer.IPrinter) error {
	var closeErr error
	for _, configuredPrinter := range printers {
		if configuredPrinter == nil {
			continue
		}
		closeErr = errors.Join(closeErr, resultshandling.ClosePrinter(configuredPrinter))
	}
	return closeErr
}

// getInterfaces initializes and returns the component interfaces required for scanning,
// including Kubernetes API and tenant configuration.
func getInterfaces(ctx context.Context, scanInfo *cautils.ScanInfo, policyIdentifiers []cautils.PolicyIdentifier) (componentInterfaces, error) {
	ctx, span := otel.Tracer("").Start(ctx, "setup interfaces")
	defer span.End()

	// ================== setup k8s interface object ======================================
	var k8s *k8sinterface.KubernetesApi
	var k8sClient kubernetes.Interface
	if scanInfo.GetScanningContext() == cautils.ContextCluster {
		k8s = kubernetesAPIFunc()
		if k8s == nil {
			// Return rather than terminate: Scan already propagates this to the
			// caller, and the command layer still exits non-zero on it.
			err := clusterConnectionError()
			span.RecordError(err)
			return componentInterfaces{}, err
		}
		k8sClient = k8s.KubernetesClient
	}
	// Connecting takes no context, so a deadline that passed meanwhile stops the scan here.
	if err := ctx.Err(); err != nil {
		err = fmt.Errorf("scan stopped while connecting to the cluster: %w", err)
		span.RecordError(err)
		return componentInterfaces{}, err
	}

	// ================== setup tenant object ======================================
	var tenantConfig cautils.ITenantConfig
	if k8s != nil {
		tenantConfig = cautils.GetTenantConfig(ctx, scanInfo.AccountID, scanInfo.AccessKey, scanInfo.GetClusterContextName(), scanInfo.CustomClusterName, k8s)
	} else {
		localTenantConfig := cautils.NewLocalConfig(scanInfo.AccountID, scanInfo.AccessKey, scanInfo.GetClusterContextName(), scanInfo.CustomClusterName)
		if hasResolvedTenantConfig(scanInfo, localTenantConfig) {
			tenantConfig = localTenantConfig
		} else {
			k8sForTenant := kubernetesAPIFunc()
			tenantConfig = cautils.GetTenantConfig(ctx, scanInfo.AccountID, scanInfo.AccessKey, scanInfo.GetClusterContextName(), scanInfo.CustomClusterName, k8sForTenant)
		}
	}
	cautils.InitCloudAPI(tenantConfig)

	// Set submit behavior AFTER loading tenant config
	setSubmitBehavior(scanInfo, tenantConfig)

	if scanInfo.Submit.GetBool() {
		// submit - Create tenant & Submit report
		if scanInfo.OmitRawResources {
			logger.L().Ctx(ctx).Warning("omit-raw-resources flag will be ignored in submit mode")
		}
	}

	// Said before the scan runs rather than alongside the results: what these
	// combinations cost is a gap in the evidence column, and a gap is only
	// noticeable if the user was told to expect it.
	for _, warning := range scanInfo.EvidenceFlagWarnings() {
		logger.L().Ctx(ctx).Warning(warning)
	}

	// ================== version testing ======================================
	// Skip version check in air-gapped mode (when keep-local flag is set)
	if !scanInfo.Local {
		v := versioncheck.NewIVersionCheckHandler(ctx)
		_ = v.CheckLatestVersion(ctx, versioncheck.NewVersionCheckRequest(scanInfo.AccountID, versioncheck.BuildNumber, policyIdentifierIdentities(policyIdentifiers), "", string(scanInfo.GetScanningContext()), k8sClient))
	}

	// ================== setup host scanner object ======================================
	// The version check above reads the cluster without the scan's context.
	if err := ctx.Err(); err != nil {
		err = fmt.Errorf("scan stopped while setting up: %w", err)
		span.RecordError(err)
		return componentInterfaces{}, err
	}
	ctxHostScanner, spanHostScanner := otel.Tracer("").Start(ctx, "setup host scanner")
	hostSensorHandler := getHostSensorHandler(ctx, scanInfo, k8s)
	if err := hostSensorHandler.Init(ctxHostScanner); err != nil {
		logger.L().Ctx(ctxHostScanner).Error("failed to init host scanner", helpers.Error(err))
		hostSensorHandler = hostsensorutils.NewHostSensorHandlerMock()
		scanInfo.HostSensorEnabled.SetBool(false)
	}
	spanHostScanner.End()

	// ================== setup resource collector object ======================================

	resourceHandler := getResourceHandler(ctx, scanInfo, tenantConfig, k8s, hostSensorHandler)

	// ================== setup reporter & printer objects ======================================

	// reporting behavior - setup reporter
	reportHandler := getReporter(ctx, tenantConfig, scanInfo.ScanID, scanInfo.Submit.GetBool(), scanInfo.FrameworkScan, *scanInfo)

	// setup printers. A dry run produces no report, so it must not open (and
	// truncate) the --output file a previous scan left behind.
	var outputPrinters []printer.IPrinter
	if !scanInfo.DryRun {
		var err error
		outputPrinters, err = GetOutputPrinters(scanInfo, ctx, tenantConfig.GetContextName())
		if err != nil {
			return componentInterfaces{}, err
		}
	}

	uiPrinter := GetUIPrinter(ctx, scanInfo, tenantConfig.GetContextName())

	// ================== return interface ======================================

	return componentInterfaces{
		tenantConfig:      tenantConfig,
		resourceHandler:   resourceHandler,
		report:            reportHandler,
		outputPrinters:    outputPrinters,
		uiPrinter:         uiPrinter,
		hostSensorHandler: hostSensorHandler,
		k8s:               k8s,
	}, nil
}

// hasResolvedTenantConfig reports whether all required tenant configuration fields
// (AccountID, AccessKey, CloudReportURL, and CloudAPIURL) are already resolved locally
// from cached config, services.json, or environment variables, and supported by explicit
// credential overrides, eliminating the need to query in-cluster ConfigMap and Secret fixtures.
// If either endpoint is missing locally and would depend on connector fallback, discovery
// is preserved so that an in-cluster ConfigMap can take precedence.
func hasResolvedTenantConfig(scanInfo *cautils.ScanInfo, tc cautils.ITenantConfig) bool {
	if tc == nil {
		return false
	}
	if tc.GetAccountID() == "" ||
		tc.GetAccessKey() == "" ||
		tc.GetCloudReportURL() == "" ||
		tc.GetCloudAPIURL() == "" {
		return false
	}

	// Verify credential provenance:
	// In-cluster Secret credentials have higher precedence than the local cache.
	// Only accept localTenantConfig as fully resolved when credentials are
	// explicitly provided by the caller (via CLI flags or environment variables),
	// which outrank in-cluster Secret. Cache-derived credentials must not bypass
	// cluster Secret lookup.
	hasAccountOverride := (scanInfo != nil && scanInfo.AccountID != "") || os.Getenv(cautils.AccountIdEnvVar) != ""
	hasAccessKeyOverride := (scanInfo != nil && scanInfo.AccessKey != "") || os.Getenv(cautils.AccessKeyEnvVar) != ""

	return hasAccountOverride && hasAccessKeyOverride
}

func validateSBOMOutput(scanInfo *cautils.ScanInfo, format string) error {
	if format != printer.CycloneDXFormat && format != printer.SPDXFormat {
		return nil
	}
	if scanInfo.ScanType == cautils.ScanTypeImage {
		return nil
	}
	if !scanInfo.ScanImages {
		return fmt.Errorf("format %q describes scanned images: add --scan-images, or run %q to scan an image directly", format, cautils.ExecName()+" scan image")
	}
	if scanInfo.Hide || scanInfo.EncryptionEnabled {
		return fmt.Errorf("format %q is not supported with --hide or --encrypt: an SBOM is the Anchore scan document, whose package identity and relationships are keyed by content-derived IDs that anonymization cannot rewrite", format)
	}
	return nil
}

// ValidateOutputPrinters validates printer compatibility, multi-format path collisions,
// and destination path safety against all scan input sources without opening any writers.
// For image scans, recursive directory traversal is deferred to GetOutputPrinters so that
// large image rootfs directories are traversed only once.
func ValidateOutputPrinters(scanInfo *cautils.ScanInfo) error {
	traverseDirs := scanInfo == nil || scanInfo.ScanType != cautils.ScanTypeImage
	_, err := validateAndResolvePrinters(scanInfo, traverseDirs)
	return err
}

// validateAndResolvePrinters checks printer compatibility, resolves output paths,
// and validates safety against input sources, optionally skipping recursive directory traversal.
func validateAndResolvePrinters(scanInfo *cautils.ScanInfo, traverseDirs bool) ([]string, error) {
	requested := scanInfo.Formats()
	formats := make([]string, 0, len(requested))
	containPrettyPrinter := false
	resolvedPaths := make(map[string]string)
	for _, format := range requested {
		usesPrettyPrinter, err := resultshandling.ValidatePrinter(scanInfo.ScanType, scanInfo.GetScanningContext(), format)
		if err != nil {
			return nil, err
		}

		if err := validateSBOMOutput(scanInfo, format); err != nil {
			return nil, err
		}

		if usesPrettyPrinter && containPrettyPrinter {
			continue
		}

		if path := resolvedOutputPath(format, scanInfo.Output); path != "" {
			if existing, collision := resolvedPaths[path]; collision {
				return nil, fmt.Errorf("output path collision: formats %q and %q both resolve to %q; specify distinct output paths or use format-specific file extensions", existing, format, path)
			}
			resolvedPaths[path] = format
		}

		if usesPrettyPrinter {
			containPrettyPrinter = true
		}
		formats = append(formats, format)
	}

	outputPaths := make([]string, 0, len(resolvedPaths))
	for p := range resolvedPaths {
		outputPaths = append(outputPaths, p)
	}
	slices.Sort(outputPaths)
	for _, path := range outputPaths {
		if err := validateScanOutputSafety(path, scanInfo, traverseDirs); err != nil {
			return nil, err
		}
	}

	return formats, nil
}

// GetOutputPrinters constructs and validates result printers for each requested format.
// It verifies printer compatibility, checks for output path collisions across formats,
// and performs a fresh destination path safety check against all scan input sources before opening any writers.
func GetOutputPrinters(scanInfo *cautils.ScanInfo, ctx context.Context, clusterName string) ([]printer.IPrinter, error) {
	formats, err := validateAndResolvePrinters(scanInfo, true)
	if err != nil {
		return nil, err
	}

	outputPrinters := make([]printer.IPrinter, 0, len(formats))
	for _, format := range formats {
		printerHandler := resultshandling.NewPrinter(ctx, format, scanInfo, clusterName)
		if err := printerHandler.SetWriter(ctx, scanInfo.Output); err != nil {
			setupErr := fmt.Errorf("configure %q output: %w", format, err)
			return nil, errors.Join(setupErr, closePrinters(append(outputPrinters, printerHandler)...))
		}
		outputPrinters = append(outputPrinters, printerHandler)
	}

	return outputPrinters, nil
}

// resolvedOutputPath returns the target filesystem path for a given format and
// outputFile argument. When outputFile is blank, formats that write to default
// files by default (HTML, PDF, Markdown) resolve to their standard default report
// file path ("report.html", "report.pdf", "report.md"). Standard sinks such as
// stdout and /dev/null return an empty string to indicate no file collision check
// is required.
func resolvedOutputPath(format, outputFile string) string {
	if outputFile == "" {
		switch format {
		case printer.HtmlFormat:
			return printer.ResolveDefaultOutputFile(printer.HtmlFormat, "report")
		case printer.PdfFormat:
			return printer.ResolveDefaultOutputFile(printer.PdfFormat, "report")
		case printer.MarkdownFormat:
			return printer.ResolveDefaultOutputFile(printer.MarkdownFormat, "report")
		default:
			return ""
		}
	}
	baseName := printer.DefaultBaseNameForFormat(format)
	resolvedFormat := format
	if _, ok := printer.FormatOutputExt[format]; !ok {
		resolvedFormat = printer.PrettyFormat
	}
	path, explicit := printer.ResolveOutputFile(resolvedFormat, outputFile, baseName)
	// Well-known sinks are shared destinations, not files: two formats both
	// writing stdout (or both discarding to /dev/null) is the intended
	// multi-format behavior, same as an empty --output, so they are skipped
	// from collision tracking. This mirrors the sink handling in
	// printer.ResolveOutputFile so the detector and the printers agree.
	if !explicit || path == "" || path == os.DevNull {
		return ""
	}
	return path
}

// fileExtForFormat returns the extension the format's printer appends to
// --output. An unknown format falls back to the pretty extension because
// NewPrinter falls back to the pretty printer for it.
func fileExtForFormat(format string) string {
	if ext, ok := printer.FormatOutputExt[format]; ok {
		return ext
	}
	return printer.PrettyOutputExt
}

// isGenuineManifest inspects an existing file to check whether it contains
// valid or attempted scannable manifests (e.g. Kubernetes resources or Terraform).
// Non-manifest files such as scan output reports (results.json, results.yaml),
// build metadata (package.json, tsconfig.json), and empty files are not genuine
// manifest inputs and therefore do not block output file reuse.
func isGenuineManifest(filePath string) bool {
	info, err := os.Stat(filePath)
	if err != nil || info.IsDir() || info.Size() == 0 {
		return false
	}

	ext := strings.ToLower(filepath.Ext(filePath))
	if ext == ".tf" {
		return true
	}

	isYaml := cautils.IsYaml(filePath) || ext == ".yaml" || ext == ".yml"
	isJson := cautils.IsJson(filePath) || ext == ".json"
	if !isYaml && !isJson {
		return false
	}

	data, err := os.ReadFile(filePath)
	if err != nil || len(bytes.TrimSpace(data)) == 0 {
		return false
	}

	format := cautils.YAML_FILE_FORMAT
	if isJson {
		format = cautils.JSON_FILE_FORMAT
	}

	workloads, _ := cautils.ReadFile(data, format)
	if len(workloads) > 0 {
		return true
	}

	return hasKubernetesManifestSignatures(data, isJson)
}

// hasKubernetesManifestSignatures checks if the data contains document-level Kubernetes
// manifest signatures (apiVersion and kind/items), distinguishing attempted or templated
// Kubernetes manifests from non-manifest JSON/YAML files such as scan reports.
// For YAML documents, apiVersion and kind/items must appear at column 0 (unindented) so
// raw resources embedded inside YAML posture reports are not misidentified as manifests.
func hasKubernetesManifestSignatures(data []byte, isJson bool) bool {
	if isJson {
		var m map[string]any
		if err := json.Unmarshal(data, &m); err == nil {
			if apiVer, ok := m["apiVersion"].(string); ok && strings.TrimSpace(apiVer) != "" {
				if _, hasKind := m["kind"]; hasKind {
					return true
				}
				if _, hasItems := m["items"]; hasItems {
					return true
				}
			}
			return false
		}
		var list []map[string]any
		if err := json.Unmarshal(data, &list); err == nil {
			for _, item := range list {
				if apiVer, ok := item["apiVersion"].(string); ok && strings.TrimSpace(apiVer) != "" {
					if _, hasKind := item["kind"]; hasKind {
						return true
					}
				}
			}
			return false
		}
		return false
	}

	// For YAML: check if document contains document-level (column-zero, unindented)
	// apiVersion and kind or items keys.
	scanner := bufio.NewScanner(bytes.NewReader(data))
	hasAPIVersion := false
	hasKindOrItems := false
	for scanner.Scan() {
		rawLine := scanner.Text()
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if trimmed == "---" {
			if hasAPIVersion && hasKindOrItems {
				return true
			}
			hasAPIVersion = false
			hasKindOrItems = false
			continue
		}
		// Document-level keys must start at column 0 (no leading whitespace).
		// Nested keys such as raw resources inside YAML scan reports are indented
		// and must not be mistaken for manifest document signatures.
		if len(rawLine) > 0 && (rawLine[0] == ' ' || rawLine[0] == '\t') {
			continue
		}
		if strings.HasPrefix(trimmed, "apiVersion:") || strings.HasPrefix(trimmed, "apiVersion ") {
			hasAPIVersion = true
		}
		if strings.HasPrefix(trimmed, "kind:") || strings.HasPrefix(trimmed, "kind ") || strings.HasPrefix(trimmed, "items:") {
			hasKindOrItems = true
		}
		if hasAPIVersion && hasKindOrItems {
			return true
		}
	}
	return hasAPIVersion && hasKindOrItems
}

// checkDirectoryCollision recursively inspects a directory input to verify that the
// output destination does not alias any genuine manifest file within the directory.
// It respects scanner path exclusion filters, prevents symlink cycles, and fails closed
// if directory traversal encounters an unexpected error.
func checkDirectoryCollision(dirPath string, scanInfo *cautils.ScanInfo, destInfo fs.FileInfo, outputFile string, visitedDirs map[any]bool) error {
	resolvedDir, err := filepath.EvalSymlinks(dirPath)
	if err != nil {
		resolvedDir = dirPath
	}
	dirInfo, err := os.Stat(resolvedDir)
	if err != nil || !dirInfo.IsDir() {
		return nil
	}
	if visitedDirs == nil {
		visitedDirs = make(map[any]bool)
	}
	for k := range visitedDirs {
		if other, ok := k.(fs.FileInfo); ok && os.SameFile(dirInfo, other) {
			return nil
		}
	}
	visitedDirs[dirInfo] = true

	pathFilter, _ := cautils.NewScanPathFilter(dirPath, scanInfo.ExcludePaths, !scanInfo.NoIgnoreFile)

	var collisionErr error
	walkErr := filepath.WalkDir(resolvedDir, func(source string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if collisionErr != nil {
			return fs.SkipAll
		}

		if d.IsDir() {
			// Do not skip the walk root itself even if its name begins with a dot (e.g. .manifests)
			if source != resolvedDir && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			if pathFilter != nil && pathFilter.Excluded(source, true) {
				return filepath.SkipDir
			}
			return nil
		}

		targetInfo, statErr := os.Stat(source)
		if statErr != nil {
			return statErr
		}

		if targetInfo.IsDir() {
			// Symlinked subdirectory
			if pathFilter != nil && pathFilter.Excluded(source, true) {
				return nil
			}
			if err := checkDirectoryCollision(source, scanInfo, destInfo, outputFile, visitedDirs); err != nil {
				collisionErr = err
				return fs.SkipAll
			}
			return nil
		}

		if pathFilter != nil && pathFilter.Excluded(source, false) {
			return nil
		}

		if os.SameFile(destInfo, targetInfo) {
			if isGenuineManifest(source) {
				collisionErr = fmt.Errorf("output path %q would overwrite input manifest %q; choose a different output file", outputFile, source)
				return fs.SkipAll
			}
		}
		return nil
	})

	if collisionErr != nil {
		return collisionErr
	}
	if walkErr != nil && !errors.Is(walkErr, fs.SkipAll) {
		return fmt.Errorf("failed walking directory %q: %w", resolvedDir, walkErr)
	}
	return nil
}

// checkGlobCollision verifies that an output destination does not alias manifests
// matched by a glob pattern, checking both directly matched files and nested directories.
// Bare relative glob patterns without a directory prefix (e.g. "*.yaml") search the
// current directory recursively while honoring scanner exclusion rules.
func checkGlobCollision(rawPath string, scanInfo *cautils.ScanInfo, destInfo fs.FileInfo, outputFile string) error {
	if matches, globErr := filepath.Glob(rawPath); globErr == nil {
		for _, match := range matches {
			matchInfo, err := os.Stat(match)
			if err != nil {
				continue
			}
			if matchInfo.IsDir() {
				if err := checkDirectoryCollision(match, scanInfo, destInfo, outputFile, nil); err != nil {
					return err
				}
			} else {
				if os.SameFile(destInfo, matchInfo) {
					if isGenuineManifest(match) {
						return fmt.Errorf("output path %q would overwrite input manifest %q; choose a different output file", outputFile, match)
					}
				}
			}
		}
	}

	root, pattern := filepath.Split(rawPath)
	if root == "" {
		root = "."
	}
	if strings.ContainsAny(pattern, "*?[]") {
		if rootInfo, err := os.Stat(root); err == nil && rootInfo.IsDir() {
			pathFilter, _ := cautils.NewScanPathFilter(root, scanInfo.ExcludePaths, !scanInfo.NoIgnoreFile)
			var collisionErr error
			walkErr := filepath.WalkDir(root, func(source string, d fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if collisionErr != nil {
					return fs.SkipAll
				}
				if d.IsDir() {
					if source != root && strings.HasPrefix(d.Name(), ".") {
						return filepath.SkipDir
					}
					if pathFilter != nil && pathFilter.Excluded(source, true) {
						return filepath.SkipDir
					}
					return nil
				}
				if pathFilter != nil && pathFilter.Excluded(source, false) {
					return nil
				}
				if matched, _ := filepath.Match(pattern, d.Name()); matched {
					if entryInfo, err := os.Stat(source); err == nil && os.SameFile(destInfo, entryInfo) {
						if isGenuineManifest(source) {
							collisionErr = fmt.Errorf("output path %q would overwrite input manifest %q; choose a different output file", outputFile, source)
							return fs.SkipAll
						}
					}
				}
				return nil
			})
			if collisionErr != nil {
				return collisionErr
			}
			if walkErr != nil && !errors.Is(walkErr, fs.SkipAll) {
				return fmt.Errorf("failed walking glob root %q: %w", root, walkErr)
			}
		}
	}
	return nil
}

// validateScanOutputSafety ensures an output destination does not overwrite an
// input manifest, baseline report, exceptions file, framework definition, or controls
// configuration. SetWriter truncates the destination file immediately on open with
// O_TRUNC, so an alias to any of these input sources would destroy user data before the
// scan can read or compare it. When traverseDirs is false, recursive directory traversal is
// deferred to GetOutputPrinters.
func validateScanOutputSafety(outputFile string, scanInfo *cautils.ScanInfo, traverseDirs bool) error {
	if outputFile == "" || outputFile == os.DevNull || scanInfo == nil {
		return nil
	}
	destInfo, err := os.Stat(outputFile)
	if err != nil {
		// If the output file does not exist yet (or a parent path component is not a directory),
		// it cannot overwrite an existing input or configuration file.
		if os.IsNotExist(err) || errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
			return nil
		}
		return fmt.Errorf("unable to verify safety of output path %q: %w", outputFile, err)
	}

	if scanInfo.OriginalStdinInfo != nil && os.SameFile(destInfo, scanInfo.OriginalStdinInfo) {
		return fmt.Errorf("output path %q would overwrite stdin input; choose a different output file", outputFile)
	}

	checkFile := func(label, inputPath string) error {
		if strings.TrimSpace(inputPath) == "" {
			return nil
		}
		info, err := os.Stat(inputPath)
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if os.SameFile(destInfo, info) {
				return fmt.Errorf("output path %q would overwrite %s %q; choose a different output file", outputFile, label, inputPath)
			}
			if traverseDirs {
				return checkDirectoryCollision(inputPath, scanInfo, destInfo, outputFile, nil)
			}
			return nil
		}
		if os.SameFile(destInfo, info) {
			return fmt.Errorf("output path %q would overwrite %s %q; choose a different output file", outputFile, label, inputPath)
		}
		return nil
	}

	if err := checkFile("baseline report", scanInfo.Baseline); err != nil {
		return err
	}
	if err := checkFile("exceptions file", scanInfo.UseExceptions); err != nil {
		return err
	}
	if err := checkFile("controls configuration", scanInfo.ControlsInputs); err != nil {
		return err
	}
	if err := checkFile("input manifest", scanInfo.FilePath); err != nil {
		return err
	}
	if err := checkFile("custom rules", scanInfo.CustomRules); err != nil {
		return err
	}
	if err := checkFile("Helm chart", scanInfo.ChartPath); err != nil {
		return err
	}
	if err := checkFile("attack-tracks file", scanInfo.AttackTracks); err != nil {
		return err
	}
	if err := checkFile("artifacts directory", scanInfo.UseArtifactsFrom); err != nil {
		return err
	}
	if err := checkFile("host sensor file", scanInfo.HostSensorYamlPath); err != nil {
		return err
	}
	for _, useFrom := range scanInfo.UseFrom {
		if err := checkFile("framework file", useFrom); err != nil {
			return err
		}
	}
	for _, valFile := range scanInfo.HelmValueFiles {
		if err := checkFile("Helm values file", valFile); err != nil {
			return err
		}
	}
	for _, setFile := range scanInfo.HelmSetFileValues {
		parts := strings.SplitN(setFile, "=", 2)
		filePath := setFile
		if len(parts) == 2 {
			filePath = parts[1]
		}
		if err := checkFile("Helm set-file", filePath); err != nil {
			return err
		}
	}

	for _, pattern := range scanInfo.InputPatterns {
		rawPath := strings.TrimSpace(pattern)
		if rawPath == "" {
			continue
		}
		if rawPath == "-" {
			if scanInfo.OriginalStdinInfo != nil {
				if os.SameFile(destInfo, scanInfo.OriginalStdinInfo) {
					return fmt.Errorf("output path %q would overwrite stdin input; choose a different output file", outputFile)
				}
			} else if file, ok := any(os.Stdin).(*os.File); ok {
				if stdinInfo, err := file.Stat(); err == nil && !stdinInfo.IsDir() {
					if os.SameFile(destInfo, stdinInfo) {
						return fmt.Errorf("output path %q would overwrite stdin input; choose a different output file", outputFile)
					}
				}
			}
			continue
		}

		// Check both the literal path (e.g. literal manifest named "file:pod.yaml")
		// and the selector-resolved path (e.g. "image.tar" from "docker-archive:image.tar")
		// so neither input source can be truncated if both paths exist on disk.
		candidates := []string{rawPath}
		resolved := rawPath
		if rest, _ := peelGenericImageSelector(resolved); rest != "" {
			resolved = rest
		}
		if scheme := detectScheme(resolved); scheme != "" {
			resolved = strings.TrimPrefix(resolved, scheme+":")
		} else if strings.HasPrefix(resolved, "docker-archive:") {
			resolved = strings.TrimPrefix(resolved, "docker-archive:")
		} else if strings.HasPrefix(resolved, "oci-archive:") {
			resolved = strings.TrimPrefix(resolved, "oci-archive:")
		} else if strings.HasPrefix(resolved, "oci-dir:") {
			resolved = strings.TrimPrefix(resolved, "oci-dir:")
		} else if strings.HasPrefix(resolved, "dir:") {
			resolved = strings.TrimPrefix(resolved, "dir:")
		} else if strings.HasPrefix(resolved, "sbom:") {
			resolved = strings.TrimPrefix(resolved, "sbom:")
		}
		resolved = strings.TrimSpace(resolved)
		if resolved != "" && resolved != rawPath {
			candidates = append(candidates, resolved)
		}

		for _, candidate := range candidates {
			info, err := os.Stat(candidate)
			if err == nil {
				if !info.IsDir() {
					if os.SameFile(destInfo, info) {
						label := "input manifest"
						if scanInfo.ScanType == cautils.ScanTypeImage {
							label = "input image"
						}
						return fmt.Errorf("output path %q would overwrite %s %q; choose a different output file", outputFile, label, pattern)
					}
				} else {
					if os.SameFile(destInfo, info) {
						label := "input manifest"
						if scanInfo.ScanType == cautils.ScanTypeImage {
							label = "input image"
						}
						return fmt.Errorf("output path %q would overwrite %s %q; choose a different output file", outputFile, label, pattern)
					}
					if traverseDirs {
						if err := checkDirectoryCollision(candidate, scanInfo, destInfo, outputFile, nil); err != nil {
							return err
						}
					}
				}
				continue
			}

			if strings.ContainsAny(candidate, "*?[]") {
				if err := checkGlobCollision(candidate, scanInfo, destInfo, outputFile); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// collectPolicies pins the shared handler for exactly as long as its caches are
// in use, so an idle registry sweep cannot close them during collection.
func collectPolicies(ctx context.Context, clusterName string, policyIdentifiers []cautils.PolicyIdentifier, scanInfo *cautils.ScanInfo, getters *cautils.Getters) (*cautils.OPASessionObj, error) {
	policyHandler, release := policyhandler.NewPolicyHandlerWithRelease(clusterName)
	defer release()
	return policyHandler.CollectPolicies(ctx, policyIdentifiers, scanInfo, getters)
}

// Scan runs a scan using ks.Context() as the operation's context. It is a
// compatibility wrapper around ScanContext for callers that have not
// migrated to passing their own context explicitly; see ScanContext's
// documentation for why that matters when a *Kubescape instance is reused
// or scan operations can overlap.
func (ks *Kubescape) Scan(scanInfo *cautils.ScanInfo, policyIdentifiers []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
	return ks.ScanContext(ks.Context(), scanInfo, policyIdentifiers)
}

// ScanContext runs a scan bound to the given ctx for its complete execution
// (initialization, policy/resource collection, OPA evaluation, image
// scanning, prioritization, and teardown all observe this same ctx), rather
// than re-reading ks.Context() at each stage. Callers that need a deadline
// or cancellation should derive ctx themselves (e.g. context.WithTimeout)
// and pass it in directly, instead of calling ks.SetContext beforehand:
// mutating the shared *Kubescape's context is not safe if the instance is
// reused or another operation could run concurrently against it, since a
// mid-operation ks.Context() read could observe a different deadline than
// the one that started the operation, or an already-restored/canceled one.
func (ks *Kubescape) ScanContext(ctx context.Context, scanInfo *cautils.ScanInfo, policyIdentifiers []cautils.PolicyIdentifier) (scanResult *resultshandling.ResultsHandler, scanErr error) {
	var (
		interfaces             componentInterfaces
		getters                cautils.Getters
		controlInputsFromCache bool
		exceptionsFromCache    bool
		resultsHandling        *resultshandling.ResultsHandler
	)

	// Output printers open their writers during interface setup. Scan owns
	// those writers until a successful return hands them to ResultsHandler.
	printersOwnedByScan := true
	defer func() {
		if printersOwnedByScan {
			if err := interfaces.closePrinters(); err != nil {
				scanErr = errors.Join(scanErr, fmt.Errorf("close printers after scan failure: %w", err))
			}
		}
	}()

	// remove host scanner components
	defer func() {
		if interfaces.hostSensorHandler != nil {
			if err := interfaces.hostSensorHandler.TearDown(); err != nil {
				logger.L().Ctx(ctx).StopError("Failed to tear down host scanner", helpers.Error(err))
			}
		}
	}()

	// ===================== Initialization =====================
	err := func() error {
		ctxInit, spanInit := otel.Tracer("").Start(ctx, "initialization")
		defer spanInit.End()
		logger.L().Start("Kubescape scanner initializing...")

		policyIdentifiers = resolveDefaultScanAllPolicies(scanInfo, policyIdentifiers) // resolve the ScanAll expansion while Init can still cache its paths
		if err := scanInfo.Init(ctxInit, policyIdentifiers); err != nil {              // initialize scan info
			return err
		}
		if err := resolveClusterContext(scanInfo); err != nil {
			return err
		}

		var err error
		interfaces, err = getInterfaces(ctxInit, scanInfo, policyIdentifiers)
		if err != nil {
			return err
		}
		interfaces.report.SetTenantConfig(interfaces.tenantConfig)

		// Only create DownloadReleasedPolicy if not in air-gapped mode
		airGapped := isAirGappedMode(scanInfo)
		var downloadReleasedPolicy *getter.DownloadReleasedPolicy
		if airGapped {
			// In air-gapped mode (--use-from is set — the user explicitly wants to load everything
			// from local files with no network access), don't initialize the downloader to prevent
			// network access
			downloadReleasedPolicy = nil
		} else {
			downloadReleasedPolicy = getter.NewDownloadReleasedPolicyWithVersion(scanInfo.ControlsVersion) // download config inputs from github release
		}

		// set policy getter only after setting the customerGUID
		getters.PolicyGetter, err = getPolicyGetter(ctxInit, scanInfo.UseFrom, interfaces.tenantConfig.GetAccountID(), scanInfo.FrameworkScan, downloadReleasedPolicy, airGapped)
		if err != nil {
			return err
		}
		getters.ControlsInputsGetter, controlInputsFromCache, err = getConfigInputsGetterForTarget(ctxInit, scanInfo.ControlsInputs, interfaces.tenantConfig.GetAccountID(), downloadReleasedPolicy, scanInfo.GetScanningContext() == cautils.ContextCluster, airGapped, interfaces.k8s)
		if err != nil {
			return err
		}
		getters.ExceptionsGetter, exceptionsFromCache, err = getExceptionsGetterForTarget(ctxInit, scanInfo.UseExceptions, interfaces.tenantConfig.GetAccountID(), downloadReleasedPolicy, scanInfo.GetScanningContext() == cautils.ContextCluster, airGapped, interfaces.k8s)
		if err != nil {
			return err
		}
		getters.AttackTracksGetter, err = getAttackTracksGetter(ctxInit, scanInfo.AttackTracks, interfaces.tenantConfig.GetAccountID(), downloadReleasedPolicy, airGapped)
		if err != nil {
			return err
		}

		if scanInfo.ScanAll {
			// Add all frameworks
			policyIdentifiers = cautils.AppendPolicyIdentifiers(policyIdentifiers, listFrameworksNames(getters.PolicyGetter), apisv1.KindFramework)

			// Add all controls
			if controls, err := getters.PolicyGetter.ListControls(); err == nil {
				controlIDs := make([]string, 0, len(controls))
				for _, control := range controls {
					controlIDs = append(controlIDs, parseControlEntry(control).ID)
				}
				policyIdentifiers = cautils.AppendPolicyIdentifiers(policyIdentifiers, controlIDs, apisv1.KindControl)
			} else {
				logger.L().Ctx(ctxInit).Warning("failed to list controls for ScanAll", helpers.Error(err))
			}
		}

		logger.L().StopSuccess("Initialized scanner")
		resultsHandling = resultshandling.NewResultsHandler(interfaces.report, interfaces.outputPrinters, interfaces.uiPrinter)
		return nil
	}()
	defer scanInfo.Cleanup()
	if err != nil {
		return nil, err
	}

	// ===================== policies =====================
	var scanData *cautils.OPASessionObj
	err = func() error {
		ctxPolicies, spanPolicies := otel.Tracer("").Start(ctx, "policies")
		defer spanPolicies.End()

		var err error
		scanData, err = collectPolicies(ctxPolicies, interfaces.tenantConfig.GetContextName(), policyIdentifiers, scanInfo, &getters)
		if err != nil {
			return err
		}
		if controlInputsFromCache {
			scanData.PolicyDegradations = append(scanData.PolicyDegradations, cautils.PolicyDegradation{Component: "controlInputs", Reason: "failed to fetch from GitHub, loaded from local cache"})
		}
		if exceptionsFromCache {
			scanData.PolicyDegradations = append(scanData.PolicyDegradations, cautils.PolicyDegradation{Component: "exceptions", Reason: "failed to fetch from GitHub, loaded from local cache"})
		}
		return nil
	}()
	if err != nil {
		return resultsHandling, err
	}

	// A dry run and collection both start with discovery calls that take no context, so a deadline that already passed stops the scan here.
	if err := ctx.Err(); err != nil {
		return resultsHandling, fmt.Errorf("scan stopped before collecting resources: %w", err)
	}
	if scanInfo.DryRun {
		resultsHandling.SetData(scanData)
		result, err := interfaces.resourceHandler.Preflight(ctx, scanData, scanInfo)
		if err != nil {
			return resultsHandling, err
		}
		printPreflightResult(result)
		if denied := result.Denied(); len(denied) > 0 {
			return resultsHandling, fmt.Errorf("dry-run: %d required resource type(s) cannot be listed with the current credentials", len(denied))
		}
		// Nothing was collected or evaluated, so callers skip HandleResults
		// for a dry run. Scan keeps ownership of the printers and closes them.
		return resultsHandling, nil
	}

	// ===================== resources =====================
	// Determine if streaming should be enabled
	enableStreaming := scanInfo.EnableStreaming
	// Snapshot the pre-scan cluster size before the streaming decision. The
	// streaming producer populates sessionObj.AllResources asynchronously, so
	// OPAProcessor cannot snapshot the resource count at construction the way
	// the non-streaming path does; the estimate stands in for it. Computing it
	// up front also covers explicit --enable-streaming on large clusters.
	var estimatedClusterSize int
	if scanInfo.GetScanningContext() == cautils.ContextCluster {
		estimatedClusterSize = estimateClusterSize(interfaces.resourceHandler, ctx, scanInfo)
	}
	if !enableStreaming && scanInfo.GetScanningContext() == cautils.ContextCluster {
		// Auto-enable streaming for large clusters
		enableStreaming = cautils.IsLargeCluster(estimatedClusterSize)
		if enableStreaming {
			logger.L().Ctx(ctx).Info("Large cluster detected, enabling resource streaming")
		}
	}

	// OPA context for both streaming and non-streaming paths
	ctxOpa, spanOpa := otel.Tracer("").Start(ctx, "opa testing")
	defer spanOpa.End()

	if enableStreaming {
		// Use streaming approach for large clusters
		err = func() error {
			ctxResources, spanResources := otel.Tracer("").Start(ctx, "resources")
			defer spanResources.End()
			return collectAndProcessResourcesWithStreaming(ctxResources, interfaces.resourceHandler, scanData, scanInfo, interfaces.tenantConfig.GetContextName(), scanInfo.ExcludedNamespaces, scanInfo.IncludeNamespaces, scanInfo.EnableRegoPrint, scanInfo.ControlTimeout, estimatedClusterSize)
		}()
		if err != nil {
			return resultsHandling, err
		}
	} else {
		// Use traditional approach for small clusters
		err = func() error {
			ctxResources, spanResources := otel.Tracer("").Start(ctx, "resources")
			defer spanResources.End()
			return resourcehandler.CollectResources(ctxResources, interfaces.resourceHandler, scanData, scanInfo)
		}()
		if err != nil {
			return resultsHandling, err
		}

		deps := resources.NewRegoDependenciesData(k8sinterface.GetK8sConfig(), interfaces.tenantConfig.GetContextName())
		exceptionRecorder, shutdownRecorder := newSecurityExceptionEventRecorder(ctxOpa)
		if shutdownRecorder != nil {
			defer shutdownRecorder()
		}
		reportResults := opaprocessor.NewOPAProcessor(scanData, deps, interfaces.tenantConfig.GetContextName(), scanInfo.ExcludedNamespaces, scanInfo.IncludeNamespaces, scanInfo.EnableRegoPrint, exceptionRecorder)
		reportResults.ControlTimeout = scanInfo.ControlTimeout
		reportResults.SetWholeClusterPolicy(scanInfo.GetWholeClusterPolicy())
		if cacheStore := loadIncrementalCacheIfEnabled(ctxOpa, scanInfo, scanData); cacheStore != nil {
			reportResults.SetIncrementalCache(cacheStore)
			defer func() {
				if flushErr := cacheStore.Flush(); flushErr != nil {
					logger.L().Ctx(ctxOpa).Warning("failed to persist incremental scan cache", helpers.Error(flushErr))
				}
			}()
		}
		if err = reportResults.ProcessRulesListener(ctxOpa, cautils.NewProgressHandler("")); err != nil {
			logger.L().Ctx(ctxOpa).Error("failed to process rules", helpers.Error(err))
			// The eager listener finalizes its accumulated results before returning
			// an error. Streaming errors can return before that invariant holds.
			resultsHandling.SetData(scanData)
			return resultsHandling, fmt.Errorf("%w", err)
		}
	}

	// ======================== prioritization ===================
	if scanInfo.PrintAttackTree || isPrioritizationScanType(scanInfo.ScanType) {
		err := func() error {
			_, spanPrioritization := otel.Tracer("").Start(ctxOpa, "prioritization")
			defer spanPrioritization.End()

			priotizationHandler, err := resourcesprioritization.NewResourcesPrioritizationHandler(ctxOpa, getters.AttackTracksGetter, scanInfo.PrintAttackTree)
			if err != nil {
				logger.L().Ctx(ctx).Warning("failed to get attack tracks, this may affect the scanning results", helpers.Error(err))
				return nil
			}
			if err := priotizationHandler.PrioritizeResources(scanData); err != nil {
				return fmt.Errorf("%w", err)
			}
			return nil
		}()
		if err != nil {
			return resultsHandling, err
		}
		if isPrioritizationScanType(scanInfo.ScanType) {
			scanData.SetTopWorkloads()
		}
	}

	if scanInfo.ScanImages {
		resultsHandling.SetScanError(scanImages(scanInfo.ScanType, scanData, ctx, resultsHandling, scanInfo, interfaces.k8s))
	}
	// ========================= results handling =====================
	resultsHandling.SetData(scanData)

	if scanInfo.EncryptionEnabled {

		masterKey, err := reportcrypto.GetMasterKeyFromEnv("encryption")
		if err != nil {
			return nil, err
		}

		dek, err := reportcrypto.GenerateDEK()
		if err != nil {
			for i := range masterKey {
				masterKey[i] = 0
			}

			return nil, fmt.Errorf(
				"failed to generate encryption key: %w", err,
			)
		}

		err = anonymizer.ApplyEncrypted(resultsHandling, dek, masterKey)

		// best-effort memory cleanup
		for i := range dek {
			dek[i] = 0
		}

		for i := range masterKey {
			masterKey[i] = 0
		}

		if err != nil {
			return nil, fmt.Errorf(
				"failed to encrypt sensitive fields: %w",
				err,
			)
		}

	} else if scanInfo.Hide {

		if err := anonymizer.Apply(
			resultsHandling,
		); err != nil {
			return nil, fmt.Errorf(
				"failed to hide sensitive fields: %w",
				err,
			)
		}
	}

	printersOwnedByScan = false
	return resultsHandling, nil
}

func resolveClusterContext(scanInfo *cautils.ScanInfo) error {
	if scanInfo.GetScanningContext() != cautils.ContextCluster {
		return nil
	}
	if err := scanInfo.ResolveClusterContextName(); err != nil {
		return fmt.Errorf("failed to resolve Kubernetes context: %w", err)
	}
	return nil
}

func scanImages(scanType cautils.ScanTypes, scanData *cautils.OPASessionObj, ctx context.Context, resultsHandling *resultshandling.ResultsHandler, scanInfo *cautils.ScanInfo, k8sApi *k8sinterface.KubernetesApi) error {
	var scanningContext cautils.ScanningContext
	if scanInfo != nil {
		scanningContext = scanInfo.GetScanningContext()
	}
	platformOverride := ""
	if scanInfo != nil {
		platformOverride = scanInfo.ImagePlatform
	}
	imagesToScan, imageToCreds, containerErrors := collectImageScanTargets(scanType, scanData, ctx, scanningContext, k8sApi, platformOverride)
	if imagesToScan.IsEmpty() {
		return errors.Join(containerErrors...)
	}

	failOnStale, maxDBAge := imagescan.ResolveDBAgeGate(scanInfo.FailOnStaleDB, scanInfo.FailOnStaleDBSet, scanInfo.MaxDBAge, scanInfo.MaxDBAgeSet)
	distCfg, installCfg, shouldUpdate, err := imagescan.NewDefaultDBConfig(scanInfo.ListingURL, scanInfo.SkipDBUpdate, failOnStale)
	if err != nil {
		logger.L().StopError(fmt.Sprintf("Invalid Grype database URL '%s': %v", scanInfo.ListingURL, err))
		return errors.Join(append(containerErrors, fmt.Errorf("invalid Grype database URL %q: %w", scanInfo.ListingURL, err))...)
	}
	svc, err := imagescan.NewScanServiceWithMatchersAndSources(distCfg, installCfg, scanInfo.UseDefaultMatchers, nil, shouldUpdate)
	if err != nil {
		logger.L().StopError(fmt.Sprintf("Failed to initialize image scanner: %s", err))
		return errors.Join(append(containerErrors, fmt.Errorf("failed to initialize image scanner: %w", err))...)
	}
	defer svc.Close()
	// Warn on a stale vulnerability DB (always); fail only with --fail-on-stale-db.
	// Deferred into the joined error so image results are still collected first.
	staleDBErr := imagescan.EnforceDBAge(svc, shouldUpdate, failOnStale, maxDBAge)
	defaultCreds := registryCredentialsFromScanInfo(scanInfo)
	jobs := buildWorkloadImageScanJobs(imagesToScan, imageToCreds, defaultCreds, scanInfo.RegistryMapping)

	concurrency := scanInfo.ImageScanConcurrency
	if concurrency <= 0 {
		concurrency = 1
	}

	return errors.Join(staleDBErr, scanImageJobsWithDiscoveryErrors(ctx, svc, concurrency, jobs, resultsHandling, containerErrors))
}

// buildWorkloadImageScanJobs turns the collected targets into scan jobs, ordered by
// image and then platform. Credentials resolved from a workload's
// imagePullSecrets win, in the order collectImageScanTargets put them in, which
// is the order the scan tries them; the CLI registry credentials are used only
// when none resolved for the image.
func buildWorkloadImageScanJobs(imagesToScan mapset.Set[ImageScanTarget], imageToCreds map[string][]imagescan.RegistryCredentials, defaultCreds imagescan.RegistryCredentials, registryMapping map[string]string) []ImageScanJob {
	jobs := make([]ImageScanJob, 0, imagesToScan.Cardinality())
	for target := range imagesToScan.Iter() {
		img := target.Image
		credsList := []imagescan.RegistryCredentials{}
		if resolvedCreds, ok := imageToCreds[img]; ok {
			credsList = append(credsList, resolvedCreds...)
		}

		if len(credsList) == 0 && (defaultCreds.Token != "" || defaultCreds.Username != "" || defaultCreds.Password != "") {
			credsList = append(credsList, defaultCreds)
		}

		jobs = append(jobs, ImageScanJob{
			Image:                   img,
			Platform:                target.Platform,
			SkipUnavailablePlatform: target.SkipUnavailable,
			RegistryCredentials:     credsList,
			RegistryMapping:         registryMapping,
		})
	}
	sort.Slice(jobs, func(i, j int) bool {
		if jobs[i].Image != jobs[j].Image {
			return jobs[i].Image < jobs[j].Image
		}
		return jobs[i].Platform < jobs[j].Platform
	})
	return jobs
}

func scanImageJobsWithDiscoveryErrors(ctx context.Context, svc imageScanService, concurrency int, jobs []ImageScanJob, resultsHandling *resultshandling.ResultsHandler, discoveryErrors []error) error {
	return errors.Join(errors.Join(discoveryErrors...), scanImageJobs(ctx, svc, concurrency, jobs, resultsHandling))
}

func scanImageJobs(ctx context.Context, svc imageScanService, concurrency int, jobs []ImageScanJob, resultsHandling *resultshandling.ResultsHandler) error {
	logger.L().Info(fmt.Sprintf("Scanning %s with %s...", countedNoun(len(jobs), "image"), countedNoun(imageScanWorkers(concurrency), "worker")))
	orchestrator := NewImageScanOrchestrator(svc, concurrency)
	results := orchestrator.ScanImages(ctx, jobs)
	sort.Slice(results, func(i, j int) bool {
		if results[i].Image != results[j].Image {
			return results[i].Image < results[j].Image
		}
		return results[i].Platform < results[j].Platform
	})

	for _, res := range results {
		target := imageScanTarget(res.Image, res.Platform)
		if res.SkipReason != nil {
			logger.L().Warning("Skipping unavailable inferred image platform",
				helpers.String("image", target), helpers.Error(res.SkipReason))
			continue
		}
		if res.Error != nil {
			logger.L().Error("failed to scan", helpers.String("image", target), helpers.Error(res.Error))
			continue
		}
		if res.ScanData != nil {
			resultsHandling.ImageScanData = append(resultsHandling.ImageScanData, *res.ScanData)
			logger.L().Success("Done scanning", helpers.String("image", target))
		}
	}
	if agg := orchestrator.GetErrorAggregator(); agg != nil && agg.HasErrors() {
		logger.L().Warning(agg.Error())
		return agg
	}
	return nil
}

func collectImageScanTargets(scanType cautils.ScanTypes, scanData *cautils.OPASessionObj, ctx context.Context, scanningContext cautils.ScanningContext, k8sApi *k8sinterface.KubernetesApi, platformOverride string) (mapset.Set[ImageScanTarget], map[string][]imagescan.RegistryCredentials, []error) {
	imagesToScan := mapset.NewSet[ImageScanTarget]()
	resolvedCreds := make(map[string][]registryCredential)
	var containerErrors []error
	nodePlatforms := buildNodePlatformIndexFromCatalog(scanData.GetCatalog())
	if scanningContext != cautils.ContextCluster {
		// imagePullSecrets belong to a live cluster target. A manifest or repository
		// may contain the same Secret name as the current kube context, but that must
		// never grant cluster credentials to an offline image scan.
		k8sApi = nil
	}
	pullSecrets := newPullSecretCache(k8sApi)

	collectWorkload := func(wl *workloadinterface.Workload) {
		images, workloadContainerErrors := getAllWorkloadImages(wl)
		for _, containerErr := range workloadContainerErrors {
			logger.L().Error("failed to collect image scan targets", helpers.Error(containerErr))
			containerErrors = append(containerErrors, containerErr)
		}
		platforms := []string{platformOverride}
		skipUnavailable := false
		if platformOverride == "" {
			selection := selectWorkloadPlatforms(wl, nodePlatforms)
			platforms = selection.platforms
			skipUnavailable = selection.skipUnavailable
			if len(platforms) == 0 {
				if selection.constrained {
					containerErrors = append(containerErrors, fmt.Errorf(
						"no observed image platform satisfies the scheduling constraints for %s", wl.GetID()))
					return
				}
				platforms = []string{""}
			}
		}
		for _, image := range images {
			if skipUnavailable {
				logger.L().Info("Scanning image across inferred platform variants",
					helpers.String("image", image), helpers.Int("platforms", len(platforms)))
			}
			for _, platform := range platforms {
				addImageScanTarget(imagesToScan, ImageScanTarget{
					Image: image, Platform: platform, SkipUnavailable: skipUnavailable,
				})
			}
			resolvedCreds[image] = append(resolvedCreds[image], resolveRegistryCredentials(ctx, pullSecrets, wl, image)...)
		}
	}

	if scanType == cautils.ScanTypeWorkload {
		collectWorkload(workloadinterface.NewWorkloadObj(scanData.SingleResourceScan.GetObject()))
	} else if catalog := scanData.GetCatalog(); catalog != nil {
		catalog.ForEach(func(_ string, workload workloadinterface.IMetadata) bool {
			if workload != nil {
				collectWorkload(workloadinterface.NewWorkloadObj(workload.GetObject()))
			}
			return true
		})
	}

	// Workloads are visited in map order, so the credentials are ordered only
	// once every workload has contributed its matches.
	imageToCreds := make(map[string][]imagescan.RegistryCredentials, len(resolvedCreds))
	for image, resolved := range resolvedCreds {
		if len(resolved) > 0 {
			imageToCreds[image] = orderRegistryCredentials(resolved)
		}
	}

	return imagesToScan, imageToCreds, containerErrors
}

func addImageScanTarget(targets mapset.Set[ImageScanTarget], target ImageScanTarget) {
	nonSkip := ImageScanTarget{Image: target.Image, Platform: target.Platform, SkipUnavailable: false}
	if targets.Contains(nonSkip) {
		return
	}
	if target.SkipUnavailable {
		targets.Add(target)
		return
	}
	targets.Remove(ImageScanTarget{Image: target.Image, Platform: target.Platform, SkipUnavailable: true})
	targets.Add(target)
}

func registryCredentialsFromScanInfo(scanInfo *cautils.ScanInfo) imagescan.RegistryCredentials {
	if scanInfo == nil {
		return imagescan.RegistryCredentials{}
	}
	return imagescan.RegistryCredentials{
		Authority: scanInfo.RegistryAuthority,
		Username:  scanInfo.RegistryUsername,
		Password:  scanInfo.RegistryPassword,
		Token:     scanInfo.RegistryToken,
	}
}

func scanSingleImage(ctx context.Context, img string, svc imageScanService, resultsHandling *resultshandling.ResultsHandler, registryMapping map[string]string, creds imagescan.RegistryCredentials) error {

	scanResults, err := scanWithRegistryMapping(
		ctx, svc, img, []imagescan.RegistryCredentials{creds},
		registryMapping, nil, nil, "",
	)
	if err != nil {
		return err
	}

	resultsHandling.ImageScanData = append(resultsHandling.ImageScanData, *scanResults)
	return nil
}

func isPrioritizationScanType(scanType cautils.ScanTypes) bool {
	return scanType == cautils.ScanTypeCluster || scanType == cautils.ScanTypeRepo
}

// isAirGappedMode returns true if the scan is configured to run in air-gapped mode,
// i.e. the user explicitly wants to load everything from local files via --use-from,
// with no network access to download the framework/policy at all. The other local-file
// flags (--controls-config, --exceptions, --attack-tracks) each have their own
// dedicated local-file-first branch in their respective getter functions in
// initutils.go and don't need to disable the network downloader entirely.
func isAirGappedMode(scanInfo *cautils.ScanInfo) bool {
	return len(scanInfo.UseFrom) > 0
}

// estimateClusterSize estimates the cluster size for determining if streaming should be enabled.
// For cluster scans it delegates to the resource handler which queries the API server
// with metadata-only LIST requests. For file-based scans it returns 0.
// Returns 0 on error so that a failed estimate falls back to the non-streaming path.
func estimateClusterSize(resourceHandler resourcehandler.IResourceHandler, ctx context.Context, scanInfo *cautils.ScanInfo) int {
	if scanInfo.GetScanningContext() != cautils.ContextCluster {
		return 0
	}

	size, err := resourceHandler.EstimateClusterSize(ctx, scanInfo)
	if err != nil {
		logger.L().Ctx(ctx).Warning("failed to estimate cluster size, falling back to non-streaming", helpers.Error(err))
		return 0
	}
	return size
}

// collectAndProcessResourcesWithStreaming collects and processes resources in
// batches so the evaluation input stays bounded on large clusters.
// estimatedClusterSize is the pre-scan cluster-size estimate the streaming
// decision was made from; the OPA processor uses it as its frozen resource
// count because sessionObj.AllResources is populated asynchronously by the
// producer goroutine.
//
// incrementalCacheSchemaVersion 3: verdicts are only stored for hermetic rules
// whose findings are attributable per object. Caches written by earlier
// schemas may hold verdicts of rules that are no longer cacheable.
const incrementalCacheSchemaVersion = "3"

// incrementalCacheContext contains every scan-wide value that can affect a
// cache-eligible rule. ResourceHash covers the resource itself; this context
// covers the inputs shared by every resource evaluation.
//
// Keep this as a named, versioned wire format. Adding a policy input without
// including it here could make an old verdict look valid for a different scan.
type incrementalCacheContext struct {
	SchemaVersion  string `json:"schemaVersion"`
	RuntimeVersion string `json:"runtimeVersion"`
	CloudProvider  string `json:"cloudProvider"`
}

// incrementalCacheVersion derives the cache namespace from both policy
// content and scan-wide evaluation inputs. In particular, cloudProvider is
// exposed to Rego as data.dataControlInputs.cloudProvider, so two otherwise
// identical resources from different providers must never share a verdict.
func incrementalCacheVersion(scanInfo *cautils.ScanInfo, scanData *cautils.OPASessionObj, runtimeVersion string) (string, error) {
	// Development builds intentionally do not have a stable build identity.
	// Reusing a persistent verdict cache for them is unsafe: source changes can
	// alter evaluator behavior while the binary continues to report "dev".
	// Returning an error makes the caller run without the persistent cache.
	if runtimeVersion == "" || runtimeVersion == "dev" {
		return "", errors.New("incremental cache requires a release build identity")
	}
	if scanInfo == nil {
		return "", errors.New("scan info is required")
	}
	if scanData == nil {
		return "", errors.New("scan data is required")
	}
	if scanData.Report == nil {
		return "", errors.New("scan report is required")
	}

	contextBytes, err := json.Marshal(incrementalCacheContext{
		SchemaVersion:  incrementalCacheSchemaVersion,
		RuntimeVersion: runtimeVersion,
		CloudProvider:  scanData.Report.ClusterCloudProvider,
	})
	if err != nil {
		return "", fmt.Errorf("marshal incremental cache context: %w", err)
	}
	policyBytes, err := json.Marshal(scanData.Policies)
	if err != nil {
		return "", fmt.Errorf("marshal resolved policies: %w", err)
	}
	allPoliciesBytes, err := json.Marshal(scanData.AllPolicies)
	if err != nil {
		return "", fmt.Errorf("marshal resolved policy rules: %w", err)
	}
	regoInputBytes, err := json.Marshal(scanData.RegoInputData)
	if err != nil {
		return "", fmt.Errorf("marshal Rego input data: %w", err)
	}

	versionParts := [][]byte{
		contextBytes,
		[]byte(scanInfo.ControlsVersion),
		policyBytes,
		allPoliciesBytes,
		regoInputBytes,
	}
	if scanInfo.ControlsInputs != "" {
		localConfig, readErr := os.ReadFile(scanInfo.ControlsInputs)
		if readErr != nil {
			return "", fmt.Errorf("read controls inputs for cache version: %w", readErr)
		}
		versionParts = append(versionParts, localConfig)
	}
	return scancache.VersionKey(versionParts...), nil
}

// loadIncrementalCacheIfEnabled builds the version key from the complete
// evaluation context and loads the incremental scan cache. It returns nil
// when incremental mode is off or a safe version cannot be derived.
func loadIncrementalCacheIfEnabled(ctx context.Context, scanInfo *cautils.ScanInfo, scanData *cautils.OPASessionObj) *scancache.Store {
	if !scanInfo.Incremental {
		return nil
	}
	cacheVersion, versionErr := incrementalCacheVersion(scanInfo, scanData, versioncheck.BuildNumber)
	if versionErr != nil {
		logger.L().Ctx(ctx).Warning("failed to derive incremental scan cache version, proceeding without cache", helpers.Error(versionErr))
		return nil
	}
	cacheStore, cacheErr := scancache.Load(getter.DefaultLocalStore, cacheVersion)
	if cacheErr != nil {
		logger.L().Ctx(ctx).Warning("failed to load incremental scan cache, proceeding without it", helpers.Error(cacheErr))
		return nil
	}
	return cacheStore
}

func collectAndProcessResourcesWithStreaming(ctx context.Context, resourceHandler resourcehandler.IResourceHandler, scanData *cautils.OPASessionObj, scanInfo *cautils.ScanInfo, clusterName string, excludedNamespaces string, includeNamespaces string, enableRegoPrint bool, controlTimeout time.Duration, estimatedClusterSize int) error {
	// The eager collector initializes this metadata before constructing the OPA
	// processor. Do the same here because the cloud provider is a policy input,
	// not only report metadata.
	resourcehandler.CollectClusterMetadata(ctx, resourceHandler, scanData)

	// Construct the processor before starting the producer goroutine. The
	// producer does not touch scanData's resource maps (it carries them on the
	// resident batch instead), but constructing first means the constructor's
	// reads of scanData cannot race a producer write regardless of what the
	// producer does later — the invariant is enforced by ordering rather than by
	// a comment in the resource handler.
	deps := resources.NewRegoDependenciesData(k8sinterface.GetK8sConfig(), clusterName)
	exceptionRecorder, shutdownRecorder := newSecurityExceptionEventRecorder(ctx)
	if shutdownRecorder != nil {
		defer shutdownRecorder()
	}
	reportResults := opaprocessor.NewOPAProcessor(scanData, deps, clusterName, excludedNamespaces, includeNamespaces, enableRegoPrint, exceptionRecorder)
	reportResults.ControlTimeout = controlTimeout
	reportResults.SetWholeClusterPolicy(scanInfo.GetWholeClusterPolicy())
	if cacheStore := loadIncrementalCacheIfEnabled(ctx, scanInfo, scanData); cacheStore != nil {
		reportResults.SetIncrementalCache(cacheStore)
		defer func() {
			if flushErr := cacheStore.Flush(); flushErr != nil {
				logger.L().Ctx(ctx).Warning("failed to persist incremental scan cache", helpers.Error(flushErr))
			}
		}()
	}

	// Stream resources in batches
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	batchChan, errChan, expectedNamespaceBatches, err := resourceHandler.StreamResourcesBatches(streamCtx, scanData, scanInfo)
	if err != nil {
		return fmt.Errorf("failed to start resource streaming: %w", err)
	}
	// AllResources is still empty here — the producer goroutine fills it only
	// after the resident batch is sent — so the frozen bucketing count must
	// come from the estimate rather than the construction-time snapshot.
	reportResults.SetInitialResourceCount(estimatedClusterSize)

	// Process batches with streaming
	if err := reportResults.ProcessWithStreaming(streamCtx, batchChan, errChan, cautils.NewProgressHandler(""), expectedNamespaceBatches); err != nil {
		return fmt.Errorf("failed to process rules with streaming: %w", err)
	}

	return nil
}

func getAllWorkloadImages(wl *workloadinterface.Workload) ([]string, []error) {
	var images []string
	var containerErrors []error
	addContainerError := func(containerClass string, err error) {
		containerErrors = append(containerErrors, fmt.Errorf("failed to get %s for kind: %s, name: %s, namespace: %s: %w", containerClass, wl.GetKind(), wl.GetName(), wl.GetNamespace(), err))
	}

	if containers, err := wl.GetContainers(); err != nil {
		addContainerError("containers", err)
	} else {
		for _, c := range containers {
			if c.Image != "" {
				images = append(images, c.Image)
			}
		}
	}
	if initContainers, err := wl.GetInitContainers(); err != nil {
		addContainerError("init containers", err)
	} else {
		for _, c := range initContainers {
			if c.Image != "" {
				images = append(images, c.Image)
			}
		}
	}
	if ephemeralContainers, err := wl.GetEphemeralContainers(); err != nil {
		addContainerError("ephemeral containers", err)
	} else {
		for _, c := range ephemeralContainers {
			if c.Image != "" {
				images = append(images, c.Image)
			}
		}
	}
	return images, containerErrors
}

// printPreflightResult prints the --dry-run RBAC check to stdout.
func printPreflightResult(result *resourcehandler.PreflightResult) {
	for _, f := range result.DiscoveryFailures {
		fmt.Printf("DISCOVERY FAILED  %s: %s\n", f.GVR, f.Error)
	}

	errored := result.Errored()
	for _, c := range errored {
		fmt.Printf("CHECK FAILED  list %s: %s\n", c.GVR, c.Reason)
	}

	denied := result.Denied()
	if len(denied) == 0 && len(errored) == 0 {
		fmt.Printf("All %d required resource type(s) can be listed with the current credentials.\n", len(result.Checks))
		return
	}

	for _, c := range denied {
		// The API server's reason is what tells a user which binding to fix, so
		// print it when there is one; RBAC often answers with none.
		if c.Reason != "" {
			fmt.Printf("DENIED  list %s: %s\n", c.GVR, c.Reason)
		} else {
			fmt.Printf("DENIED  list %s\n", c.GVR)
		}
		if len(c.AffectedControls) > 0 {
			fmt.Printf("        -> %s will not evaluate\n", strings.Join(c.AffectedControls, ", "))
		}
	}

	allowed := len(result.Checks) - len(denied) - len(errored)
	fmt.Printf("\n%d/%d required resource type(s) can be listed. %d denied, %d could not be checked.\n", allowed, len(result.Checks), len(denied), len(errored))
}
