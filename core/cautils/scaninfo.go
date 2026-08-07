package cautils

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kubescape/backend/pkg/versioncheck"
	giturl "github.com/kubescape/go-git-url"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/reporthandling"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

type ScanningContext string

const (
	ContextCluster   ScanningContext = "cluster"
	ContextFile      ScanningContext = "single-file"
	ContextDir       ScanningContext = "local-dir"
	ContextGitLocal  ScanningContext = "git-local"
	ContextGitRemote ScanningContext = "git-remote"
)

const ( // deprecated
	ScopeCluster = "cluster"
)
const (
	LocalControlInputsFilename string = "controls-inputs.json"
	LocalExceptionsFilename    string = "exceptions.json"
	LocalAttackTracksFilename  string = "attack-tracks.json"
)

type BoolPtrFlag struct {
	valPtr *bool
}

func NewBoolPtr(b *bool) BoolPtrFlag {
	return BoolPtrFlag{valPtr: b}
}

func (bpf *BoolPtrFlag) Type() string {
	return "bool"
}

func (bpf *BoolPtrFlag) String() string {
	if bpf.valPtr != nil {
		return fmt.Sprintf("%v", *bpf.valPtr)
	}
	return ""
}
func (bpf *BoolPtrFlag) Get() *bool {
	return bpf.valPtr
}
func (bpf *BoolPtrFlag) GetBool() bool {
	if bpf.valPtr == nil {
		return false
	}
	return *bpf.valPtr
}

func (bpf *BoolPtrFlag) SetBool(val bool) {
	bpf.valPtr = &val
}

func (bpf *BoolPtrFlag) Set(val string) error {
	parsed, err := strconv.ParseBool(val)
	if err != nil {
		return err
	}
	bpf.SetBool(parsed)
	return nil
}

// ViewTypes specifies how scan results are presented by the default (pretty) printer.
type ViewTypes string

const (
	// ResourceViewType prints one section per failed resource, listing the
	// controls that failed it. It only takes effect in verbose mode; passed
	// resources are not shown.
	ResourceViewType ViewTypes = "resource"

	// SecurityViewType is the default view (see the --view flag). Rather than
	// changing how results are grouped, it selects a security-oriented set of
	// frameworks to scan with — workloadscan+allcontrols for a repository or
	// directory target, clusterscan+mitre+nsa for a cluster — and prints the
	// standard posture summary without per-control or per-resource detail.
	// Note: the `scan framework` subcommand rewrites this to ResourceViewType.
	SecurityViewType ViewTypes = "security"

	// ControlViewType groups results by control, showing the compliance status
	// of every control and the resources that failed it. Failed and
	// action-required resources are always listed, and passed resources are
	// listed in verbose mode.
	ControlViewType ViewTypes = "control"
)

type PolicyIdentifier struct {
	Identifier string                        // policy Identifier e.g. c-0012 for control, nsa,mitre for frameworks
	Kind       apisv1.NotificationPolicyKind // policy kind e.g. Framework,Control,Rule
}

type ScanInfo struct {
	UseExceptions         string   // Load file with exceptions configuration
	ControlsInputs        string   // Load file with inputs for controls
	AttackTracks          string   // Load file with attack tracks
	UseFrom               []string // Load framework from local file (instead of download). Use when running offline
	UseDefault            bool     // Load framework from cached file (instead of download). Use when running offline
	UseArtifactsFrom      string   // Load artifacts from local path. Use when running offline
	ControlsVersion       string   // Pin the regolibrary release used to download policies (e.g. "v2.0.301"). Empty uses the latest release
	VerboseMode           bool     // Display all the input resources and not only failed resources
	Hide                  bool     // Hide sensitive identifiers (names, namespaces, images) in results
	EncryptionEnabled     bool
	View                  string                       //
	Format                string                       // Format results (table, json, junit ...)
	Output                string                       // Store results in an output file, Output file name
	FormatVersion         string                       // Output object can be different between versions, this is for testing and backward compatibility
	CustomClusterName     string                       // Set the custom name of the cluster
	ExcludedNamespaces    string                       // used for host scanner namespace
	IncludeNamespaces     string                       //
	Namespace             string                       // target namespace for workload scans
	InputPatterns         []string                     // Yaml files input patterns
	Silent                bool                         // Silent mode - Do not print progress logs
	FailThreshold         float32                      // DEPRECATED - Failure score threshold
	ComplianceThreshold   float32                      // Compliance score threshold
	FailThresholdSeverity string                       // Severity at and above which the command should fail
	FailCoverageThreshold float32                      // Coverage threshold below which the command fails (0 = disabled)
	FailOnDegradedConfig  bool                         // Fail the scan if control inputs or exceptions could not be loaded and a fallback was used
	Submit                BoolPtrFlag                  // Submit results to Kubescape Cloud BE. Get() is nil unless explicitly set by the caller (flag/env/request field)
	ScanID                string                       // Report id of the current scan
	HostSensorEnabled     BoolPtrFlag                  // Deploy Kubescape K8s host scanner to collect data from certain controls
	HostSensorYamlPath    string                       // Path to hostsensor file
	Local                 bool                         // Do not submit results
	AccountID             string                       // account ID
	AccessKey             string                       // access key
	FrameworkScan         bool                         // false if scanning control
	ScanAll               bool                         // true if scan all frameworks
	OmitRawResources      bool                         // true if omit raw resources from the output
	PrintAttackTree       bool                         // true if print attack tree
	EnableRegoPrint       bool                         // true if print rego
	ScanObject            *objectsenvelopes.ScanObject // identifies a single resource (k8s object) to be scanned
	IsDeletedScanObject   bool                         // indicates whether the ScanObject is a deleted K8S resource
	TriggeredByCLI        bool                         // indicates whether the scan was triggered by the CLI
	ScanType              ScanTypes
	ScanImages            bool
	UseDefaultMatchers    bool
	ScanTimeout           time.Duration // Maximum duration for the entire scan (0 = no timeout)
	ControlTimeout        time.Duration // Maximum duration for evaluating a single control (0 = no timeout)
	EnableStreaming       bool          // Enable resource streaming for large clusters to keep the evaluation input bounded
	ChartPath             string
	FilePath              string
	HelmValueFiles        []string // -f / --values: paths to Helm values YAML files (repeatable)
	HelmSetValues         []string // --set: Helm value overrides as key=value (repeatable)
	HelmSetStringValues   []string // --set-string: forced-string Helm value overrides
	HelmSetFileValues     []string // --set-file: Helm value overrides whose value is read from a file
	HelmReleaseName       string   // --release-name: Helm release name made available as .Release.Name during render
	HelmReleaseNamespace  string   // --release-namespace: Helm release namespace made available as .Release.Namespace
	LabelsToCopy          []string // Labels to copy from workloads to scan reports
	scanningContext       *ScanningContext
	cleanups              []func()
	ListingURL            string            //Grype vulnerability database URL
	RegistryMapping       map[string]string // Map internal registry URLs to external ones
	RegistryAuthority     string            // Registry host[:port] explicit credentials apply to
	RegistryUsername      string            // Username for workload image registry authentication
	RegistryPassword      string            // Password for workload image registry authentication
	RegistryToken         string            // Bearer token for workload image registry authentication
}

type Getters struct {
	ExceptionsGetter     getter.IExceptionsGetter
	ControlsInputsGetter getter.IControlsInputsGetter
	PolicyGetter         getter.IPolicyGetter
	AttackTracksGetter   getter.IAttackTracksGetter
}

func (scanInfo *ScanInfo) Init(ctx context.Context, policyIdentifiers []PolicyIdentifier) {
	scanInfo.setUseFrom(policyIdentifiers)
	scanInfo.setUseArtifactsFrom(ctx)
	// setUseFrom and setUseArtifactsFrom can resolve to the same file - --use-default and
	// --use-artifacts-from both point at the local store on the offline HTTP handler path -
	// and a repeated path costs an extra read and unmarshal per policy load.
	scanInfo.UseFrom = unique(scanInfo.UseFrom)
	if scanInfo.ScanID == "" {
		scanInfo.ScanID = uuid.NewString()
	}
}

func (scanInfo *ScanInfo) Cleanup() {
	for _, cleanup := range scanInfo.cleanups {
		cleanup()
	}
}

func (scanInfo *ScanInfo) AddCleanup(cleanup func()) {
	scanInfo.cleanups = append(scanInfo.cleanups, cleanup)
}

func (scanInfo *ScanInfo) setUseArtifactsFrom(ctx context.Context) {
	if scanInfo.UseArtifactsFrom == "" {
		return
	}
	// UseArtifactsFrom must be a path without a filename
	dir, file := filepath.Split(scanInfo.UseArtifactsFrom)
	if dir == "" {
		scanInfo.UseArtifactsFrom = file
	} else if strings.Contains(file, ".json") {
		scanInfo.UseArtifactsFrom = dir
	}
	// set frameworks files
	files, err := os.ReadDir(scanInfo.UseArtifactsFrom)
	if err != nil {
		logger.L().Ctx(ctx).Fatal("failed to read files from directory", helpers.String("dir", scanInfo.UseArtifactsFrom), helpers.Error(err))
	}
	framework := &reporthandling.Framework{}
	for _, f := range files {
		filePath := filepath.Join(scanInfo.UseArtifactsFrom, f.Name())
		file, err := os.ReadFile(filePath)
		if err == nil {
			if err := json.Unmarshal(file, framework); err == nil {
				scanInfo.UseFrom = append(scanInfo.UseFrom, filepath.Join(scanInfo.UseArtifactsFrom, f.Name()))
			}
		}
	}
	// set config-inputs file
	if scanInfo.ControlsInputs == "" {
		scanInfo.ControlsInputs = filepath.Join(scanInfo.UseArtifactsFrom, LocalControlInputsFilename)
	}
	// set exceptions
	if scanInfo.UseExceptions == "" {
		scanInfo.UseExceptions = filepath.Join(scanInfo.UseArtifactsFrom, LocalExceptionsFilename)
	}

	// set attack tracks
	if scanInfo.AttackTracks == "" {
		scanInfo.AttackTracks = filepath.Join(scanInfo.UseArtifactsFrom, LocalAttackTracksFilename)
	}
}

func (scanInfo *ScanInfo) setUseFrom(policyIdentifiers []PolicyIdentifier) {
	if scanInfo.UseDefault {
		for _, policy := range policyIdentifiers {
			path, err := getter.PolicyCachePath(policy.Identifier)
			if err != nil {
				logger.L().Warning("skipping default cache lookup for policy", helpers.String("identifier", policy.Identifier), helpers.Error(err))
				continue
			}
			scanInfo.UseFrom = append(scanInfo.UseFrom, path)
		}
	}
}

// Formats returns a slice of output formats that have been requested for a given scan.
// Empty entries and surrounding whitespace are dropped so that inputs like
// "json,,pdf" or "json, ,pdf" do not produce blank format strings.
func (scanInfo *ScanInfo) Formats() []string {
	if scanInfo.Format == "" {
		return []string{}
	}

	var cleaned []string
	for f := range strings.SplitSeq(scanInfo.Format, ",") {
		if v := strings.TrimSpace(f); v != "" {
			cleaned = append(cleaned, v)
		}
	}

	return unique(cleaned)
}

func unique(items []string) []string {
	seen := map[string]bool{}
	result := []string{}

	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}

func (scanInfo *ScanInfo) SetScanType(scanType ScanTypes) {
	scanInfo.ScanType = scanType
}

// BuildPolicyIdentifiers builds a list of policy identifiers from the given
// string identifiers, adding any new ones that are not already present.
func BuildPolicyIdentifiers(policies []string, kind apisv1.NotificationPolicyKind) []PolicyIdentifier {
	return AppendPolicyIdentifiers(nil, policies, kind)
}

// AppendPolicyIdentifiers appends the given string identifiers to the existing
// list, adding any new ones that are not already present.
func AppendPolicyIdentifiers(existing []PolicyIdentifier, policies []string, kind apisv1.NotificationPolicyKind) []PolicyIdentifier {
	result := append([]PolicyIdentifier(nil), existing...)
	for _, policy := range policies {
		if !containsIdentifier(result, policy) {
			result = append(result, PolicyIdentifier{
				Kind:       kind,
				Identifier: policy,
			})
		}
	}
	return result
}

// containsIdentifier reports whether the named identifier is already present.
// The comparison is case-insensitive because a cache round-trip changes the casing:
// the downloader lists regolibrary's lower case "nsa" and writes a file whose name
// field is "NSA", so LoadPolicy.ListFrameworks reads back a name that no longer matches
// the lower case getter.NativeFrameworks entry. Matching exactly would leave both in the
// list and make downloadScanPolicies fetch and evaluate the same framework twice.
func containsIdentifier(identifiers []PolicyIdentifier, name string) bool {
	for _, policy := range identifiers {
		if strings.EqualFold(policy.Identifier, name) {
			return true
		}
	}
	return false
}

// splitNamespaceList parses a comma-separated namespace list (as accepted by
// --exclude-namespaces / --include-namespaces) into a clean slice. Empty
// entries and surrounding whitespace are dropped.
func splitNamespaceList(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for p := range strings.SplitSeq(s, ",") {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func scanInfoToScanMetadata(ctx context.Context, scanInfo *ScanInfo, policyIdentifiers []PolicyIdentifier) *reporthandlingv2.Metadata {
	metadata := &reporthandlingv2.Metadata{}

	metadata.ScanMetadata.Formats = []string{scanInfo.Format}
	metadata.ScanMetadata.FormatVersion = scanInfo.FormatVersion
	metadata.ScanMetadata.Submit = scanInfo.Submit.GetBool()

	if ns := splitNamespaceList(scanInfo.ExcludedNamespaces); len(ns) > 0 {
		metadata.ScanMetadata.ExcludedNamespaces = ns
	}
	if ns := splitNamespaceList(scanInfo.IncludeNamespaces); len(ns) > 0 {
		metadata.ScanMetadata.IncludeNamespaces = ns
	}

	// scan type
	if len(policyIdentifiers) > 0 {
		metadata.ScanMetadata.TargetType = string(policyIdentifiers[0].Kind)
	}
	// append frameworks
	for _, policy := range policyIdentifiers {
		metadata.ScanMetadata.TargetNames = append(metadata.ScanMetadata.TargetNames, policy.Identifier)
	}

	metadata.ScanMetadata.KubescapeVersion = versioncheck.BuildNumber
	metadata.ScanMetadata.VerboseMode = scanInfo.VerboseMode
	metadata.ScanMetadata.FailThreshold = scanInfo.FailThreshold
	metadata.ScanMetadata.ComplianceThreshold = scanInfo.ComplianceThreshold
	metadata.ScanMetadata.HostScanner = scanInfo.HostSensorEnabled.GetBool()
	metadata.ScanMetadata.VerboseMode = scanInfo.VerboseMode
	metadata.ScanMetadata.ControlsInputs = scanInfo.ControlsInputs

	switch scanInfo.GetScanningContext() {
	case ContextCluster:
		// cluster
		metadata.ScanMetadata.ScanningTarget = reporthandlingv2.Cluster
	case ContextFile:
		// local file
		metadata.ScanMetadata.ScanningTarget = reporthandlingv2.File
	case ContextGitLocal:
		// local-git
		metadata.ScanMetadata.ScanningTarget = reporthandlingv2.GitLocal
	case ContextGitRemote:
		// remote
		metadata.ScanMetadata.ScanningTarget = reporthandlingv2.Repo
	case ContextDir:
		// directory
		metadata.ScanMetadata.ScanningTarget = reporthandlingv2.Directory

	}

	scanInfo.setContextMetadata(ctx, &metadata.ContextMetadata)

	return metadata
}

func (scanInfo *ScanInfo) GetInputFiles() string {
	if len(scanInfo.InputPatterns) > 0 {
		return scanInfo.InputPatterns[0]
	}
	return ""
}

func (scanInfo *ScanInfo) GetScanningContext() ScanningContext {
	if scanInfo.scanningContext == nil {
		scanningContext := scanInfo.getScanningContext(scanInfo.GetInputFiles())
		scanInfo.scanningContext = &scanningContext
	}
	return *scanInfo.scanningContext
}

// getScanningContext get scanning context from the input param
// this function should be called only once. Call GetScanningContext() to get the scanning context
func (scanInfo *ScanInfo) getScanningContext(input string) ScanningContext {
	//  cluster
	if input == "" {
		return ContextCluster
	}

	// Check if input is a URL (http:// or https://)
	isURL := isHTTPURL(input)

	// git url
	if _, err := giturl.NewGitURL(input); err == nil {
		originalInput := input
		if repo, err := CloneGitRepo(&input); err == nil {
			if _, err := NewLocalGitRepository(repo); err == nil {
				scanInfo.AddCleanup(func() {
					if err := ReleaseClonedRepo(originalInput); err != nil {
						logger.L().Warning("failed to clean up cloned repository", helpers.String("url", originalInput), helpers.Error(err))
					}
				})
				scanInfo.cloneAdditionalRemoteInputs(originalInput)
				return ContextGitRemote
			}
			if err := ReleaseClonedRepo(originalInput); err != nil {
				logger.L().Warning("failed to clean up invalid cloned repository", helpers.String("url", originalInput), helpers.Error(err))
			}
		}
		// If giturl.NewGitURL succeeded but cloning failed, the input is a git URL
		// that couldn't be cloned. Don't treat it as a local path.
		// The clone error was already logged by CloneGitRepo.
		// Return ContextDir to prevent the URL from being joined with the current directory
		// and to trigger a "no files found" error with the actual URL (not a mangled path).
		return ContextDir
	}

	// If it looks like a URL but wasn't recognized as a git URL, still don't treat it as a local path
	if isURL {
		logger.L().Error("URL provided but not recognized as a valid git repository. Ensure the URL is correct and accessible", helpers.String("url", input))
		return ContextDir
	}

	if !filepath.IsAbs(input) { // parse path
		if o, err := os.Getwd(); err == nil {
			input = filepath.Join(o, input)
		}
	}

	// local git repo
	if _, err := NewLocalGitRepository(input); err == nil {
		return ContextGitLocal
	}

	//  single file
	if isFile(input) {
		return ContextFile
	}

	//  dir/glob
	return ContextDir
}

// cloneAdditionalRemoteInputs prepares every remote input before file loading.
// Previously only the first URL was cloned, so later URL inputs were interpreted
// as local filesystem paths and silently skipped.
func (scanInfo *ScanInfo) cloneAdditionalRemoteInputs(firstInput string) {
	for _, candidate := range scanInfo.InputPatterns {
		if candidate == firstInput {
			continue
		}
		if _, err := giturl.NewGitURL(candidate); err != nil {
			continue
		}

		originalInput := candidate
		if _, err := CloneGitRepo(&candidate); err != nil {
			logger.L().Error("failed to clone additional git input", helpers.String("url", originalInput), helpers.Error(err))
			continue
		}
		scanInfo.AddCleanup(func() {
			if err := ReleaseClonedRepo(originalInput); err != nil {
				logger.L().Warning("failed to clean up cloned repository", helpers.String("url", originalInput), helpers.Error(err))
			}
		})
	}
}

func (scanInfo *ScanInfo) setContextMetadata(ctx context.Context, contextMetadata *reporthandlingv2.ContextMetadata) {
	input := scanInfo.GetInputFiles()
	switch scanInfo.GetScanningContext() {
	case ContextCluster:
		contextMetadata.ClusterContextMetadata = &reporthandlingv2.ClusterMetadata{
			ContextName: k8sinterface.GetContextName(),
		}
	case ContextDir:
		// the base path must be the root the file loader anchored the resources'
		// relative paths on, or the two no longer compose for anyone joining them
		basePath := ScanRootPath(input)
		contextMetadata.DirectoryContextMetadata = &reporthandlingv2.DirectoryContextMetadata{
			BasePath: basePath,
			HostName: getHostname(),
		}
		// add repo context for submitting
		contextMetadata.RepoContextMetadata = &reporthandlingv2.RepoContextMetadata{
			Provider:      "none",
			Repo:          fmt.Sprintf("path@%s", getAbsPath(input)),
			Owner:         getHostname(),
			Branch:        "none",
			DefaultBranch: "none",
			LocalRootPath: basePath,
		}

	case ContextFile:
		contextMetadata.FileContextMetadata = &reporthandlingv2.FileContextMetadata{
			FilePath: getAbsPath(input),
			HostName: getHostname(),
		}
		// add repo context for submitting
		contextMetadata.RepoContextMetadata = &reporthandlingv2.RepoContextMetadata{
			Provider:      "none",
			Repo:          fmt.Sprintf("file@%s", getAbsPath(input)),
			Owner:         getHostname(),
			Branch:        "none",
			DefaultBranch: "none",
			LocalRootPath: ScanRootPath(input),
		}
	case ContextGitLocal:
		// local
		repoContext, err := metadataGitLocal(input)
		if err != nil {
			logger.L().Ctx(ctx).Warning("in setContextMetadata", helpers.Interface("case", ContextGitLocal), helpers.Error(err))
		}
		contextMetadata.RepoContextMetadata = repoContext
	case ContextGitRemote:
		// remote
		repoContext, err := metadataGitLocal(GetClonedPath(input))
		if err != nil {
			logger.L().Ctx(ctx).Warning("in setContextMetadata", helpers.Interface("case", ContextGitRemote), helpers.Error(err))
		}
		contextMetadata.RepoContextMetadata = repoContext
	}
}

func metadataGitLocal(input string) (*reporthandlingv2.RepoContextMetadata, error) {
	repoContext := &reporthandlingv2.RepoContextMetadata{
		Branch:        "none",
		DefaultBranch: "none",
		LocalRootPath: getAbsPath(input),
	}
	gitParser, err := NewLocalGitRepository(input)
	if err != nil {
		return repoContext, fmt.Errorf("%w", err)
	}
	if root, rootErr := gitParser.GetRootDir(); rootErr == nil {
		repoContext.LocalRootPath = root
	}
	remoteURL, err := gitParser.GetRemoteUrl()
	if err != nil {
		return repoContext, fmt.Errorf("%w", err)
	}
	gitParserURL, err := giturl.NewGitURL(remoteURL)
	if err != nil {
		return repoContext, fmt.Errorf("%w", err)
	}
	branchName := gitParser.GetBranchName()
	if branchName != "" {
		gitParserURL.SetBranchName(branchName)
		repoContext.Branch = branchName
		repoContext.DefaultBranch = ""
	}

	repoContext.Provider = gitParserURL.GetProvider()
	repoContext.Repo = gitParserURL.GetRepoName()
	repoContext.Owner = gitParserURL.GetOwnerName()
	repoContext.RemoteURL = gitParserURL.GetURL().String()

	commit, err := gitParser.GetLastCommit()
	if err != nil {
		return repoContext, fmt.Errorf("%w", err)
	}
	repoContext.LastCommit = reporthandling.LastCommit{
		Hash:          commit.SHA,
		Date:          commit.Committer.Date,
		CommitterName: commit.Committer.Name,
	}
	return repoContext, nil
}
func getHostname() string {
	if h, e := os.Hostname(); e == nil {
		return h
	}
	return ""
}

func getAbsPath(p string) string {
	if !filepath.IsAbs(p) { // parse path
		if o, err := os.Getwd(); err == nil {
			return filepath.Join(o, p)
		}
	}
	return p
}

// isHTTPURL checks if the input string is an HTTP or HTTPS URL
func isHTTPURL(input string) bool {
	return strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://")
}
