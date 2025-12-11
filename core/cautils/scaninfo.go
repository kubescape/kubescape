package cautils

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
	localControlInputsFilename string = "controls-inputs.json"
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
	switch val {
	case "true":
		bpf.SetBool(true)
	case "false":
		bpf.SetBool(false)
	}
	return nil
}

// TODO - UPDATE
type ViewTypes string
type EnvScopeTypes string
type ManageClusterTypes string

const (
	ResourceViewType ViewTypes = "resource"
	SecurityViewType ViewTypes = "security"
	ControlViewType  ViewTypes = "control"
)

type PolicyIdentifier struct {
	Identifier string                        // policy Identifier e.g. c-0012 for control, nsa,mitre for frameworks
	Kind       apisv1.NotificationPolicyKind // policy kind e.g. Framework,Control,Rule
}

type ScanInfo struct {
	Getters                                            // TODO - remove from object
	PolicyIdentifier      []PolicyIdentifier           // TODO - remove from object
	UseExceptions         string                       // Load file with exceptions configuration
	ControlsInputs        string                       // Load file with inputs for controls
	AttackTracks          string                       // Load file with attack tracks
	UseFrom               []string                     // Load framework from local file (instead of download). Use when running offline
	UseDefault            bool                         // Load framework from cached file (instead of download). Use when running offline
	UseArtifactsFrom      string                       // Load artifacts from local path. Use when running offline
	VerboseMode           bool                         // Display all the input resources and not only failed resources
	View                  string                       //
	Format                string                       // Format results (table, json, junit ...)
	Output                string                       // Store results in an output file, Output file name
	FormatVersion         string                       // Output object can be different between versions, this is for testing and backward compatibility
	CustomClusterName     string                       // Set the custom name of the cluster
	ExcludedNamespaces    string                       // used for host scanner namespace
	IncludeNamespaces     string                       //
	InputPatterns         []string                     // Yaml files input patterns
	Silent                bool                         // Silent mode - Do not print progress logs
	FailThreshold         float32                      // DEPRECATED - Failure score threshold
	ComplianceThreshold   float32                      // Compliance score threshold
	FailThresholdSeverity string                       // Severity at and above which the command should fail
	Submit                bool                         // Submit results to Kubescape Cloud BE
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
	ChartPath             string
	FilePath              string
	scanningContext       *ScanningContext
	cleanups              []func()
}

type Getters struct {
	ExceptionsGetter     getter.IExceptionsGetter
	ControlsInputsGetter getter.IControlsInputsGetter
	PolicyGetter         getter.IPolicyGetter
	AttackTracksGetter   getter.IAttackTracksGetter
}

func (scanInfo *ScanInfo) Init(ctx context.Context) {
	scanInfo.setUseFrom()
	scanInfo.setUseArtifactsFrom(ctx)
	if scanInfo.ScanID == "" {
		scanInfo.ScanID = uuid.NewString()
	}
}

func (scanInfo *ScanInfo) Cleanup() {
	for _, cleanup := range scanInfo.cleanups {
		cleanup()
	}
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
	scanInfo.ControlsInputs = filepath.Join(scanInfo.UseArtifactsFrom, localControlInputsFilename)
	// set exceptions
	scanInfo.UseExceptions = filepath.Join(scanInfo.UseArtifactsFrom, LocalExceptionsFilename)

	// set attack tracks
	scanInfo.AttackTracks = filepath.Join(scanInfo.UseArtifactsFrom, LocalAttackTracksFilename)
}

func (scanInfo *ScanInfo) setUseFrom() {
	if scanInfo.UseDefault {
		for _, policy := range scanInfo.PolicyIdentifier {
			scanInfo.UseFrom = append(scanInfo.UseFrom, getter.GetDefaultPath(policy.Identifier+".json"))
		}
	}
}

// Formats returns a slice of output formats that have been requested for a given scan
func (scanInfo *ScanInfo) Formats() []string {
	formatString := scanInfo.Format
	if formatString != "" {
		return strings.Split(scanInfo.Format, ",")
	} else {
		return []string{}
	}
}

func (scanInfo *ScanInfo) SetScanType(scanType ScanTypes) {
	scanInfo.ScanType = scanType
}

func (scanInfo *ScanInfo) SetPolicyIdentifiers(policies []string, kind apisv1.NotificationPolicyKind) {
	for _, policy := range policies {
		if !scanInfo.contains(policy) {
			newPolicy := PolicyIdentifier{}
			newPolicy.Kind = kind
			newPolicy.Identifier = policy
			scanInfo.PolicyIdentifier = append(scanInfo.PolicyIdentifier, newPolicy)
		}
	}
}

func (scanInfo *ScanInfo) contains(policyName string) bool {
	for _, policy := range scanInfo.PolicyIdentifier {
		if policy.Identifier == policyName {
			return true
		}
	}
	return false
}

func scanInfoToScanMetadata(ctx context.Context, scanInfo *ScanInfo) *reporthandlingv2.Metadata {
	metadata := &reporthandlingv2.Metadata{}

	metadata.ScanMetadata.Formats = []string{scanInfo.Format}
	metadata.ScanMetadata.FormatVersion = scanInfo.FormatVersion
	metadata.ScanMetadata.Submit = scanInfo.Submit

	// TODO - Add excluded and included namespaces
	// if len(scanInfo.ExcludedNamespaces) > 1 {
	// 	opaSessionObj.Metadata.ScanMetadata.ExcludedNamespaces = strings.Split(scanInfo.ExcludedNamespaces[1:], ",")
	// }
	// if len(scanInfo.IncludeNamespaces) > 1 {
	// 	opaSessionObj.Metadata.ScanMetadata.IncludeNamespaces = strings.Split(scanInfo.IncludeNamespaces[1:], ",")
	// }

	// scan type
	if len(scanInfo.PolicyIdentifier) > 0 {
		metadata.ScanMetadata.TargetType = string(scanInfo.PolicyIdentifier[0].Kind)
	}
	// append frameworks
	for _, policy := range scanInfo.PolicyIdentifier {
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
	isURL := strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://")

	// git url
	if _, err := giturl.NewGitURL(input); err == nil {
		if repo, err := CloneGitRepo(&input); err == nil {
			if _, err := NewLocalGitRepository(repo); err == nil {
				scanInfo.cleanups = append(scanInfo.cleanups, func() {
					_ = os.RemoveAll(repo)
				})
				return ContextGitRemote
			}
		}
		// If giturl.NewGitURL succeeded but cloning failed, the input is a git URL
		// that couldn't be cloned. Don't treat it as a local path.
		// The clone error was already logged by CloneGitRepo
		return ContextDir // Return ContextDir to trigger "no files found" error with clear URL context
	}

	// If it looks like a URL but wasn't recognized as a git URL, still don't treat it as a local path
	if isURL {
		logger.L().Error("URL provided but not recognized as a valid git repository", helpers.String("url", input))
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

func (scanInfo *ScanInfo) setContextMetadata(ctx context.Context, contextMetadata *reporthandlingv2.ContextMetadata) {
	input := scanInfo.GetInputFiles()
	switch scanInfo.GetScanningContext() {
	case ContextCluster:
		contextMetadata.ClusterContextMetadata = &reporthandlingv2.ClusterMetadata{
			ContextName: k8sinterface.GetContextName(),
		}
	case ContextDir:
		contextMetadata.DirectoryContextMetadata = &reporthandlingv2.DirectoryContextMetadata{
			BasePath: getAbsPath(input),
			HostName: getHostname(),
		}
		// add repo context for submitting
		contextMetadata.RepoContextMetadata = &reporthandlingv2.RepoContextMetadata{
			Provider:      "none",
			Repo:          fmt.Sprintf("path@%s", getAbsPath(input)),
			Owner:         getHostname(),
			Branch:        "none",
			DefaultBranch: "none",
			LocalRootPath: getAbsPath(input),
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
			LocalRootPath: getAbsPath(input),
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
	gitParser, err := NewLocalGitRepository(input)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	remoteURL, err := gitParser.GetRemoteUrl()
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	repoContext := &reporthandlingv2.RepoContextMetadata{}
	gitParserURL, err := giturl.NewGitURL(remoteURL)
	if err != nil {
		return repoContext, fmt.Errorf("%w", err)
	}
	gitParserURL.SetBranchName(gitParser.GetBranchName())

	repoContext.Provider = gitParserURL.GetProvider()
	repoContext.Repo = gitParserURL.GetRepoName()
	repoContext.Owner = gitParserURL.GetOwnerName()
	repoContext.Branch = gitParserURL.GetBranchName()
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
	repoContext.LocalRootPath, _ = gitParser.GetRootDir()

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
