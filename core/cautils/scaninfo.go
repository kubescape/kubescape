package cautils

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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

	"github.com/google/uuid"
)

type ScanningContext string

const (
	ContextCluster  ScanningContext = "cluster"
	ContextFile     ScanningContext = "single-file"
	ContextDir      ScanningContext = "local-dir"
	ContextGitURL   ScanningContext = "git-url"
	ContextGitLocal ScanningContext = "git-local"
)

const ( // deprecated
	ScopeCluster = "cluster"
	ScopeYAML    = "yaml"
)
const (
	// ScanCluster                string = "cluster"
	// ScanLocalFiles             string = "yaml"
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
	VerboseMode           bool                         // Display all of the input resources and not only failed resources
	View                  string                       // Display all of the input resources and not only failed resources
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
	ScanObject            *objectsenvelopes.ScanObject // identifies a single resource (k8s object) to be scanned
	IsDeletedScanObject   bool                         // indicates whether the ScanObject is a deleted K8S resource
	ScanType              ScanTypes
	ScanImages            bool
	ChartPath             string
	FilePath              string
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

	inputFiles := ""
	if len(scanInfo.InputPatterns) > 0 {
		inputFiles = scanInfo.InputPatterns[0]
	}
	switch GetScanningContext(inputFiles) {
	case ContextCluster:
		// cluster
		metadata.ScanMetadata.ScanningTarget = reporthandlingv2.Cluster
	case ContextFile:
		// local file
		metadata.ScanMetadata.ScanningTarget = reporthandlingv2.File
	case ContextGitURL:
		// url
		metadata.ScanMetadata.ScanningTarget = reporthandlingv2.Repo
	case ContextGitLocal:
		// local-git
		metadata.ScanMetadata.ScanningTarget = reporthandlingv2.GitLocal
	case ContextDir:
		// directory
		metadata.ScanMetadata.ScanningTarget = reporthandlingv2.Directory

	}

	setContextMetadata(ctx, &metadata.ContextMetadata, inputFiles)

	return metadata
}

func (scanInfo *ScanInfo) GetScanningContext() ScanningContext {
	if len(scanInfo.InputPatterns) > 0 {
		return GetScanningContext(scanInfo.InputPatterns[0])
	}
	return GetScanningContext("")
}

// GetScanningContext get scanning context from the input param
func GetScanningContext(input string) ScanningContext {
	//  cluster
	if input == "" {
		return ContextCluster
	}

	// url
	if _, err := giturl.NewGitURL(input); err == nil {
		return ContextGitURL
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
func setContextMetadata(ctx context.Context, contextMetadata *reporthandlingv2.ContextMetadata, input string) {
	switch GetScanningContext(input) {
	case ContextCluster:
		contextMetadata.ClusterContextMetadata = &reporthandlingv2.ClusterMetadata{
			ContextName: k8sinterface.GetContextName(),
		}
	case ContextGitURL:
		// url
		context, err := metadataGitURL(input)
		if err != nil {
			logger.L().Ctx(ctx).Warning("in setContextMetadata", helpers.Interface("case", ContextGitURL), helpers.Error(err))
		}
		contextMetadata.RepoContextMetadata = context
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
		context, err := metadataGitLocal(input)
		if err != nil {
			logger.L().Ctx(ctx).Warning("in setContextMetadata", helpers.Interface("case", ContextGitURL), helpers.Error(err))
		}
		contextMetadata.RepoContextMetadata = context
	}
}

func metadataGitURL(input string) (*reporthandlingv2.RepoContextMetadata, error) {
	context := &reporthandlingv2.RepoContextMetadata{}
	gitParser, err := giturl.NewGitAPI(input)
	if err != nil {
		return context, fmt.Errorf("%w", err)
	}
	if gitParser.GetBranchName() == "" {
		gitParser.SetDefaultBranchName()
	}
	context.Provider = gitParser.GetProvider()
	context.Repo = gitParser.GetRepoName()
	context.Owner = gitParser.GetOwnerName()
	context.Branch = gitParser.GetBranchName()
	context.RemoteURL = gitParser.GetURL().String()

	commit, err := gitParser.GetLatestCommit()
	if err != nil {
		return context, fmt.Errorf("%w", err)
	}

	context.LastCommit = reporthandling.LastCommit{
		Hash:          commit.SHA,
		Date:          commit.Committer.Date,
		CommitterName: commit.Committer.Name,
	}

	return context, nil
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
	context := &reporthandlingv2.RepoContextMetadata{}
	gitParserURL, err := giturl.NewGitURL(remoteURL)
	if err != nil {
		return context, fmt.Errorf("%w", err)
	}
	gitParserURL.SetBranchName(gitParser.GetBranchName())

	context.Provider = gitParserURL.GetProvider()
	context.Repo = gitParserURL.GetRepoName()
	context.Owner = gitParserURL.GetOwnerName()
	context.Branch = gitParserURL.GetBranchName()
	context.RemoteURL = gitParserURL.GetURL().String()

	commit, err := gitParser.GetLastCommit()
	if err != nil {
		return context, fmt.Errorf("%w", err)
	}
	context.LastCommit = reporthandling.LastCommit{
		Hash:          commit.SHA,
		Date:          commit.Committer.Date,
		CommitterName: commit.Committer.Name,
	}
	context.LocalRootPath, _ = gitParser.GetRootDir()

	return context, nil
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

// ScanningContextToScanningScope convert the context to the deprecated scope
func ScanningContextToScanningScope(scanningContext ScanningContext) string {
	if scanningContext == ContextCluster {
		return ScopeCluster
	}
	return ScopeYAML
}
