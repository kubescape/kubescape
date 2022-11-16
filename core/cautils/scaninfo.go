package cautils

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"

	giturl "github.com/armosec/go-git-url"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v2/core/cautils/getter"
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
	localExceptionsFilename    string = "exceptions.json"
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

const (
	ResourceViewType ViewTypes = "resource"
	ControlViewType  ViewTypes = "control"
)

type PolicyIdentifier struct {
	Name        string                        // policy name e.g. nsa,mitre,c-0012
	Kind        apisv1.NotificationPolicyKind // policy kind e.g. Framework,Control,Rule
	Designators armotypes.PortalDesignator
}

type ScanInfo struct {
	Getters                                  // TODO - remove from object
	PolicyIdentifier      []PolicyIdentifier // TODO - remove from object
	UseExceptions         string             // Load file with exceptions configuration
	ControlsInputs        string             // Load file with inputs for controls
	UseFrom               []string           // Load framework from local file (instead of download). Use when running offline
	UseDefault            bool               // Load framework from cached file (instead of download). Use when running offline
	UseArtifactsFrom      string             // Load artifacts from local path. Use when running offline
	VerboseMode           bool               // Display all of the input resources and not only failed resources
	View                  string             // Display all of the input resources and not only failed resources
	Format                string             // Format results (table, json, junit ...)
	Output                string             // Store results in an output file, Output file name
	FormatVersion         string             // Output object can be differnet between versions, this is for testing and backward compatibility
	CustomClusterName     string             // Set the custom name of the cluster
	ExcludedNamespaces    string             // used for host scanner namespace
	IncludeNamespaces     string             //
	InputPatterns         []string           // Yaml files input patterns
	Silent                bool               // Silent mode - Do not print progress logs
	FailThreshold         float32            // Failure score threshold
	FailThresholdSeverity string             // Severity at and above which the command should fail
	Submit                bool               // Submit results to Kubescape Cloud BE
	ScanID                string             // Report id of the current scan
	HostSensorEnabled     BoolPtrFlag        // Deploy Kubescape K8s host scanner to collect data from certain controls
	HostSensorYamlPath    string             // Path to hostsensor file
	Local                 bool               // Do not submit results
	Credentials           Credentials        // account ID
	KubeContext           string             // context name
	FrameworkScan         bool               // false if scanning control
	ScanAll               bool               // true if scan all frameworks
}

type Getters struct {
	ExceptionsGetter     getter.IExceptionsGetter
	ControlsInputsGetter getter.IControlsInputsGetter
	PolicyGetter         getter.IPolicyGetter
	AttackTracksGetter   getter.IAttackTracksGetter
}

func (scanInfo *ScanInfo) Init() {
	scanInfo.setUseFrom()
	scanInfo.setOutputFile()
	scanInfo.setUseArtifactsFrom()
	if scanInfo.ScanID == "" {
		scanInfo.ScanID = uuid.NewString()
	}

}

func (scanInfo *ScanInfo) setUseArtifactsFrom() {
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
		logger.L().Fatal("failed to read files from directory", helpers.String("dir", scanInfo.UseArtifactsFrom), helpers.Error(err))
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
	scanInfo.UseExceptions = filepath.Join(scanInfo.UseArtifactsFrom, localExceptionsFilename)
}

func (scanInfo *ScanInfo) setUseFrom() {
	if scanInfo.UseDefault {
		for _, policy := range scanInfo.PolicyIdentifier {
			scanInfo.UseFrom = append(scanInfo.UseFrom, getter.GetDefaultPath(policy.Name+".json"))
		}
	}
}

func (scanInfo *ScanInfo) setOutputFile() {
	if scanInfo.Output == "" {
		return
	}
	if scanInfo.Format == "json" {
		if filepath.Ext(scanInfo.Output) != ".json" {
			scanInfo.Output += ".json"
		}
	}
	if scanInfo.Format == "junit" {
		if filepath.Ext(scanInfo.Output) != ".xml" {
			scanInfo.Output += ".xml"
		}
	}
	if scanInfo.Format == "pdf" {
		if filepath.Ext(scanInfo.Output) != ".pdf" {
			scanInfo.Output += ".pdf"
		}
	}
}

func (scanInfo *ScanInfo) SetPolicyIdentifiers(policies []string, kind apisv1.NotificationPolicyKind) {
	for _, policy := range policies {
		if !scanInfo.contains(policy) {
			newPolicy := PolicyIdentifier{}
			newPolicy.Kind = kind
			newPolicy.Name = policy
			scanInfo.PolicyIdentifier = append(scanInfo.PolicyIdentifier, newPolicy)
		}
	}
}

func (scanInfo *ScanInfo) contains(policyName string) bool {
	for _, policy := range scanInfo.PolicyIdentifier {
		if policy.Name == policyName {
			return true
		}
	}
	return false
}

func scanInfoToScanMetadata(scanInfo *ScanInfo) *reporthandlingv2.Metadata {
	metadata := &reporthandlingv2.Metadata{}

	metadata.ScanMetadata.Format = scanInfo.Format
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
		metadata.ScanMetadata.TargetNames = append(metadata.ScanMetadata.TargetNames, policy.Name)
	}

	metadata.ScanMetadata.KubescapeVersion = BuildNumber
	metadata.ScanMetadata.VerboseMode = scanInfo.VerboseMode
	metadata.ScanMetadata.FailThreshold = scanInfo.FailThreshold
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

	setContextMetadata(&metadata.ContextMetadata, inputFiles)

	return metadata
}

func (scanInfo *ScanInfo) GetScanningContext() ScanningContext {
	input := ""
	if len(scanInfo.InputPatterns) > 0 {
		input = scanInfo.InputPatterns[0]
	}
	return GetScanningContext(input)
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
	if IsFile(input) {
		return ContextFile
	}

	//  dir/glob
	return ContextDir
}
func setContextMetadata(contextMetadata *reporthandlingv2.ContextMetadata, input string) {
	switch GetScanningContext(input) {
	case ContextCluster:
		contextMetadata.ClusterContextMetadata = &reporthandlingv2.ClusterMetadata{
			ContextName: k8sinterface.GetContextName(),
		}
	case ContextGitURL:
		// url
		context, err := metadataGitURL(input)
		if err != nil {
			logger.L().Warning("in setContextMetadata", helpers.Interface("case", ContextGitURL), helpers.Error(err))
		}
		contextMetadata.RepoContextMetadata = context
	case ContextDir:
		contextMetadata.DirectoryContextMetadata = &reporthandlingv2.DirectoryContextMetadata{
			BasePath: getAbsPath(input),
			HostName: getHostname(),
		}
	case ContextFile:
		contextMetadata.FileContextMetadata = &reporthandlingv2.FileContextMetadata{
			FilePath: getAbsPath(input),
			HostName: getHostname(),
		}
	case ContextGitLocal:
		// local
		context, err := metadataGitLocal(input)
		if err != nil {
			logger.L().Warning("in setContextMetadata", helpers.Interface("case", ContextGitURL), helpers.Error(err))
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
	context.LocalRootPath = getAbsPath(input)

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
