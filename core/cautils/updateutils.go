package cautils

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/armosec/utils-go/boolutils"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v2/core/cautils/getter"

	"golang.org/x/mod/semver"
)

type IVersionCheckHandlerU interface {
	CheckLatestVersionU(*VersionCheckRequestU) error
}

func NewIVersionCheckHandlerU() IVersionCheckHandlerU {
	if BuildNumber == "" {
		logger.L().Warning("unknown build number, this might affect your scan results. Please make sure you are updated to latest version")
	}
	if v, ok := os.LookupEnv(SKIP_VERSION_CHECK); ok && boolutils.StringToBool(v) {
		return NewVersionCheckHandlerMockU()
	} else if v, ok := os.LookupEnv(SKIP_VERSION_CHECK_DEPRECATED); ok && boolutils.StringToBool(v) {
		return NewVersionCheckHandlerMockU()
	}
	return NewVersionCheckHandlerU()
}

type VersionCheckHandlerMockU struct {
}

func NewVersionCheckHandlerMockU() *VersionCheckHandlerMockU {
	return &VersionCheckHandlerMockU{}
}

type VersionCheckHandlerU struct {
	versionURL string
}
type VersionCheckRequestU struct {
	Client           string `json:"client"`           // kubescape
	ClientBuild      string `json:"clientBuild"`      // client build environment
	ClientVersion    string `json:"clientVersion"`    // kubescape version
	Framework        string `json:"framework"`        // framework name
	FrameworkVersion string `json:"frameworkVersion"` // framework version
	ScanningTarget   string `json:"target"`           // Deprecated
	ScanningContext  string `json:"context"`          // scanning context- cluster/file/gitURL/localGit/dir
}

type VersionCheckResponseU struct {
	Client          string `json:"client"`          // kubescape
	ClientUpdate    string `json:"clientUpdate"`    // kubescape latest version
	Framework       string `json:"framework"`       // framework name
	FrameworkUpdate string `json:"frameworkUpdate"` // framework latest version
	Message         string `json:"message"`         // alert message
}

func NewVersionCheckHandlerU() *VersionCheckHandlerU {
	return &VersionCheckHandlerU{
		versionURL: "https://us-central1-elated-pottery-310110.cloudfunctions.net/ksgf1v1",
	}
}
func NewVersionCheckRequestU(buildNumber, frameworkName, frameworkVersion, scanningTarget string) *VersionCheckRequestU {
	if buildNumber == "" {
		buildNumber = UnknownBuildNumber
	}
	if scanningTarget == "" {
		scanningTarget = "unknown"
	}
	if Client == "" {
		Client = "local-build"
	}
	return &VersionCheckRequestU{
		Client:           "kubescape",
		ClientBuild:      Client,
		ClientVersion:    buildNumber,
		Framework:        frameworkName,
		FrameworkVersion: frameworkVersion,
		ScanningTarget:   scanningTarget,
	}
}

func (v *VersionCheckHandlerMockU) CheckLatestVersionU(versionData *VersionCheckRequestU) error {
	logger.L().Info("Skipping version check")
	return nil
}

func (v *VersionCheckHandlerU) CheckLatestVersionU(versionData *VersionCheckRequestU) error {
	defer func() {
		if err := recover(); err != nil {
			logger.L().Warning("failed to get latest version", helpers.Interface("error", err))
		}
	}()

	latestVersion, err := v.getLatestVersionU(versionData)
	if err != nil || latestVersion == nil {
		return fmt.Errorf("failed to get latest version")
	}

	LatestReleaseVersion := latestVersion.ClientUpdate

	if latestVersion.ClientUpdate != "" {
		if BuildNumber != "" && semver.Compare(BuildNumber, LatestReleaseVersion) == -1 {
			logger.L().Warning(warningMessage(LatestReleaseVersion))
		}
	}

	if latestVersion.Message != "" {
		logger.L().Info(latestVersion.Message)
	}

	return nil
}

func (v *VersionCheckHandlerU) getLatestVersionU(versionData *VersionCheckRequestU) (*VersionCheckResponseU, error) {

	reqBody, err := json.Marshal(*versionData)
	if err != nil {
		return nil, fmt.Errorf("in 'CheckLatestVersion' failed to json.Marshal, reason: %s", err.Error())
	}

	resp, err := getter.HttpPost(http.DefaultClient, v.versionURL, map[string]string{"Content-Type": "application/json"}, reqBody)
	if err != nil {
		return nil, err
	}

	vResp := &VersionCheckResponseU{}
	if err = getter.JSONDecoder(resp).Decode(vResp); err != nil {
		return nil, err
	}
	return vResp, nil
}

func warningMessageU(release string) string {
	return fmt.Sprintf("Updating your current version '%s' to the latest release: '%s' ...", BuildNumber, release)
}
