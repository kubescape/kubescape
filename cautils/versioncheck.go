package cautils

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/armosec/kubescape/cautils/getter"
	"github.com/armosec/kubescape/cautils/logger"
	"github.com/armosec/kubescape/cautils/logger/helpers"
	pkgutils "github.com/armosec/utils-go/utils"
)

const SKIP_VERSION_CHECK = "KUBESCAPE_SKIP_UPDATE_CHECK"

var BuildNumber string

const UnknownBuildNumber = "unknown"

type IVersionCheckHandler interface {
	CheckLatestVersion(*VersionCheckRequest) error
}

func NewIVersionCheckHandler() IVersionCheckHandler {
	if BuildNumber == "" {
		logger.L().Warning("unknown build number, this might affect your scan results. Please make sure you are updated to latest version")
	}
	if v, ok := os.LookupEnv(SKIP_VERSION_CHECK); ok && pkgutils.StringToBool(v) {
		return NewVersionCheckHandlerMock()
	}
	return NewVersionCheckHandler()
}

type VersionCheckHandlerMock struct {
}

func NewVersionCheckHandlerMock() *VersionCheckHandlerMock {
	return &VersionCheckHandlerMock{}
}

type VersionCheckHandler struct {
	versionURL string
}
type VersionCheckRequest struct {
	Client           string `json:"client"`           // kubescape
	ClientVersion    string `json:"clientVersion"`    // kubescape version
	Framework        string `json:"framework"`        // framework name
	FrameworkVersion string `json:"frameworkVersion"` // framework version
	ScanningTarget   string `json:"target"`           // scanning target- cluster/yaml
}

type VersionCheckResponse struct {
	Client          string `json:"client"`          // kubescape
	ClientUpdate    string `json:"clientUpdate"`    // kubescape latest version
	Framework       string `json:"framework"`       // framework name
	FrameworkUpdate string `json:"frameworkUpdate"` // framework latest version
	Message         string `json:"message"`         // alert message
}

func NewVersionCheckHandler() *VersionCheckHandler {
	return &VersionCheckHandler{
		versionURL: "https://us-central1-elated-pottery-310110.cloudfunctions.net/ksgf1v1",
	}
}
func NewVersionCheckRequest(buildNumber, frameworkName, frameworkVersion, scanningTarget string) *VersionCheckRequest {
	if buildNumber == "" {
		buildNumber = UnknownBuildNumber
	}
	if scanningTarget == "" {
		scanningTarget = "unknown"
	}
	return &VersionCheckRequest{
		Client:           "kubescape",
		ClientVersion:    buildNumber,
		Framework:        frameworkName,
		FrameworkVersion: frameworkVersion,
		ScanningTarget:   scanningTarget,
	}
}

func (v *VersionCheckHandlerMock) CheckLatestVersion(versionData *VersionCheckRequest) error {
	logger.L().Info("Skipping version check")
	return nil
}

func (v *VersionCheckHandler) CheckLatestVersion(versionData *VersionCheckRequest) error {
	defer func() {
		if err := recover(); err != nil {
			logger.L().Warning("failed to get latest version", helpers.Interface("error", err))
		}
	}()

	latestVersion, err := v.getLatestVersion(versionData)
	if err != nil || latestVersion == nil {
		return fmt.Errorf("failed to get latest version")
	}

	if latestVersion.ClientUpdate != "" {
		if BuildNumber != "" && BuildNumber < latestVersion.ClientUpdate {
			logger.L().Warning(warningMessage(latestVersion.Client, latestVersion.ClientUpdate))
		}
	}

	// TODO - Enable after supporting framework version
	// if latestVersion.FrameworkUpdate != "" {
	// 	fmt.Println(warningMessage(latestVersion.Framework, latestVersion.FrameworkUpdate))
	// }

	if latestVersion.Message != "" {
		logger.L().Info(latestVersion.Message)
	}

	return nil
}

func (v *VersionCheckHandler) getLatestVersion(versionData *VersionCheckRequest) (*VersionCheckResponse, error) {

	reqBody, err := json.Marshal(*versionData)
	if err != nil {
		return nil, fmt.Errorf("in 'CheckLatestVersion' failed to json.Marshal, reason: %s", err.Error())
	}

	resp, err := getter.HttpPost(http.DefaultClient, v.versionURL, map[string]string{"Content-Type": "application/json"}, reqBody)
	if err != nil {
		return nil, err
	}

	vResp := &VersionCheckResponse{}
	if err = getter.JSONDecoder(resp).Decode(vResp); err != nil {
		return nil, err
	}
	return vResp, nil
}

func warningMessage(kind, release string) string {
	return fmt.Sprintf("'%s' is not updated to the latest release: '%s'", kind, release)
}
