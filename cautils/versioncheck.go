package cautils

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/armosec/kubescape/cautils/getter"
	pkgutils "github.com/armosec/utils-go/utils"
)

const SKIP_VERSION_CHECK = "KUBESCAPE_SKIP_UPDATE_CHECK"

var BuildNumber string

type IVersionCheckHandler interface {
	CheckLatestVersion(*VersionCheckRequest) error
}

func NewIVersionCheckHandler() IVersionCheckHandler {
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
	return &VersionCheckRequest{
		Client:           "kubescape",
		ClientVersion:    buildNumber,
		Framework:        frameworkName,
		FrameworkVersion: frameworkVersion,
		ScanningTarget:   scanningTarget,
	}
}

func (v *VersionCheckHandlerMock) CheckLatestVersion(versionData *VersionCheckRequest) error {
	fmt.Println("Skipping version check")
	return nil
}

func (v *VersionCheckHandler) CheckLatestVersion(versionData *VersionCheckRequest) error {

	latestVersion, err := v.getLatestVersion(versionData)
	if err != nil || latestVersion == nil {
		return fmt.Errorf("failed to get latest version: %v", err)
	}

	if latestVersion.ClientUpdate != "" {
		fmt.Println(warningMessage(latestVersion.Client, latestVersion.ClientUpdate))
	}

	if latestVersion.FrameworkUpdate != "" {
		fmt.Println(warningMessage(latestVersion.Framework, latestVersion.FrameworkUpdate))
	}
	return nil
}

func (v *VersionCheckHandler) getLatestVersion(versionData *VersionCheckRequest) (*VersionCheckResponse, error) {

	reqBody, err := json.Marshal(versionData)
	if err != nil {
		return nil, fmt.Errorf("in 'CheckLatestVersion' failed to json.Marshal, reason: %v", err)
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
	return fmt.Sprintf("Warning: '%s' is not updated to the latest release: '%s'", kind, release)
}
