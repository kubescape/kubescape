package cautils

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/armosec/utils-go/boolutils"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v2/core/cautils/getter"
	"go.opentelemetry.io/otel"
	"golang.org/x/mod/semver"
)

const SKIP_VERSION_CHECK_DEPRECATED_ENV = "KUBESCAPE_SKIP_UPDATE_CHECK"
const SKIP_VERSION_CHECK_ENV = "KS_SKIP_UPDATE_CHECK"
const CLIENT_ENV = "KS_CLIENT"

var BuildNumber string
var Client string
var LatestReleaseVersion string

const UnknownBuildNumber = "unknown"

type IVersionCheckHandler interface {
	CheckLatestVersion(context.Context, *VersionCheckRequest) error
}

func NewIVersionCheckHandler(ctx context.Context) IVersionCheckHandler {
	if BuildNumber == "" {
		logger.L().Ctx(ctx).Warning("unknown build number, this might affect your scan results. Please make sure you are updated to latest version")
	}

	if v, ok := os.LookupEnv(CLIENT_ENV); ok && v != "" {
		Client = v
	}

	if v, ok := os.LookupEnv(SKIP_VERSION_CHECK_ENV); ok && boolutils.StringToBool(v) {
		return NewVersionCheckHandlerMock()
	} else if v, ok := os.LookupEnv(SKIP_VERSION_CHECK_DEPRECATED_ENV); ok && boolutils.StringToBool(v) {
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
	ClientBuild      string `json:"clientBuild"`      // client build environment
	ClientVersion    string `json:"clientVersion"`    // kubescape version
	Framework        string `json:"framework"`        // framework name
	FrameworkVersion string `json:"frameworkVersion"` // framework version
	ScanningTarget   string `json:"target"`           // Deprecated
	ScanningContext  string `json:"context"`          // scanning context- cluster/file/gitURL/localGit/dir
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
	if Client == "" {
		Client = "local-build"
	}
	return &VersionCheckRequest{
		Client:           "kubescape",
		ClientBuild:      Client,
		ClientVersion:    buildNumber,
		Framework:        frameworkName,
		FrameworkVersion: frameworkVersion,
		ScanningTarget:   scanningTarget,
	}
}

func (v *VersionCheckHandlerMock) CheckLatestVersion(_ context.Context, _ *VersionCheckRequest) error {
	logger.L().Info("Skipping version check")
	return nil
}

func (v *VersionCheckHandler) CheckLatestVersion(ctx context.Context, versionData *VersionCheckRequest) error {
	ctx, span := otel.Tracer("").Start(ctx, "versionCheckHandler.CheckLatestVersion")
	defer span.End()
	defer func() {
		if err := recover(); err != nil {
			logger.L().Ctx(ctx).Warning("failed to get latest version", helpers.Interface("error", err))
		}
	}()

	latestVersion, err := v.getLatestVersion(versionData)
	if err != nil || latestVersion == nil {
		return fmt.Errorf("failed to get latest version")
	}

	LatestReleaseVersion := latestVersion.ClientUpdate

	if latestVersion.ClientUpdate != "" {
		if BuildNumber != "" && semver.Compare(BuildNumber, LatestReleaseVersion) == -1 {
			logger.L().Ctx(ctx).Warning(warningMessage(LatestReleaseVersion))
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

func warningMessage(release string) string {
	return fmt.Sprintf("current version '%s' is not updated to the latest release: '%s'", BuildNumber, release)
}
