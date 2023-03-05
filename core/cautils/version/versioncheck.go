package version

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	conv "github.com/armosec/utils-go/boolutils"
	jsoniter "github.com/json-iterator/go"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"go.opentelemetry.io/otel"
	"golang.org/x/mod/semver"
)

var json jsoniter.API

func init() {
	json = jsoniter.ConfigFastest
}

// Environment variables driving the version checker.
const (
	SKIP_VERSION_CHECK_DEPRECATED_ENV = "KUBESCAPE_SKIP_UPDATE_CHECK"
	SKIP_VERSION_CHECK_ENV            = "KS_SKIP_UPDATE_CHECK"
	CLIENT_ENV                        = "KS_CLIENT"
)

const (
	versionURL = "https://us-central1-elated-pottery-310110.cloudfunctions.net/ksgf1v1"
)

// Version-related variables.
var (
	// BuildNumber is set to the git release tag (semver). It is initialized at build time when cutting a release (see build script)
	//
	// NOTE: it is not hydrated when building from source (e.g. go build).
	BuildNumber string

	// LatestReleaseVersion is the semver tag of the latest published version.
	LatestReleaseVersion string

	// Client app built with the ks libraries.
	Client string

	mx sync.RWMutex // serializes access to mutable package level variables
)

var _ IChecker = &Checker{}

type (
	// IChecker knows how to check the current version against the latest published release.
	IChecker interface {
		CheckLatestVersion(context.Context, ...CheckRequestOption) error
	}

	// Checker inquires kubescape's versioning cloud function to retrieve version information.
	Checker struct {
		versionURL string
	}

	CheckRequestOption func(*versionCheckRequest)

	versionCheckRequest struct {
		Client           string `json:"client"`           // kubescape
		ClientBuild      string `json:"clientBuild"`      // client build environment
		ClientVersion    string `json:"clientVersion"`    // kubescape version
		Framework        string `json:"framework"`        // framework name
		FrameworkVersion string `json:"frameworkVersion"` // framework version
		ScanningTarget   string `json:"target"`           // Deprecated
		ScanningContext  string `json:"context"`          // scanning context- cluster/file/gitURL/localGit/dir
	}

	versionCheckResponse struct {
		Client          string `json:"client"`          // kubescape
		ClientUpdate    string `json:"clientUpdate"`    // kubescape latest version
		Framework       string `json:"framework"`       // framework name
		FrameworkUpdate string `json:"frameworkUpdate"` // framework latest version
		Message         string `json:"message"`         // alert message
	}
)

// IsCurrentAtLatest tells whether we're up to date.
func IsCurrentAtLatest() bool {
	mx.RLock()
	defer mx.RUnlock()

	return BuildNumber == LatestReleaseVersion
}

// NewIChecker returns the appropriate version checker depending on the environment settings.
//
// If the environment variable "KUBESCAPE_SKIP_UPDATE_CHECK" is set to "true" (or "1"), the check is skipped.
func NewIChecker(ctx context.Context) IChecker {
	mx.RLock()
	buildNumber := BuildNumber
	mx.RUnlock()

	if buildNumber == "" {
		logger.L().Ctx(ctx).Warning(
			"unknown build number, this might affect your scan results. Please make sure you are updated to latest version",
		)
	}

	if shouldSkip := conv.StringToBool(os.Getenv(SKIP_VERSION_CHECK_ENV)) || conv.StringToBool(os.Getenv(SKIP_VERSION_CHECK_DEPRECATED_ENV)); shouldSkip {
		return NewSkipChecker()
	}

	return NewChecker()
}

// NewChecker returns a version checker.
func NewChecker() *Checker {
	return &Checker{
		versionURL: versionURL,
	}
}

func defaultCheckRequest() *versionCheckRequest {
	var (
		defaultClient string
		defaultBuild  string
	)
	clientFromEnv := os.Getenv(CLIENT_ENV)
	mx.RLock()
	buildNumber := BuildNumber
	clientFromBuild := Client
	mx.RUnlock()

	switch {
	case clientFromEnv != "":
		defaultClient = clientFromEnv
	case clientFromBuild != "":
		defaultClient = clientFromBuild
	default:
		defaultClient = "local-build"
	}

	if buildNumber != "" {
		defaultBuild = buildNumber
	} else {
		defaultBuild = "unknown"
	}

	return &versionCheckRequest{
		Client:           "kubescape",
		ClientBuild:      defaultClient,
		ClientVersion:    defaultBuild,
		Framework:        "",
		FrameworkVersion: "",
		ScanningTarget:   "version",
	}
}

func WithFramework(framework string) CheckRequestOption {
	return func(r *versionCheckRequest) {
		r.Framework = framework
	}
}

func WithFrameworkVersion(version string) CheckRequestOption {
	return func(r *versionCheckRequest) {
		r.FrameworkVersion = version
	}
}

// WithTarget specifies the scanning target to request the appropriate version.
//
// By default, the "version" target returns the kubescape version.
//
// TODO(fredbi): use enum
func WithTarget(target string) CheckRequestOption {
	return func(r *versionCheckRequest) {
		r.ScanningTarget = target
	}
}

func newCheckRequest(opts []CheckRequestOption) *versionCheckRequest {
	req := defaultCheckRequest()

	for _, apply := range opts {
		apply(req)
	}

	return req
}

// CheckLatestVersion checks for the latest published version.
func (v *Checker) CheckLatestVersion(ctx context.Context, opts ...CheckRequestOption) error {
	ctx, span := otel.Tracer("").Start(ctx, "versionCheckHandler.CheckLatestVersion")
	defer span.End()

	versionRequest := newCheckRequest(opts)
	latestVersion, err := v.getLatestVersion(ctx, versionRequest)
	if err != nil {
		logger.L().Ctx(ctx).Debug("failed to get latest version", helpers.Error(err))

		return fmt.Errorf("failed to get latest version")
	}

	if latestVersion.ClientUpdate != "" && versionRequest.ClientVersion != "" && semver.Compare(versionRequest.ClientVersion, latestVersion.ClientUpdate) == -1 {
		logger.L().Ctx(ctx).Warning(
			fmt.Sprintf("current version '%s' is not updated to the latest release: '%s'", versionRequest.ClientVersion, latestVersion.ClientUpdate),
		)
	}

	// TODO - Enable after supporting framework version
	// if latestVersion.FrameworkUpdate != "" {
	// 	fmt.Println(warningMessage(latestVersion.Framework, latestVersion.FrameworkUpdate))
	// }

	if latestVersion.Message != "" {
		logger.L().Ctx(ctx).Info(latestVersion.Message)
	}

	mx.Lock()
	LatestReleaseVersion = latestVersion.ClientUpdate
	mx.Unlock()

	return nil
}

func (v *Checker) getLatestVersion(ctx context.Context, versionData *versionCheckRequest) (*versionCheckResponse, error) {
	body, err := json.Marshal(*versionData)
	if err != nil {
		return nil, fmt.Errorf("in 'CheckLatestVersion' failed to json.Marshal, reason: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.versionURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errAPI(resp)
	}

	dec := json.NewDecoder(resp.Body)
	dec.UseNumber()

	version := &versionCheckResponse{}
	if err = dec.Decode(&version); err != nil {
		return nil, err
	}

	return version, nil
}

func errAPI(resp *http.Response) error {
	const maxSize int64 = 1024

	reason := new(strings.Builder)
	if resp.Body != nil {
		var size int64
		if resp.ContentLength > maxSize {
			size = maxSize
		} else {
			size = resp.ContentLength
		}

		if size > 0 {
			reason.Grow(int(size))
		}
		_, _ = io.CopyN(reason, resp.Body, size)
	}

	return fmt.Errorf("http-error: '%s', reason: '%s'", resp.Status, reason.String())
}
