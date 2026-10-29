package update

//This update command updates to the latest kubescape release.
//Example:-
//          kubescape update

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kubescape/kubescape/v4/core/meta"

	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/spf13/cobra"
	"golang.org/x/mod/semver"
)

const (
	installationLink string = "https://kubescape.io/docs/install-cli/"
)

var updateCmdExamples = fmt.Sprintf(`
  # Update to the latest kubescape release
  %[1]s update
`, cautils.ExecName())

type UpdateInfo struct {
	LatestVersion    string `json:"latestVersion,omitempty"`
	InstallationLink string `json:"installationLink,omitempty"`
	Message          string `json:"message,omitempty"`
}

// newVersionCheckHandler is the seam used by GetUpdateCmd so unit tests can
// substitute a mock without changing runtime behaviour. The update command
// intentionally does NOT use versioncheck.NewIVersionCheckHandler: that
// constructor returns a no-op mock when KS_SKIP_UPDATE_CHECK is set, which is a
// scan/deploy knob ("don't phone home during scans") and must not disable the
// one command whose purpose is checking for a release.
var newVersionCheckHandler = func() versioncheck.IVersionCheckHandler {
	return versioncheck.NewVersionCheckHandler()
}

func GetUpdateCmd(ks meta.IKubescape) *cobra.Command {
	var updateFormat string
	updateCmd := &cobra.Command{
		Use:     "update",
		Short:   "Update to latest release version",
		Long:    ``,
		Example: updateCmdExamples,
		RunE: func(cmd *cobra.Command, args []string) error {
			if updateFormat != "text" && updateFormat != "json" {
				return fmt.Errorf("unsupported format %q, supported: text, json", updateFormat)
			}

			v := newVersionCheckHandler()
			versionCheckRequest := versioncheck.NewVersionCheckRequest("", versioncheck.BuildNumber, "", "", "update", nil)
			if err := v.CheckLatestVersion(ks.Context(), versionCheckRequest); err != nil {
				return err
			}

			if updateFormat == "json" {
				info := UpdateInfo{}
				if isDevelopmentBuild(versioncheck.BuildNumber) {
					info.Message = "Nothing to update: you are running the development version"
				} else if isLatestVersion(versioncheck.BuildNumber, versioncheck.LatestReleaseVersion) {
					info.Message = "Nothing to update: you are running the latest version"
				} else {
					info.LatestVersion = versioncheck.LatestReleaseVersion
					info.InstallationLink = installationLink
				}
				b, err := json.Marshal(info)
				if err != nil {
					return fmt.Errorf("failed to marshal update info: %w", err)
				}
				_, err = fmt.Fprintln(cmd.OutOrStdout(), string(b))
				return err
			}

			//Checking the user's version of kubescape to the latest release
			if isDevelopmentBuild(versioncheck.BuildNumber) {
				//your version is unknown
				fmt.Printf("Nothing to update: you are running the development version\n")
			} else if isLatestVersion(versioncheck.BuildNumber, versioncheck.LatestReleaseVersion) {
				//your version is the latest version
				logger.L().Info("Nothing to update: you are running the latest version", helpers.String("Version", versioncheck.BuildNumber))
			} else {
				fmt.Printf("Version %s is available. Please refer to our installation documentation: %s\n", versioncheck.LatestReleaseVersion, installationLink)
			}
			return nil
		},
	}
	updateCmd.Flags().StringVarP(&updateFormat, "format", "f", "text", "Output format. Supported formats: text, json")
	return updateCmd
}

// isDevelopmentBuild reports whether buildNumber names no release: unset, the
// "dev" version of a build from source, any other version that is not semver,
// or a release candidate.
func isDevelopmentBuild(buildNumber string) bool {
	version := buildNumber
	if version != "" && !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
	return !semver.IsValid(version) || strings.Contains(buildNumber, "rc")
}

// isLatestVersion reports whether a successful version check found no newer
// release. CheckLatestVersion fails when the version service cannot be
// reached, and the service only names a latest release when it is newer than
// the running version, so no latest release means this one is up to date.
func isLatestVersion(buildNumber, latest string) bool {
	return latest == "" || buildNumber == latest
}
