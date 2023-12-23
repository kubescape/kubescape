package download

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/core"
	"github.com/kubescape/kubescape/v3/core/meta"
	v1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/spf13/cobra"
	"golang.org/x/exp/slices"
)

var (
	downloadExample = fmt.Sprintf(`
  # Download all artifacts and save them in the default path (~/.kubescape)
  %[1]s download artifacts
  
  # Download all artifacts and save them in /tmp path
  %[1]s download artifacts --output /tmp
  
  # Download the NSA framework. Run '%[1]s list frameworks' for all frameworks names
  %[1]s download framework nsa

  # Download the "C-0001" control. Run '%[1]s list controls --id' for all controls ids
  %[1]s download control "C-0001"

  # Download the "C-0001" control. Run '%[1]s list controls --id' for all controls ids
  %[1]s download control C-0001

  # Download the configured exceptions
  %[1]s download exceptions 

  # Download the configured controls-inputs 
  %[1]s download controls-inputs 
`, cautils.ExecName())
)

func GetDownloadCmd(ks meta.IKubescape) *cobra.Command {
	var downloadInfo = v1.DownloadInfo{}

	downloadCmd := &cobra.Command{
		Use:     "download <policy> <policy name>",
		Short:   fmt.Sprintf("Download %s", strings.Join(core.DownloadSupportCommands(), ",")),
		Long:    ``,
		Example: downloadExample,
		Args: func(cmd *cobra.Command, args []string) error {
			supported := strings.Join(core.DownloadSupportCommands(), ",")
			if len(args) < 1 {
				return fmt.Errorf("policy type required, supported: %v", supported)
			}
			if !slices.Contains(core.DownloadSupportCommands(), args[0]) {
				return fmt.Errorf("invalid parameter '%s'. Supported parameters: %s", args[0], supported)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {

			if err := flagValidationDownload(&downloadInfo); err != nil {
				return err
			}

			if filepath.Ext(downloadInfo.Path) == ".json" {
				downloadInfo.Path, downloadInfo.FileName = filepath.Split(downloadInfo.Path)
			}

			if len(args) == 0 {
				return fmt.Errorf("no arguements provided")
			}

			downloadInfo.Target = args[0]
			if len(args) >= 2 {

				downloadInfo.Identifier = args[1]

			}
			if err := ks.Download(context.TODO(), &downloadInfo); err != nil {
				logger.L().Fatal(err.Error())
			}
			return nil
		},
	}

	downloadCmd.PersistentFlags().StringVarP(&downloadInfo.AccountID, "account", "", "", "Kubescape SaaS account ID. Default will load account ID from cache")
	downloadCmd.PersistentFlags().StringVarP(&downloadInfo.AccessKey, "access-key", "", "", "Kubescape SaaS access key. Default will load access key from cache")
	downloadCmd.Flags().StringVarP(&downloadInfo.Path, "output", "o", "", "Output file. If not specified, will save in `~/.kubescape/<policy name>.json`")

	return downloadCmd
}

// Check if the flag entered are valid
func flagValidationDownload(downloadInfo *v1.DownloadInfo) error {

	// Validate the user's credentials
	return cautils.ValidateAccountID(downloadInfo.AccountID)
}
