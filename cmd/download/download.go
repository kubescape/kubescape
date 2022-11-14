package download

import (
	"fmt"
	"path/filepath"
	"strings"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/core"
	"github.com/kubescape/kubescape/v2/core/meta"
	v1 "github.com/kubescape/kubescape/v2/core/meta/datastructures/v1"
	"github.com/spf13/cobra"
)

var (
	downloadExample = `
  # Download all artifacts and save them in the default path (~/.kubescape)
  kubescape download artifacts
  
  # Download all artifacts and save them in /tmp path
  kubescape download artifacts --output /tmp
  
  # Download the NSA framework. Run 'kubescape list frameworks' for all frameworks names
  kubescape download framework nsa

  # Download the "HostPath mount" control. Run 'kubescape list controls' for all controls names
  kubescape download control "HostPath mount"

  # Download the "C-0001" control. Run 'kubescape list controls --id' for all controls ids
  kubescape download control C-0001

  # Download the configured exceptions
  kubescape download exceptions 

  # Download the configured controls-inputs 
  kubescape download controls-inputs 

`
)

func GeDownloadCmd(ks meta.IKubescape) *cobra.Command {
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
			if cautils.StringInSlice(core.DownloadSupportCommands(), args[0]) == cautils.ValueNotFound {
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
			downloadInfo.Target = args[0]
			if len(args) >= 2 {
				downloadInfo.Name = args[1]
			}
			if err := ks.Download(&downloadInfo); err != nil {
				logger.L().Fatal(err.Error())
			}
			return nil
		},
	}

	downloadCmd.PersistentFlags().StringVarP(&downloadInfo.Credentials.Account, "account", "", "", "Kubescape SaaS account ID. Default will load account ID from cache")
	downloadCmd.PersistentFlags().StringVarP(&downloadInfo.Credentials.ClientID, "client-id", "", "", "Kubescape SaaS client ID. Default will load client ID from cache, read more - https://hub.armosec.io/docs/authentication")
	downloadCmd.PersistentFlags().StringVarP(&downloadInfo.Credentials.SecretKey, "secret-key", "", "", "Kubescape SaaS secret key. Default will load secret key from cache, read more - https://hub.armosec.io/docs/authentication")
	downloadCmd.Flags().StringVarP(&downloadInfo.Path, "output", "o", "", "Output file. If not specified, will save in `~/.kubescape/<policy name>.json`")

	return downloadCmd
}

// Check if the flag entered are valid
func flagValidationDownload(downloadInfo *v1.DownloadInfo) error {

	// Validate the user's credentials
	return downloadInfo.Credentials.Validate()
}
