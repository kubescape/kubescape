package scan

import (
	"context"
	"fmt"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/core"
	"github.com/kubescape/kubescape/v2/core/meta"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling"
	"github.com/kubescape/kubescape/v2/pkg/imagescan"

	"github.com/spf13/cobra"
)

type imageScanInfo struct {
	Username string
	Password string
}

// TODO(vladklokun): document image scanning on the Kubescape Docs Hub?
var (
	imageExample = fmt.Sprintf(`
  This command is still in BETA. Feel free to contact the kubescape maintainers for more information.
  
  Scan an image for vulnerabilities. 

  # Scan the 'nginx' image
  %[1]s scan image "nginx"

  # Image scan documentation:
  # https://hub.armosec.io/docs/images
`, cautils.ExecName())
)

// imageCmd represents the image command
func getImageCmd(ks meta.IKubescape, scanInfo *cautils.ScanInfo, imgScanInfo *imageScanInfo) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "image <IMAGE_NAME>",
		Short:   "Scan an image for vulnerabilities",
		Example: imageExample,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("the command takes exactly one image name as an argument")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateImageScanInfo(scanInfo); err != nil {
				return err
			}
			failOnSeverity := imagescan.ParseSeverity(scanInfo.FailThresholdSeverity)

			ctx := context.Background()
			dbCfg, _ := imagescan.NewDefaultDBConfig()
			svc := imagescan.NewScanService(dbCfg)

			creds := imagescan.RegistryCredentials{
				Username: imgScanInfo.Username,
				Password: imgScanInfo.Password,
			}

			userInput := args[0]

			logger.L().Start(fmt.Sprintf("Scanning image: %s", userInput))
			scanResults, err := svc.Scan(ctx, userInput, creds)
			if err != nil {
				logger.L().StopError(fmt.Sprintf("Failed to scan image: %s", userInput))
				return err
			}
			logger.L().StopSuccess(fmt.Sprintf("Successfully scanned image: %s", userInput))

			scanInfo.SetScanType(cautils.ScanTypeImage)

			outputPrinters := core.GetOutputPrinters(scanInfo, ctx)

			uiPrinter := core.GetUIPrinter(ctx, scanInfo)

			resultsHandler := resultshandling.NewResultsHandler(nil, outputPrinters, uiPrinter)

			resultsHandler.ImageScanData = []cautils.ImageScanData{
				{
					PresenterConfig: scanResults,
					Image:           userInput,
				},
			}

			resultsHandler.HandleResults(ctx)

			if imagescan.ExceedsSeverityThreshold(scanResults, failOnSeverity) {
				terminateOnExceedingSeverity(scanInfo, logger.L())
			}

			return err
		},
	}

	cmd.PersistentFlags().StringVarP(&imgScanInfo.Username, "username", "u", "", "Username for registry login")
	cmd.PersistentFlags().StringVarP(&imgScanInfo.Password, "password", "p", "", "Password for registry login")

	return cmd
}

// validateImageScanInfo validates the ScanInfo struct for the `image` command
func validateImageScanInfo(scanInfo *cautils.ScanInfo) error {
	severity := scanInfo.FailThresholdSeverity

	if err := validateSeverity(severity); severity != "" && err != nil {
		return err
	}
	return nil
}
