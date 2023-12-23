package core

import (
	"context"
	"fmt"

	"github.com/anchore/grype/grype/presenter/models"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v3/core/cautils"
	ksmetav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling"
	"github.com/kubescape/kubescape/v3/pkg/imagescan"
)

func (ks *Kubescape) ScanImage(ctx context.Context, imgScanInfo *ksmetav1.ImageScanInfo, scanInfo *cautils.ScanInfo) (*models.PresenterConfig, error) {
	logger.L().Start(fmt.Sprintf("Scanning image %s...", imgScanInfo.Image))

	dbCfg, _ := imagescan.NewDefaultDBConfig()
	svc := imagescan.NewScanService(dbCfg)

	creds := imagescan.RegistryCredentials{
		Username: imgScanInfo.Username,
		Password: imgScanInfo.Password,
	}

	scanResults, err := svc.Scan(ctx, imgScanInfo.Image, creds)
	if err != nil {
		logger.L().StopError(fmt.Sprintf("Failed to scan image: %s", imgScanInfo.Image))
		return nil, err
	}

	logger.L().StopSuccess(fmt.Sprintf("Successfully scanned image: %s", imgScanInfo.Image))

	scanInfo.SetScanType(cautils.ScanTypeImage)

	outputPrinters := GetOutputPrinters(scanInfo, ctx, "")

	uiPrinter := GetUIPrinter(ctx, scanInfo, "")

	resultsHandler := resultshandling.NewResultsHandler(nil, outputPrinters, uiPrinter)

	resultsHandler.ImageScanData = []cautils.ImageScanData{
		{
			PresenterConfig: scanResults,
			Image:           imgScanInfo.Image,
		},
	}

	return scanResults, resultsHandler.HandleResults(ctx)
}
