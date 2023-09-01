package core

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/anchore/grype/grype/presenter"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/go-logger/iconlogger"
	"github.com/kubescape/kubescape/v2/core/cautils"
	ksmetav1 "github.com/kubescape/kubescape/v2/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer"
	"github.com/kubescape/kubescape/v2/pkg/imagescan"

	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling"
	copa "github.com/project-copacetic/copacetic/pkg/patch"
	log "github.com/sirupsen/logrus"
)

func (ks *Kubescape) Patch(ctx context.Context, patchInfo *ksmetav1.PatchInfo) error {

	logger.InitLogger(iconlogger.LoggerName)
	// ===================== Scan the image =====================
	logger.L().Start(fmt.Sprintf("Scanning image: %s", patchInfo.Image))

	// Setup the scan service
	dbCfg, _ := imagescan.NewDefaultDBConfig()
	svc := imagescan.NewScanService(dbCfg)
	creds := imagescan.RegistryCredentials{
		Username: patchInfo.Username,
		Password: patchInfo.Password,
	}
	// Scan the image
	scanResults, err := svc.Scan(ctx, patchInfo.Image, creds)
	if err != nil {
		return err
	}
	// Save the scan results to a file in json format
	pres := presenter.GetPresenter("json", "", false, *scanResults)

	fileName := fmt.Sprintf("%s:%s.json", patchInfo.ImageName, patchInfo.ImageTag)
	fileName = strings.ReplaceAll(fileName, "/", "-")

	writer := printer.GetWriter(ctx, fileName)

	if err := pres.Present(writer); err != nil {
		return err
	}
	logger.L().StopSuccess(fmt.Sprintf("Successfully scanned image: %s", patchInfo.Image))

	// ===================== Patch the image using copacetic =====================
	logger.L().Start("Patching image...")

	sout, serr := os.Stdout, os.Stderr
	if logger.L().GetLevel() != "debug" {
		disableCopaLogger()
	}

	if err := copa.Patch(ctx, patchInfo.Timeout, patchInfo.BuildkitAddress, patchInfo.Image, fileName, patchInfo.PatchedImageTag, ""); err != nil {
		return err
	}

	if logger.L().GetLevel() != "debug" {
		enableCopaLogger(sout, serr)
	}

	patchedImageName := fmt.Sprintf("%s:%s", patchInfo.ImageName, patchInfo.PatchedImageTag)
	logger.L().StopSuccess(fmt.Sprintf("Patched image successfully. Loaded image: %s", patchedImageName))

	// ===================== Re-scan the image =====================

	logger.L().Start(fmt.Sprintf("Re-Scanning image: %s", patchedImageName))

	scanResultsPatched, err := svc.Scan(ctx, patchedImageName, creds)
	if err != nil {
		return err
	}
	logger.L().StopSuccess(fmt.Sprintf("Successfully re-scanned image: %s", patchedImageName))

	// ===================== Clean up =====================
	// Remove the scan results file, which was used to patch the image
	if err := os.Remove(fileName); err != nil {
		logger.L().Warning(fmt.Sprintf("failed to remove residual file: %v", fileName), helpers.Error(err))
	}

	// ===================== Results Handling =====================

	var scanInfo cautils.ScanInfo
	scanInfo.SetScanType(cautils.ScanTypeImage)
	outputPrinters := GetOutputPrinters(&scanInfo, ctx)
	uiPrinter := GetUIPrinter(ctx, &scanInfo)
	resultsHandler := resultshandling.NewResultsHandler(nil, outputPrinters, uiPrinter)
	resultsHandler.ImageScanData = []cautils.ImageScanData{
		{
			PresenterConfig: scanResultsPatched,
			Image:           patchedImageName,
		},
	}
	resultsHandler.HandleResults(ctx)

	return nil
}

func disableCopaLogger() {
	os.Stdout, os.Stderr = nil, nil
	null, _ := os.Open(os.DevNull)
	log.SetOutput(null)
}

func enableCopaLogger(sout, serr *os.File) {
	os.Stdout, os.Stderr = sout, serr
	log.SetOutput(os.Stdout)
}
