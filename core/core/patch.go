package core

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/anchore/grype/grype/presenter"
	"github.com/anchore/grype/grype/presenter/models"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v2/core/cautils"
	ksmetav1 "github.com/kubescape/kubescape/v2/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer"
	printerv2 "github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer/v2"
	"github.com/kubescape/kubescape/v2/pkg/imagescan"

	copa "github.com/project-copacetic/copacetic/pkg/patch"
)

func (ks *Kubescape) Patch(ctx context.Context, patchInfo *ksmetav1.PatchInfo) error {

	// ===================== Scan the image =====================
	logger.L().Info("Scanning image...")
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
	writer, err := os.OpenFile(fileName, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)
	if err != nil {
		return err
	}
	defer writer.Close()

	if err := pres.Present(writer); err != nil {
		return err
	}
	logger.L().Success("Scanned image successfully")

	// ===================== Patch the image using copacetic =====================
	logger.L().Info("Patching image...")
	if err := copa.Patch(ctx, patchInfo.Timeout, patchInfo.BuildkitAddress, patchInfo.Image, fileName, patchInfo.PatchedImageTag, ""); err != nil {
		return err
	}
	logger.L().Success("Patched image successfully")

	// ===================== Re-scan the image =====================
	logger.L().Info("Re-scanning image...")
	// Re-scan the image
	patchedImageName := fmt.Sprintf("%s:%s", patchInfo.ImageName, patchInfo.PatchedImageTag)

	scanResultsPatched, err := svc.Scan(ctx, patchedImageName, creds)
	if err != nil {
		return err
	}
	// Save the patched image's scan results to a file in json format, if requested
	fileNamePatched := fmt.Sprintf("%s:%s.json", patchInfo.ImageName, patchInfo.PatchedImageTag)
	fileNamePatched = strings.ReplaceAll(fileNamePatched, "/", "-")

	if patchInfo.IncludeReport {
		pres = presenter.GetPresenter("json", "", false, *scanResultsPatched)

		writer, err = os.OpenFile(fileNamePatched, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)
		if err != nil {
			return err
		}
		defer writer.Close()

		if err := pres.Present(writer); err != nil {
			return err
		}
	}
	logger.L().Success("Re-scanned image successfully")

	// ===================== Clean up =====================
	// Remove the scan results files, which were used to patch the image
	if !patchInfo.IncludeReport {
		if err := os.Remove(fileName); err != nil {
			logger.L().Warning(fmt.Sprintf("failed to remove residual file: %v", fileName), helpers.Error(err))
		}
	}

	// ===================== Results Handling =====================
	logger.L().Info("Preparing results ...")

	doc, err := models.NewDocument(scanResults.Packages, scanResults.Context, scanResults.Matches, scanResults.IgnoredMatches, scanResults.MetadataProvider, nil, scanResults.DBStatus)
	if err != nil {
		logger.L().Error(fmt.Sprintf("failed to create document for image: %v", patchInfo.Image), helpers.Error(err))
	}
	CVEs := printerv2.ExtractCVEs(doc.Matches)
	fixableCVEs := printerv2.ExtractFixableCVEs(doc.Matches)

	docPatched, err := models.NewDocument(scanResultsPatched.Packages, scanResultsPatched.Context, scanResultsPatched.Matches, scanResultsPatched.IgnoredMatches, scanResultsPatched.MetadataProvider, nil, scanResultsPatched.DBStatus)
	if err != nil {
		logger.L().Error(fmt.Sprintf("failed to create document for image: %v", patchedImageName), helpers.Error(err))
	}
	CVEsPatched := printerv2.ExtractCVEs(docPatched.Matches)
	fixableCVEsPatched := printerv2.ExtractFixableCVEs(docPatched.Matches)

	writer = printer.GetWriter(ctx, os.Stdout.Name())
	cautils.InfoTextDisplay(writer, "\nVulnerability summary: \n")

	cautils.SimpleDisplay(writer, "Image: %s\n", patchInfo.Image)
	cautils.SimpleDisplay(writer, "  * Total CVE's  : %v\n", len(CVEs))
	cautils.SimpleDisplay(writer, "  * Fixable CVE's: %v\n\n", len(fixableCVEs))

	cautils.SimpleDisplay(writer, "Image: %s\n", patchedImageName)
	cautils.SimpleDisplay(writer, "  * Total CVE's  : %v\n", len(CVEsPatched))
	cautils.SimpleDisplay(writer, "  * Fixable CVE's: %v\n\n", len(fixableCVEsPatched))

	if patchInfo.IncludeReport {
		logger.L().Success("Results saved", helpers.String("filename", fileName))
		logger.L().Success("Results saved", helpers.String("filename", fileNamePatched))
	}

	return nil

}
