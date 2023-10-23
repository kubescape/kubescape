package core

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/anchore/grype/grype/presenter"
	"github.com/anchore/grype/grype/presenter/models"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"

	"github.com/kubescape/kubescape/v3/core/cautils"
	ksmetav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
	"github.com/kubescape/kubescape/v3/pkg/imagescan"

	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling"
	log "github.com/sirupsen/logrus"

	copaGrype "github.com/anubhav06/copa-grype/grype"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/pkgmgr"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
)

func (ks *Kubescape) Patch(ctx context.Context, patchInfo *ksmetav1.PatchInfo, scanInfo *cautils.ScanInfo) (*models.PresenterConfig, error) {

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
		return nil, err
	}
	// Save the scan results to a file in json format
	pres := presenter.GetPresenter("json", "", false, *scanResults)

	fileName := fmt.Sprintf("%s:%s.json", patchInfo.ImageName, patchInfo.ImageTag)
	fileName = strings.ReplaceAll(fileName, "/", "-")

	writer := printer.GetWriter(ctx, fileName)

	if err := pres.Present(writer); err != nil {
		return nil, err
	}
	logger.L().StopSuccess(fmt.Sprintf("Successfully scanned image: %s", patchInfo.Image))

	// ===================== Patch the image using copacetic =====================
	logger.L().Start("Patching image...")
	patchedImageName := fmt.Sprintf("%s:%s", patchInfo.ImageName, patchInfo.PatchedImageTag)

	sout, serr := os.Stdout, os.Stderr
	if logger.L().GetLevel() != "debug" {
		disableCopaLogger()
	}

	if err := copaPatch(ctx, patchInfo.Timeout, patchInfo.BuildkitAddress, patchInfo.Image, fileName, patchedImageName, "", patchInfo.IgnoreError, patchInfo.BuildKitOpts); err != nil {
		return nil, err
	}

	// Restore the output streams
	os.Stdout, os.Stderr = sout, serr

	logger.L().StopSuccess(fmt.Sprintf("Patched image successfully. Loaded image: %s", patchedImageName))

	// ===================== Re-scan the image =====================

	logger.L().Start(fmt.Sprintf("Re-scanning image: %s", patchedImageName))

	scanResultsPatched, err := svc.Scan(ctx, patchedImageName, creds)
	if err != nil {
		return nil, err
	}
	logger.L().StopSuccess(fmt.Sprintf("Successfully re-scanned image: %s", patchedImageName))

	// ===================== Clean up =====================
	// Remove the scan results file, which was used to patch the image
	if err := os.Remove(fileName); err != nil {
		logger.L().Warning(fmt.Sprintf("failed to remove residual file: %v", fileName), helpers.Error(err))
	}

	// ===================== Results Handling =====================

	scanInfo.SetScanType(cautils.ScanTypeImage)
	outputPrinters := GetOutputPrinters(scanInfo, ctx, "")
	uiPrinter := GetUIPrinter(ctx, scanInfo, "")
	resultsHandler := resultshandling.NewResultsHandler(nil, outputPrinters, uiPrinter)
	resultsHandler.ImageScanData = []cautils.ImageScanData{
		{
			PresenterConfig: scanResultsPatched,
			Image:           patchedImageName,
		},
	}

	return scanResultsPatched, resultsHandler.HandleResults(ctx)
}

func disableCopaLogger() {
	os.Stdout, os.Stderr = nil, nil
	null, _ := os.Open(os.DevNull)
	log.SetOutput(null)
}

// copaPatch is a slightly modified copy of the Patch function from the original "project-copacetic/copacetic" repo
// https://github.com/project-copacetic/copacetic/blob/main/pkg/patch/patch.go
func copaPatch(ctx context.Context, timeout time.Duration, buildkitAddr, image, reportFile, patchedImageName, workingFolder string, ignoreError bool, bkOpts buildkit.Opts) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ch := make(chan error)
	go func() {
		ch <- patchWithContext(timeoutCtx, buildkitAddr, image, reportFile, patchedImageName, workingFolder, ignoreError, bkOpts)
	}()

	select {
	case err := <-ch:
		return err
	case <-timeoutCtx.Done():
		// add a grace period for long running deferred cleanup functions to complete
		<-time.After(1 * time.Second)

		err := fmt.Errorf("patch exceeded timeout %v", timeout)
		log.Error(err)
		return err
	}
}

func patchWithContext(ctx context.Context, buildkitAddr, image, reportFile, patchedImageName, workingFolder string, ignoreError bool, bkOpts buildkit.Opts) error {
	// Ensure working folder exists for call to InstallUpdates
	if workingFolder == "" {
		var err error
		workingFolder, err = os.MkdirTemp("", "copa-*")
		if err != nil {
			return err
		}
		defer os.RemoveAll(workingFolder)
		if err = os.Chmod(workingFolder, 0o744); err != nil {
			return err
		}
	} else {
		if isNew, err := utils.EnsurePath(workingFolder, 0o744); err != nil {
			log.Errorf("failed to create workingFolder %s", workingFolder)
			return err
		} else if isNew {
			defer os.RemoveAll(workingFolder)
		}
	}

	// Parse report for update packages
	updates, err := tryParseScanReport(reportFile)
	if err != nil {
		return err
	}

	client, err := buildkit.NewClient(ctx, bkOpts)
	if err != nil {
		return err
	}
	defer client.Close()

	// Configure buildctl/client for use by package manager
	config, err := buildkit.InitializeBuildkitConfig(ctx, client, image, updates)
	if err != nil {
		return err
	}

	// Create package manager helper
	pkgmgr, err := pkgmgr.GetPackageManager(updates.Metadata.OS.Type, config, workingFolder)
	if err != nil {
		return err
	}

	// Export the patched image state to Docker
	patchedImageState, _, err := pkgmgr.InstallUpdates(ctx, updates, ignoreError)
	if err != nil {
		return err
	}

	if err = buildkit.SolveToDocker(ctx, config.Client, patchedImageState, config.ConfigData, patchedImageName); err != nil {
		return err
	}

	return nil
}

// This function adds support to copa for patching Kubescape produced results
func tryParseScanReport(file string) (*unversioned.UpdateManifest, error) {

	parser := copaGrype.GrypeParser{}
	manifest, err := parser.Parse(file)

	// Convert from v1alpha1 to unversioned.UpdateManifest
	var um unversioned.UpdateManifest
	um.Metadata.OS.Type = manifest.Metadata.OS.Type
	um.Metadata.OS.Version = manifest.Metadata.OS.Version
	um.Metadata.Config.Arch = manifest.Metadata.Config.Arch
	um.Updates = make([]unversioned.UpdatePackage, len(manifest.Updates))
	for i, update := range manifest.Updates {
		um.Updates[i].Name = update.Name
		um.Updates[i].InstalledVersion = update.InstalledVersion
		um.Updates[i].FixedVersion = update.FixedVersion
		um.Updates[i].VulnerabilityID = update.VulnerabilityID
	}

	if err == nil {
		return &um, nil
	}

	return nil, err
}
