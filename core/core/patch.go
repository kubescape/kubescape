package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/anchore/grype/grype/presenter"
	"github.com/anchore/grype/grype/presenter/models"
	copaGrype "github.com/anubhav06/copa-grype/grype"
	"github.com/containerd/platforms"
	"github.com/docker/buildx/build"
	"github.com/docker/cli/cli/config"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/cautils"
	ksmetav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
	"github.com/kubescape/kubescape/v3/pkg/imagescan"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/exporter/containerimage/exptypes"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/session/auth/authprovider"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/pkgmgr"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	"github.com/quay/claircore/osrelease"
	log "github.com/sirupsen/logrus"
)

const (
	copaProduct = "copa"
)

func (ks *Kubescape) Patch(patchInfo *ksmetav1.PatchInfo, scanInfo *cautils.ScanInfo) (*models.PresenterConfig, error) {

	// ===================== Scan the image =====================
	logger.L().Start(fmt.Sprintf("Scanning image: %s", patchInfo.Image))

	// Setup the scan service
	dbCfg, _ := imagescan.NewDefaultDBConfig()
	svc, err := imagescan.NewScanService(dbCfg)
	if err != nil {
		logger.L().StopError(fmt.Sprintf("Failed to initialize image scanner: %s", err))
		return nil, err
	}
	defer svc.Close()
	creds := imagescan.RegistryCredentials{
		Username: patchInfo.Username,
		Password: patchInfo.Password,
	}
	// Scan the image
	scanResults, err := svc.Scan(ks.Context(), patchInfo.Image, creds, nil, nil)
	if err != nil {
		return nil, err
	}

	// If the scan results ID is empty, set it to "grype"
	if scanResults.ID.Name == "" {
		scanResults.ID.Name = "grype"
	}
	// Save the scan results to a file in json format
	pres := presenter.GetPresenter("json", "", false, *scanResults)

	fileName := fmt.Sprintf("%s:%s.json", patchInfo.ImageName, patchInfo.ImageTag)
	fileName = strings.ReplaceAll(fileName, "/", "-")

	writer := printer.GetWriter(ks.Context(), fileName)

	if err = pres.Present(writer); err != nil {
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

	if err = copaPatch(ks.Context(), patchInfo.Timeout, patchInfo.BuildkitAddress, patchInfo.Image, fileName, patchedImageName, "", patchInfo.IgnoreError, patchInfo.BuildKitOpts); err != nil {
		return nil, err
	}

	// Restore the output streams
	os.Stdout, os.Stderr = sout, serr

	logger.L().StopSuccess(fmt.Sprintf("Patched image successfully. Loaded image: %s", patchedImageName))

	// ===================== Re-scan the image =====================

	logger.L().Start(fmt.Sprintf("Re-scanning image: %s", patchedImageName))

	scanResultsPatched, err := svc.Scan(ks.Context(), patchedImageName, creds, nil, nil)
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
	outputPrinters := GetOutputPrinters(scanInfo, ks.Context(), "")
	uiPrinter := GetUIPrinter(ks.Context(), scanInfo, "")
	resultsHandler := resultshandling.NewResultsHandler(nil, outputPrinters, uiPrinter)
	resultsHandler.ImageScanData = []cautils.ImageScanData{
		{
			PresenterConfig: scanResultsPatched,
			Image:           patchedImageName,
		},
	}

	return scanResultsPatched, resultsHandler.HandleResults(ks.Context(), scanInfo)
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
		if err := os.Chmod(workingFolder, 0o744); err != nil {
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

	var updates *unversioned.UpdateManifest
	// Parse report for update packages
	updates, err := tryParseScanReport(reportFile)
	if err != nil {
		return err
	}

	bkClient, err := buildkit.NewClient(ctx, bkOpts)
	if err != nil {
		return fmt.Errorf("copa: error creating buildkit client :: %w", err)
	}
	defer bkClient.Close()

	dockerConfig := config.LoadDefaultConfigFile(os.Stderr)
	cfg := authprovider.DockerAuthProviderConfig{ConfigFile: dockerConfig}
	attachable := []session.Attachable{authprovider.NewDockerAuthProvider(cfg)}
	solveOpt := client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type: client.ExporterImage,
				Attrs: map[string]string{
					"name": patchedImageName,
					"push": "true",
				},
			},
		},
		Frontend: "",         // i.e. we are passing in the llb.Definition directly
		Session:  attachable, // used for authprovider, sshagentprovider and secretprovider
	}
	solveOpt.SourcePolicy, err = build.ReadSourcePolicy()
	if err != nil {
		return fmt.Errorf("copa: error reading source policy :: %w", err)
	}

	buildChannel := make(chan *client.SolveStatus)
	_, err = bkClient.Build(ctx, solveOpt, copaProduct, func(ctx context.Context, c gwclient.Client) (*gwclient.Result, error) {
		// Configure buildctl/client for use by package manager
		config, err := buildkit.InitializeBuildkitConfig(ctx, c, image)
		if err != nil {
			return nil, fmt.Errorf("copa: error initializing buildkit config for image %s :: %w", image, err)
		}

		// Create package manager helper
		var manager pkgmgr.PackageManager
		if reportFile == "" {
			// determine OS family
			fileBytes, err := buildkit.ExtractFileFromState(ctx, c, &config.ImageState, "/etc/os-release")
			if err != nil {
				return nil, fmt.Errorf("unable to extract /etc/os-release file from state %w", err)
			}

			osType, err := getOSType(ctx, fileBytes)
			if err != nil {
				return nil, fmt.Errorf("copa: error getting os type :: %w", err)
			}

			osVersion, err := getOSVersion(ctx, fileBytes)
			if err != nil {
				return nil, fmt.Errorf("copa: error getting os version :: %w", err)
			}

			// get package manager based on os family type
			manager, err = pkgmgr.GetPackageManager(osType, osVersion, config, workingFolder)
			if err != nil {
				return nil, fmt.Errorf("copa: error getting package manager for ostype=%s, version=%s :: %w", osType, osVersion, err)
			}
			// do not specify updates, will update all
			updates = nil
		} else {
			// get package manager based on os family type
			manager, err = pkgmgr.GetPackageManager(updates.Metadata.OS.Type, updates.Metadata.OS.Version, config, workingFolder)
			if err != nil {
				return nil, fmt.Errorf("copa: error getting package manager by family type: ostype=%s, osversion=%s :: %w", updates.Metadata.OS.Type, updates.Metadata.OS.Version, err)
			}
		}

		// Export the patched image state to Docker
		// TODO: Add support for other output modes as buildctl does.
		log.Infof("Patching %d vulnerabilities", len(updates.Updates))
		patchedImageState, errPkgs, err := manager.InstallUpdates(ctx, updates, ignoreError)
		log.Infof("Error is: %v", err)
		if err != nil {
			return nil, nil
		}

		platform := platforms.Normalize(platforms.DefaultSpec())
		if platform.OS != "linux" {
			platform.OS = "linux"
		}

		def, err := patchedImageState.Marshal(ctx, llb.Platform(platform))
		if err != nil {
			return nil, err
		}

		res, err := c.Solve(ctx, gwclient.SolveRequest{
			Definition: def.ToPB(),
			Evaluate:   true,
		})
		if err != nil {
			return nil, err
		}

		res.AddMeta(exptypes.ExporterImageConfigKey, config.ConfigData)

		// Currently can only validate updates if updating via scanner
		if reportFile != "" {
			// create a new manifest with the successfully patched packages
			validatedManifest := &unversioned.UpdateManifest{
				Metadata: unversioned.Metadata{
					OS: unversioned.OS{
						Type:    updates.Metadata.OS.Type,
						Version: updates.Metadata.OS.Version,
					},
					Config: unversioned.Config{
						Arch: updates.Metadata.Config.Arch,
					},
				},
				Updates: []unversioned.UpdatePackage{},
			}
			for _, update := range updates.Updates {
				if !slices.Contains(errPkgs, update.Name) {
					validatedManifest.Updates = append(validatedManifest.Updates, update)
				}
			}
		}
		return res, nil
	}, buildChannel)

	return nil
}

func getOSType(ctx context.Context, osreleaseBytes []byte) (string, error) {
	r := bytes.NewReader(osreleaseBytes)
	osData, err := osrelease.Parse(ctx, r)
	if err != nil {
		return "", fmt.Errorf("unable to parse os-release data %w", err)
	}

	osType := strings.ToLower(osData["NAME"])
	switch {
	case strings.Contains(osType, "alpine"):
		return "alpine", nil
	case strings.Contains(osType, "debian"):
		return "debian", nil
	case strings.Contains(osType, "ubuntu"):
		return "ubuntu", nil
	case strings.Contains(osType, "amazon"):
		return "amazon", nil
	case strings.Contains(osType, "centos"):
		return "centos", nil
	case strings.Contains(osType, "mariner"):
		return "cbl-mariner", nil
	case strings.Contains(osType, "azure linux"):
		return "azurelinux", nil
	case strings.Contains(osType, "red hat"):
		return "redhat", nil
	case strings.Contains(osType, "rocky"):
		return "rocky", nil
	case strings.Contains(osType, "oracle"):
		return "oracle", nil
	case strings.Contains(osType, "alma"):
		return "alma", nil
	default:
		log.Error("unsupported osType ", osType)
		return "", errors.ErrUnsupported
	}
}

func getOSVersion(ctx context.Context, osreleaseBytes []byte) (string, error) {
	r := bytes.NewReader(osreleaseBytes)
	osData, err := osrelease.Parse(ctx, r)
	if err != nil {
		return "", fmt.Errorf("unable to parse os-release data %w", err)
	}

	return osData["VERSION_ID"], nil
}

// This function adds support to copa for patching Kubescape produced results
func tryParseScanReport(file string) (*unversioned.UpdateManifest, error) {

	parser := copaGrype.GrypeParser{}
	manifest, err := parser.Parse(file)
	if err != nil {
		return nil, err
	}

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

	return &um, nil
}
