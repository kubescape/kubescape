package core

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
)

const (
	TargetControlsInputs = "controls-inputs"
	TargetExceptions     = "exceptions"
	TargetControl        = "control"
	TargetFramework      = "framework"
	TargetArtifacts      = "artifacts"
	TargetAttackTracks   = "attack-tracks"
)

var downloadFunc = map[string]func(context.Context, *metav1.DownloadInfo) error{
	TargetControlsInputs: downloadConfigInputs,
	TargetExceptions:     downloadExceptions,
	TargetControl:        downloadControl,
	TargetFramework:      downloadFramework,
	TargetArtifacts:      downloadArtifacts,
	TargetAttackTracks:   downloadAttackTracks,
}

func DownloadSupportCommands() []string {
	commands := []string{}
	for key := range downloadFunc {
		commands = append(commands, key)
	}

	// Sort the keys of the map
	sort.Strings(commands)
	return commands
}

func (ks *Kubescape) Download(ctx context.Context, downloadInfo *metav1.DownloadInfo) error {
	setPathAndFilename(downloadInfo)
	if err := os.MkdirAll(downloadInfo.Path, os.ModePerm); err != nil {
		return err
	}
	if err := downloadArtifact(ctx, downloadInfo, downloadFunc); err != nil {
		return err
	}
	return nil
}

func downloadArtifact(ctx context.Context, downloadInfo *metav1.DownloadInfo, downloadArtifactFunc map[string]func(context.Context, *metav1.DownloadInfo) error) error {
	if f, ok := downloadArtifactFunc[downloadInfo.Target]; ok {
		if err := f(ctx, downloadInfo); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("unknown command to download")
}

func setPathAndFilename(downloadInfo *metav1.DownloadInfo) {
	if downloadInfo.Path == "" {
		downloadInfo.Path = getter.GetDefaultPath("")
		return
	}
	dir, file := filepath.Split(downloadInfo.Path)
	if dir == "" {
		downloadInfo.Path = file
		return
	}
	if strings.Contains(file, ".json") {
		downloadInfo.Path = filepath.Clean(dir)
		downloadInfo.FileName = file
	}
}

func downloadArtifacts(ctx context.Context, downloadInfo *metav1.DownloadInfo) error {
	downloadInfo.FileName = ""
	var artifacts = map[string]func(context.Context, *metav1.DownloadInfo) error{
		"controls-inputs": downloadConfigInputs,
		"exceptions":      downloadExceptions,
		"framework":       downloadFramework,
		"attack-tracks":   downloadAttackTracks,
	}
	for artifact := range artifacts {
		if err := downloadArtifact(ctx, &metav1.DownloadInfo{Target: artifact, Path: downloadInfo.Path, FileName: fmt.Sprintf("%s.json", artifact)}, artifacts); err != nil {
			logger.L().Ctx(ctx).Warning("error downloading", helpers.String("artifact", artifact), helpers.Error(err))
		}
	}
	return nil
}

func downloadConfigInputs(ctx context.Context, downloadInfo *metav1.DownloadInfo) error {
	tenant := cautils.GetTenantConfig(downloadInfo.AccountID, downloadInfo.AccessKey, "", "", getKubernetesApi())

	controlsInputsGetter := getConfigInputsGetter(ctx, downloadInfo.Identifier, tenant.GetAccountID(), nil)
	controlInputs, err := controlsInputsGetter.GetControlsInputs(tenant.GetContextName())
	if err != nil {
		return err
	}
	if downloadInfo.FileName == "" {
		downloadInfo.FileName = fmt.Sprintf("%s.json", downloadInfo.Target)
	}
	if controlInputs == nil {
		return fmt.Errorf("failed to download controlInputs - received an empty objects")
	}
	// save in file
	err = getter.SaveInFile(controlInputs, filepath.Join(downloadInfo.Path, downloadInfo.FileName))
	if err != nil {
		return err
	}
	logger.L().Success("Downloaded", helpers.String("artifact", downloadInfo.Target), helpers.String("path", filepath.Join(downloadInfo.Path, downloadInfo.FileName)))
	return nil
}

func downloadExceptions(ctx context.Context, downloadInfo *metav1.DownloadInfo) error {
	tenant := cautils.GetTenantConfig(downloadInfo.AccountID, downloadInfo.AccessKey, "", "", getKubernetesApi())
	exceptionsGetter := getExceptionsGetter(ctx, "", tenant.GetAccountID(), nil)

	exceptions, err := exceptionsGetter.GetExceptions(tenant.GetContextName())
	if err != nil {
		return err
	}

	if downloadInfo.FileName == "" {
		downloadInfo.FileName = fmt.Sprintf("%s.json", downloadInfo.Target)
	}
	// save in file
	err = getter.SaveInFile(exceptions, filepath.Join(downloadInfo.Path, downloadInfo.FileName))
	if err != nil {
		return err
	}
	logger.L().Ctx(ctx).Success("Downloaded", helpers.String("artifact", downloadInfo.Target), helpers.String("path", filepath.Join(downloadInfo.Path, downloadInfo.FileName)))
	return nil
}

func downloadAttackTracks(ctx context.Context, downloadInfo *metav1.DownloadInfo) error {
	var err error
	tenant := cautils.GetTenantConfig(downloadInfo.AccountID, downloadInfo.AccessKey, "", "", getKubernetesApi())

	attackTracksGetter := getAttackTracksGetter(ctx, "", tenant.GetAccountID(), nil)

	attackTracks, err := attackTracksGetter.GetAttackTracks()
	if err != nil {
		return err
	}

	if downloadInfo.FileName == "" {
		downloadInfo.FileName = fmt.Sprintf("%s.json", downloadInfo.Target)
	}
	// save in file
	err = getter.SaveInFile(attackTracks, filepath.Join(downloadInfo.Path, downloadInfo.FileName))
	if err != nil {
		return err
	}
	logger.L().Success("Downloaded", helpers.String("attack tracks", downloadInfo.Target), helpers.String("path", filepath.Join(downloadInfo.Path, downloadInfo.FileName)))
	return nil

}

func downloadFramework(ctx context.Context, downloadInfo *metav1.DownloadInfo) error {

	tenant := cautils.GetTenantConfig(downloadInfo.AccountID, downloadInfo.AccessKey, "", "", getKubernetesApi())

	g := getPolicyGetter(ctx, nil, tenant.GetAccountID(), true, nil)

	if downloadInfo.Identifier == "" {
		// if framework name not specified - download all frameworks
		frameworks, err := g.GetFrameworks()
		if err != nil {
			return err
		}
		for _, fw := range frameworks {
			downloadTo := filepath.Join(downloadInfo.Path, (strings.ToLower(fw.Name) + ".json"))
			err = getter.SaveInFile(fw, downloadTo)
			if err != nil {
				return err
			}
			logger.L().Success("Downloaded", helpers.String("artifact", downloadInfo.Target), helpers.String("name", fw.Name), helpers.String("path", downloadTo))
		}
		// return fmt.Errorf("missing framework name")
	} else {
		if downloadInfo.FileName == "" {
			downloadInfo.FileName = fmt.Sprintf("%s.json", downloadInfo.Identifier)
		}
		framework, err := g.GetFramework(downloadInfo.Identifier)
		if err != nil {
			return err
		}
		if framework == nil {
			return fmt.Errorf("failed to download framework - received an empty objects")
		}
		downloadTo := filepath.Join(downloadInfo.Path, downloadInfo.FileName)
		err = getter.SaveInFile(framework, downloadTo)
		if err != nil {
			return err
		}
		logger.L().Success("Downloaded", helpers.String("artifact", downloadInfo.Target), helpers.String("name", framework.Name), helpers.String("path", downloadTo))
	}
	return nil
}

func downloadControl(ctx context.Context, downloadInfo *metav1.DownloadInfo) error {

	tenant := cautils.GetTenantConfig(downloadInfo.AccountID, downloadInfo.AccessKey, "", "", getKubernetesApi())

	g := getPolicyGetter(ctx, nil, tenant.GetAccountID(), false, nil)

	if downloadInfo.Identifier == "" {
		// TODO - support
		return fmt.Errorf("missing control ID")
	}
	if downloadInfo.FileName == "" {
		downloadInfo.FileName = fmt.Sprintf("%s.json", downloadInfo.Identifier)
	}
	controls, err := g.GetControl(downloadInfo.Identifier)
	if err != nil {
		return fmt.Errorf("failed to download control id '%s',  %s", downloadInfo.Identifier, err.Error())
	}
	if controls == nil {
		return fmt.Errorf("failed to download control id '%s' - received an empty objects", downloadInfo.Identifier)
	}
	downloadTo := filepath.Join(downloadInfo.Path, downloadInfo.FileName)
	err = getter.SaveInFile(controls, downloadTo)
	if err != nil {
		return err
	}
	logger.L().Success("Downloaded", helpers.String("artifact", downloadInfo.Target), helpers.String("ID", downloadInfo.Identifier), helpers.String("path", downloadTo))
	return nil
}
