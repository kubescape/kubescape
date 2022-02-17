package clihandler

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/getter"
	"github.com/armosec/kubescape/cautils/logger"
	"github.com/armosec/kubescape/cautils/logger/helpers"
)

var downloadFunc = map[string]func(*cautils.DownloadInfo) error{
	"controls-inputs": downloadConfigInputs,
	"exceptions":      downloadExceptions,
	"control":         downloadControl,
	"framework":       downloadFramework,
	"artifacts":       downloadArtifacts,
}

func DownloadSupportCommands() []string {
	commands := []string{}
	for k := range downloadFunc {
		commands = append(commands, k)
	}
	return commands
}

func CliDownload(downloadInfo *cautils.DownloadInfo) error {
	setPathandFilename(downloadInfo)
	if err := downloadArtifact(downloadInfo, downloadFunc); err != nil {
		return err
	}
	return nil
}

func downloadArtifact(downloadInfo *cautils.DownloadInfo, downloadArtifactFunc map[string]func(*cautils.DownloadInfo) error) error {
	if f, ok := downloadArtifactFunc[downloadInfo.Target]; ok {
		if err := f(downloadInfo); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("unknown command to download")
}

func setPathandFilename(downloadInfo *cautils.DownloadInfo) {
	if downloadInfo.Path == "" {
		downloadInfo.Path = getter.GetDefaultPath("")
	} else {
		dir, file := filepath.Split(downloadInfo.Path)
		if dir == "" {
			downloadInfo.Path = file
		} else if strings.Contains(file, ".json") {
			downloadInfo.Path = dir
			downloadInfo.FileName = file
		}
	}
}

func downloadArtifacts(downloadInfo *cautils.DownloadInfo) error {
	downloadInfo.FileName = ""
	var artifacts = map[string]func(*cautils.DownloadInfo) error{
		"controls-inputs": downloadConfigInputs,
		"exceptions":      downloadExceptions,
		"framework":       downloadFramework,
	}
	for artifact := range artifacts {
		if err := downloadArtifact(&cautils.DownloadInfo{Target: artifact, Path: downloadInfo.Path, FileName: fmt.Sprintf("%s.json", artifact)}, artifacts); err != nil {
			logger.L().Error("error downloading", helpers.String("artifact", artifact), helpers.Error(err))
		}
	}
	return nil
}

func downloadConfigInputs(downloadInfo *cautils.DownloadInfo) error {
	tenant := getTenantConfig(downloadInfo.Account, "", getKubernetesApi())

	controlsInputsGetter := getConfigInputsGetter(downloadInfo.Name, tenant.GetAccountID(), nil)
	controlInputs, err := controlsInputsGetter.GetControlsInputs(tenant.GetClusterName())
	if err != nil {
		return err
	}
	if downloadInfo.FileName == "" {
		downloadInfo.FileName = fmt.Sprintf("%s.json", downloadInfo.Target)
	}
	// save in file
	err = getter.SaveInFile(controlInputs, filepath.Join(downloadInfo.Path, downloadInfo.FileName))
	if err != nil {
		return err
	}
	logger.L().Success("Downloaded", helpers.String("artifact", downloadInfo.Target), helpers.String("path", filepath.Join(downloadInfo.Path, downloadInfo.FileName)))
	return nil
}

func downloadExceptions(downloadInfo *cautils.DownloadInfo) error {
	var err error
	tenant := getTenantConfig(downloadInfo.Account, "", getKubernetesApi())

	exceptionsGetter := getExceptionsGetter("")
	exceptions := []armotypes.PostureExceptionPolicy{}
	if tenant.GetAccountID() != "" {
		exceptions, err = exceptionsGetter.GetExceptions(tenant.GetClusterName())
		if err != nil {
			return err
		}
	}
	if downloadInfo.FileName == "" {
		downloadInfo.FileName = fmt.Sprintf("%s.json", downloadInfo.Target)
	}
	// save in file
	err = getter.SaveInFile(exceptions, filepath.Join(downloadInfo.Path, downloadInfo.FileName))
	if err != nil {
		return err
	}
	logger.L().Success("Downloaded", helpers.String("artifact", downloadInfo.Target), helpers.String("path", filepath.Join(downloadInfo.Path, downloadInfo.FileName)))
	return nil
}

func downloadFramework(downloadInfo *cautils.DownloadInfo) error {

	tenant := getTenantConfig(downloadInfo.Account, "", getKubernetesApi())

	g := getPolicyGetter(nil, tenant.GetAccountID(), true, nil)

	if downloadInfo.Name == "" {
		// if framework name not specified - download all frameworks
		frameworks, err := g.GetFrameworks()
		if err != nil {
			return err
		}
		for _, fw := range frameworks {
			err = getter.SaveInFile(fw, filepath.Join(downloadInfo.Path, (strings.ToLower(fw.Name)+".json")))
			if err != nil {
				return err
			}
			logger.L().Success("Downloaded", helpers.String("artifact", downloadInfo.Target), helpers.String("name", fw.Name), helpers.String("path", filepath.Join(downloadInfo.Path, downloadInfo.FileName)))
		}
		// return fmt.Errorf("missing framework name")
	} else {
		if downloadInfo.FileName == "" {
			downloadInfo.FileName = fmt.Sprintf("%s.json", downloadInfo.Name)
		}
		framework, err := g.GetFramework(downloadInfo.Name)
		if err != nil {
			return err
		}
		err = getter.SaveInFile(framework, filepath.Join(downloadInfo.Path, downloadInfo.FileName))
		if err != nil {
			return err
		}
		logger.L().Success("Downloaded", helpers.String("artifact", downloadInfo.Target), helpers.String("name", framework.Name), helpers.String("path", filepath.Join(downloadInfo.Path, downloadInfo.FileName)))
	}
	return nil
}

func downloadControl(downloadInfo *cautils.DownloadInfo) error {

	tenant := getTenantConfig(downloadInfo.Account, "", getKubernetesApi())

	g := getPolicyGetter(nil, tenant.GetAccountID(), false, nil)

	if downloadInfo.Name == "" {
		// TODO - support
		return fmt.Errorf("missing control name")
	}
	if downloadInfo.FileName == "" {
		downloadInfo.FileName = fmt.Sprintf("%s.json", downloadInfo.Name)
	}
	controls, err := g.GetControl(downloadInfo.Name)
	if err != nil {
		return err
	}
	err = getter.SaveInFile(controls, filepath.Join(downloadInfo.Path, downloadInfo.FileName))
	if err != nil {
		return err
	}
	logger.L().Success("Downloaded", helpers.String("artifact", downloadInfo.Target), helpers.String("name", downloadInfo.Name), helpers.String("path", filepath.Join(downloadInfo.Path, downloadInfo.FileName)))
	return nil
}
