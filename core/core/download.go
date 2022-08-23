package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v2/core/cautils/getter"
	metav1 "github.com/kubescape/kubescape/v2/core/meta/datastructures/v1"
)

var downloadFunc = map[string]func(*metav1.DownloadInfo) error{
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

func (ks *Kubescape) Download(downloadInfo *metav1.DownloadInfo) error {
	setPathandFilename(downloadInfo)
	if err := os.MkdirAll(downloadInfo.Path, os.ModePerm); err != nil {
		return err
	}
	if err := downloadArtifact(downloadInfo, downloadFunc); err != nil {
		return err
	}
	return nil
}

func downloadArtifact(downloadInfo *metav1.DownloadInfo, downloadArtifactFunc map[string]func(*metav1.DownloadInfo) error) error {
	if f, ok := downloadArtifactFunc[downloadInfo.Target]; ok {
		if err := f(downloadInfo); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("unknown command to download")
}

func setPathandFilename(downloadInfo *metav1.DownloadInfo) {
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

func downloadArtifacts(downloadInfo *metav1.DownloadInfo) error {
	downloadInfo.FileName = ""
	var artifacts = map[string]func(*metav1.DownloadInfo) error{
		"controls-inputs": downloadConfigInputs,
		"exceptions":      downloadExceptions,
		"framework":       downloadFramework,
	}
	for artifact := range artifacts {
		if err := downloadArtifact(&metav1.DownloadInfo{Target: artifact, Path: downloadInfo.Path, FileName: fmt.Sprintf("%s.json", artifact)}, artifacts); err != nil {
			logger.L().Error("error downloading", helpers.String("artifact", artifact), helpers.Error(err))
		}
	}
	return nil
}

func downloadConfigInputs(downloadInfo *metav1.DownloadInfo) error {
	tenant := getTenantConfig(&downloadInfo.Credentials, "", getKubernetesApi())

	controlsInputsGetter := getConfigInputsGetter(downloadInfo.Name, tenant.GetAccountID(), nil)
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

func downloadExceptions(downloadInfo *metav1.DownloadInfo) error {
	var err error
	tenant := getTenantConfig(&downloadInfo.Credentials, "", getKubernetesApi())

	exceptionsGetter := getExceptionsGetter("")
	exceptions := []armotypes.PostureExceptionPolicy{}
	if tenant.GetAccountID() != "" {
		exceptions, err = exceptionsGetter.GetExceptions(tenant.GetContextName())
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

func downloadFramework(downloadInfo *metav1.DownloadInfo) error {

	tenant := getTenantConfig(&downloadInfo.Credentials, "", getKubernetesApi())

	g := getPolicyGetter(nil, tenant.GetTenantEmail(), true, nil)

	if downloadInfo.Name == "" {
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
			downloadInfo.FileName = fmt.Sprintf("%s.json", downloadInfo.Name)
		}
		framework, err := g.GetFramework(downloadInfo.Name)
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

func downloadControl(downloadInfo *metav1.DownloadInfo) error {

	tenant := getTenantConfig(&downloadInfo.Credentials, "", getKubernetesApi())

	g := getPolicyGetter(nil, tenant.GetTenantEmail(), false, nil)

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
	if controls == nil {
		return fmt.Errorf("failed to download control - received an empty objects")
	}
	downloadTo := filepath.Join(downloadInfo.Path, downloadInfo.FileName)
	err = getter.SaveInFile(controls, downloadTo)
	if err != nil {
		return err
	}
	logger.L().Success("Downloaded", helpers.String("artifact", downloadInfo.Target), helpers.String("name", downloadInfo.Name), helpers.String("path", downloadTo))
	return nil
}
