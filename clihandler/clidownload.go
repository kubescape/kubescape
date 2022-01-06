package clihandler

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/getter"
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
	if f, ok := downloadFunc[downloadInfo.Target]; ok {
		setPathandFilename(downloadInfo)
		if err := f(downloadInfo); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Printf("'%s' downloaded successfully and saved at: '%s/%s'\n", downloadInfo.Target, downloadInfo.Path, downloadInfo.FileName)
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
		} else {
			downloadInfo.Path = dir
			downloadInfo.FileName = file
		}
	}
}

func downloadArtifacts(downloadInfo *cautils.DownloadInfo) error {
	if err := downloadFramework(downloadInfo); err != nil {
		return err
	}
	if err := downloadConfigInputs(downloadInfo); err != nil {
		return err
	}
	if err := downloadExceptions(downloadInfo); err != nil {
		return err
	}
	return nil
}

func downloadConfigInputs(downloadInfo *cautils.DownloadInfo) error {
	tenant := getTenantConfig(downloadInfo.Account, getKubernetesApi())
	controlsInputsGetter := getConfigInputsGetter(downloadInfo.Name, tenant.GetCustomerGUID(), nil)
	controlInputs, err := controlsInputsGetter.GetControlsInputs(tenant.GetClusterName())
	if err != nil {
		return err
	}
	filename := downloadInfo.FileName
	if filename == "" {
		filename = fmt.Sprintf("%s.json", "controls-inputs")
	}
	// save in file
	err = getter.SaveInFile(controlInputs, filepath.Join(downloadInfo.Path, filename))
	if err != nil {
		return err
	}
	return nil
}

func downloadExceptions(downloadInfo *cautils.DownloadInfo) error {
	var err error
	tenant := getTenantConfig(downloadInfo.Account, getKubernetesApi())
	exceptionsGetter := getExceptionsGetter("")
	exceptions := []armotypes.PostureExceptionPolicy{}
	if tenant.GetCustomerGUID() != "" {
		exceptions, err = exceptionsGetter.GetExceptions(tenant.GetClusterName())
		if err != nil {
			return err
		}
	}
	filename := downloadInfo.FileName
	if filename == "" {
		filename = fmt.Sprintf("%s.json", "exceptions")
	}
	// save in file
	err = getter.SaveInFile(exceptions, filepath.Join(downloadInfo.Path, filename))
	if err != nil {
		return err
	}
	return nil
}

func downloadFramework(downloadInfo *cautils.DownloadInfo) error {
	tenant := getTenantConfig(downloadInfo.Account, getKubernetesApi())
	g := getPolicyGetter(nil, tenant.GetCustomerGUID(), true, nil)

	if downloadInfo.Name == "" {
		// if framework name not specified - download all frameworks
		frameworks, err := g.GetFrameworks()
		if err != nil {
			return err
		}
		for _, fw := range frameworks {
			err = getter.SaveInFile(fw, getter.GetDefaultPath(strings.ToLower(fw.Name)+".json"))
			if err != nil {
				return err
			}
		}
		// return fmt.Errorf("missing framework name")
	} else {
		filename := downloadInfo.FileName
		if filename == "" {
			filename = fmt.Sprintf("%s.json", "controls-inputs")
		}
		framework, err := g.GetFramework(downloadInfo.Name)
		if err != nil {
			return err
		}
		err = getter.SaveInFile(framework, filepath.Join(downloadInfo.Path, filename))
		if err != nil {
			return err
		}
	}
	return nil
}

func downloadControl(downloadInfo *cautils.DownloadInfo) error {
	tenant := getTenantConfig(downloadInfo.Account, getKubernetesApi())
	g := getPolicyGetter(nil, tenant.GetCustomerGUID(), true, nil)

	if downloadInfo.Name == "" {
		// TODO - support
		return fmt.Errorf("missing control name")
	}
	filename := downloadInfo.FileName
	if filename == "" {
		filename = fmt.Sprintf("%s.json", "controls-inputs")
	}
	controls, err := g.GetControl(downloadInfo.Name)
	if err != nil {
		return err
	}
	err = getter.SaveInFile(controls, filepath.Join(downloadInfo.Path, filename))
	if err != nil {
		return err
	}
	return nil
}
