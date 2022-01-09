package clihandler

import (
	"fmt"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/getter"
)

var downloadFunc = map[string]func(*cautils.DownloadInfo) error{
	"controls-inputs": downloadConfigInputs,
	"exceptions":      downloadExceptions,
	"control":         downloadControl,
	"framework":       downloadFramework,
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
		if err := f(downloadInfo); err != nil {
			return err
		}
		fmt.Printf("'%s' downloaded successfully and saved at: '%s'\n", downloadInfo.Target, downloadInfo.Path)
		return nil
	}
	return fmt.Errorf("unknown command to download")
}

func downloadConfigInputs(downloadInfo *cautils.DownloadInfo) error {
	tenant := getTenantConfig(downloadInfo.Account, "", getKubernetesApi()) // change k8sinterface
	controlsInputsGetter := getConfigInputsGetter(downloadInfo.Name, tenant.GetCustomerGUID(), nil)
	controlInputs, err := controlsInputsGetter.GetControlsInputs(tenant.GetClusterName())
	if err != nil {
		return err
	}
	if downloadInfo.Path == "" {
		downloadInfo.Path = getter.GetDefaultPath(fmt.Sprintf("%s.json", downloadInfo.Target))
	}
	// save in file
	err = getter.SaveInFile(controlInputs, downloadInfo.Path)
	if err != nil {
		return err
	}
	return nil
}

func downloadExceptions(downloadInfo *cautils.DownloadInfo) error {
	tenant := getTenantConfig(downloadInfo.Account, "", getKubernetesApi()) // change k8sinterface
	exceptionsGetter := getExceptionsGetter("")
	exceptions, err := exceptionsGetter.GetExceptions(tenant.GetClusterName())
	if err != nil {
		return err
	}
	if downloadInfo.Path == "" {
		downloadInfo.Path = getter.GetDefaultPath(fmt.Sprintf("%s.json", downloadInfo.Target))
	}
	// save in file
	err = getter.SaveInFile(exceptions, downloadInfo.Path)
	if err != nil {
		return err
	}
	return nil
}

func downloadFramework(downloadInfo *cautils.DownloadInfo) error {
	tenant := getTenantConfig(downloadInfo.Account, "", getKubernetesApi()) // change k8sinterface
	g := getPolicyGetter(nil, tenant.GetCustomerGUID(), true, nil)

	if downloadInfo.Name == "" {
		// TODO - support
		return fmt.Errorf("missing framework name")
	}
	if downloadInfo.Path == "" {
		downloadInfo.Path = getter.GetDefaultPath(downloadInfo.Name + ".json")
	}
	frameworks, err := g.GetFramework(downloadInfo.Name)
	if err != nil {
		return err
	}
	err = getter.SaveInFile(frameworks, downloadInfo.Path)
	if err != nil {
		return err
	}
	return nil
}

func downloadControl(downloadInfo *cautils.DownloadInfo) error {
	tenant := getTenantConfig(downloadInfo.Account, "", getKubernetesApi()) // change k8sinterface
	g := getPolicyGetter(nil, tenant.GetCustomerGUID(), false, nil)

	if downloadInfo.Name == "" {
		// TODO - support
		return fmt.Errorf("missing control name")
	}
	if downloadInfo.Path == "" {
		downloadInfo.Path = getter.GetDefaultPath(downloadInfo.Name + ".json")
	}
	controls, err := g.GetControl(downloadInfo.Name)
	if err != nil {
		return err
	}
	err = getter.SaveInFile(controls, downloadInfo.Path)
	if err != nil {
		return err
	}
	return nil
}
