package clihandler

import (
	"fmt"
	"strings"

	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/getter"
)

var downloadInfo cautils.DownloadInfo

func CliDownload(args []string) error {
	switch strings.ToLower(args[0]) {
	case "framework":
		return downloadFramework(args[1])
	case "control":
		return downloadControl(args[1])
	case "exceptions":
		return downloadExceptions(args[1])
	case "configinputs":
		return downloadConfigInputs(args[1])
	// case "artifacts":
	default:
		return fmt.Errorf("unknown command to download")
	}
}

func downloadConfigInputs(controlsInputs string) error {
	tenant := getTenantConfig("", &k8sinterface.KubernetesApi{}) // change k8sinterface
	downloadReleasedPolicy := getter.NewDownloadReleasedPolicy() // download config inputs from github release
	controlsInputsGetter := getConfigInputsGetter(controlsInputs, tenant.GetCustomerGUID(), downloadReleasedPolicy)
	controlInputs, err := controlsInputsGetter.GetControlsInputs(tenant.GetCustomerGUID(), tenant.GetClusterName())
	if err != nil {
		return err
	}
	// save in file
	return nil
}

func downloadExceptions(frameworkName string) error {
	return nil
}

func downloadFramework(frameworkName string) error {
	downloadInfo.FrameworkName = strings.ToLower(frameworkName)
	g := getter.NewDownloadReleasedPolicy()
	if err := g.SetRegoObjects(); err != nil {
		return err
	}

	if downloadInfo.Path == "" {
		downloadInfo.Path = getter.GetDefaultPath(downloadInfo.FrameworkName + ".json")
	}
	frameworks, err := g.GetFramework(downloadInfo.FrameworkName)
	if err != nil {
		return err
	}
	err = getter.SaveFrameworkInFile(frameworks, downloadInfo.Path)
	if err != nil {
		return err
	}
	return nil
}

func downloadControl(controlName string) error {
	downloadInfo.ControlName = strings.ToLower(controlName)
	g := getter.NewDownloadReleasedPolicy()
	if err := g.SetRegoObjects(); err != nil {
		return err
	}
	if downloadInfo.Path == "" {
		downloadInfo.Path = getter.GetDefaultPath(downloadInfo.ControlName + ".json")
	}
	controls, err := g.GetControl(downloadInfo.ControlName)
	if err != nil {
		return err
	}
	err = getter.SaveControlInFile(controls, downloadInfo.Path)
	if err != nil {
		return err
	}
	return nil
}
