package main

import (
	"fmt"
	"os"

	"github.com/armosec/kubescape/clihandler/cmd"
	pkgutils "github.com/armosec/utils-go/utils"
)

const SKIP_VERSION_CHECK = "KUBESCAPE_SKIP_UPDATE_CHECK"

func main() {
	CheckLatestVersion()
	cmd.Execute()
}

func CheckLatestVersion() {
	if v, ok := os.LookupEnv(SKIP_VERSION_CHECK); ok && pkgutils.StringToBool(v) {
		return
	}
	latest, err := cmd.GetLatestVersion()
	if err != nil || latest == "unknown" {
		return
	}
	if latest != cmd.BuildNumber {
		fmt.Println("Warning: You are not updated to the latest release: " + latest)
	}
}
