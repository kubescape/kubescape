package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/armosec/kubescape/cmd"
)

func main() {
	CheckLatestVersion()
	flag.Parse()
	cmd.InitArmoBEConnector()
	cmd.Execute()
}

func CheckLatestVersion() {
	latest, err := cmd.GetLatestVersion()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
	} else if latest != cmd.BuildNumber {
		fmt.Println("Warning: You are not updated to the latest release: " + latest)
	}

}
