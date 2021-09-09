package main

import (
	"fmt"

	"github.com/armosec/kubescape/cmd"
)

func main() {
	CheckLatestVersion()
	cmd.Execute()
}

func CheckLatestVersion() {
	latest, _ := cmd.GetLatestVersion()
	if latest != cmd.BuildNumber {
		fmt.Println("Warning: You are not updated to the latest release: " + latest)
	}

}
