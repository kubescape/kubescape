package main

import (
	"fmt"

	"github.com/armosec/kubescape/cmd"
)

var (
	sha1ver   string
	buildTime string
)

func main() {
	fmt.Println(sha1ver)
	fmt.Println(buildTime)
	cmd.Execute()
}
