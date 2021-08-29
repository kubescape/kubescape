package clihandler

import (
	"flag"
	"fmt"
	"strings"

	"kubescape/cautils/opapolicy"
)

type FlagHandler struct {
	policyIdentifier *opapolicy.PolicyIdentifier
}

func NewFlagHandler() *FlagHandler {
	flag.Parse()
	return &FlagHandler{}
}

func (flagHandler *FlagHandler) ExecuteScan() bool {
	return flagHandler.policyIdentifier != nil
}

// SetupHTTPListener set up listening http servers
func (flagHandler *FlagHandler) ParseFlag() {
	f := "help"
	if len(flag.Args()) >= 1 {
		f = strings.ToLower(flag.Arg(0))
	}
	switch f {
	case "scan":
		flagHandler.Scan()
	case "version":
		flagHandler.Version()
	case "help":
		flagHandler.Help()
	default:
		fmt.Println("unknown input argument")
		flagHandler.Help()
	}
}

func (flagHandler *FlagHandler) Help() {
	fmt.Println("Run: kubescape scan framework nsa --exclude-namespaces kube-system,kube-public")
}

func (flagHandler *FlagHandler) Version() {
	fmt.Println("betav1")
}

func (flagHandler *FlagHandler) Scan() {
	f := "help"
	if len(flag.Args()) >= 2 {
		f = strings.ToLower(flag.Arg(1))
	}
	switch f {
	case "framework":
		flagHandler.ScanFramework()
	case "control":
		flagHandler.ScanControl()
	case "help":
		flagHandler.ScanHelp()
	default:
		fmt.Println("unknown input argument")
		flagHandler.ScanHelp()
	}
}
func (flagHandler *FlagHandler) ScanFramework() {
	frameworkName := strings.ToUpper(flag.Arg(2))
	// if cautils.StringInSlice(SupportedFrameworks(), frameworkName) == cautils.ValueNotFound {
	// 	fmt.Printf("framework %s not supported, supported frameworks: %v", frameworkName, SupportedFrameworks())
	// 	return
	// }
	flagHandler.policyIdentifier = &opapolicy.PolicyIdentifier{
		Kind: opapolicy.KindFramework,
		Name: frameworkName,
	}
}
func (flagHandler *FlagHandler) ScanControl() {
	flagHandler.policyIdentifier = &opapolicy.PolicyIdentifier{
		Kind: opapolicy.KindControl,
		Name: strings.ToUpper(flag.Arg(3)),
	}
}
func (flagHandler *FlagHandler) ScanHelp() {
	fmt.Println("")
}
func (flagHandler *FlagHandler) ScanFrameworkHelp() {
	fmt.Println("Run framework nsa or mitre")
}
func (flagHandler *FlagHandler) ScanControlHelp() {
	fmt.Println("not supported")
}

func SupportedFrameworks() []string {
	return []string{"nsa", "mitre"} // TODO - get from BE
}
