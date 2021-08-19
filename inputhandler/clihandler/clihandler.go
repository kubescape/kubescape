package clihandler

import (
	"fmt"
	"kube-escape/cautils"
	"kube-escape/policyhandler"
	"os"

	"kube-escape/cautils/armotypes"
	"kube-escape/cautils/opapolicy"
)

type CLIHandler struct {
	policyHandler *policyhandler.PolicyHandler
	flagHandler   FlagHandler
}

func NewCLIHandler(policyHandler *policyhandler.PolicyHandler) *CLIHandler {
	return &CLIHandler{
		flagHandler:   *NewFlagHandler(),
		policyHandler: policyHandler,
	}
}

func (clihandler *CLIHandler) Scan() error {
	clihandler.flagHandler.ParseFlag()
	if !clihandler.flagHandler.ExecuteScan() {
		os.Exit(0)
	}
	cautils.InfoDisplay(os.Stdout, "ARMO security scanner starting\n")

	policyNotification := &opapolicy.PolicyNotification{
		NotificationType: opapolicy.TypeExecPostureScan,
		Rules: []opapolicy.PolicyIdentifier{
			*clihandler.flagHandler.policyIdentifier,
		},
		Designators: armotypes.PortalDesignator{},
	}

	switch policyNotification.NotificationType {
	case opapolicy.TypeExecPostureScan:
		go func() {
			if err := clihandler.policyHandler.HandleNotificationRequest(policyNotification); err != nil {
				fmt.Printf("%v\n", err)
				os.Exit(0)
			}
		}()
	default:
		return fmt.Errorf("notification type '%s' Unknown", policyNotification.NotificationType)
	}
	return nil
}
