package core

import (
	"fmt"
	"strings"

	logger "github.com/kubescape/go-logger"
	metav1 "github.com/kubescape/kubescape/v2/core/meta/datastructures/v1"

	"github.com/kubescape/kubescape/v2/core/pkg/fixhandler"
)

const NoChangesApplied = "No changes were applied."
const NoResourcesToFix = "No issues to fix."
const ConfirmationQuestion = "Would you like to apply the changes to the files above? [y|n]: "

func (ks *Kubescape) Fix(fixInfo *metav1.FixInfo) error {
	logger.L().Info("Reading report file...")
	handler, err := fixhandler.NewFixHandler(fixInfo)
	if err != nil {
		return err
	}

	resourcesToFix := handler.PrepareResourcesToFix()

	if len(resourcesToFix) == 0 {
		logger.L().Info(NoResourcesToFix)
		return nil
	}

	handler.PrintExpectedChanges(resourcesToFix)

	if fixInfo.DryRun {
		logger.L().Info(NoChangesApplied)
		return nil
	}

	if !fixInfo.NoConfirm && !userConfirmed() {
		logger.L().Info(NoChangesApplied)
		return nil
	}

	updatedFilesCount, errors := handler.ApplyChanges(resourcesToFix)
	logger.L().Info(fmt.Sprintf("Fixed resources in %d files.", updatedFilesCount))

	if len(errors) > 0 {
		for _, err := range errors {
			logger.L().Error(err.Error())
		}
		return fmt.Errorf("Failed to fix some resources, check the logs for more details")
	}

	return nil
}

func userConfirmed() bool {
	var input string

	for {
		fmt.Printf(ConfirmationQuestion)
		if _, err := fmt.Scanln(&input); err != nil {
			continue
		}

		input = strings.ToLower(input)
		if input == "y" || input == "yes" {
			return true
		} else if input == "n" || input == "no" {
			return false
		}
	}
}
