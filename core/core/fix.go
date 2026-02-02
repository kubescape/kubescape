package core

import (
	"fmt"
	"strings"

	"github.com/kubescape/go-logger"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v3/core/pkg/fixhandler"
)

const (
	noChangesApplied     = "No changes were applied."
	noResourcesToFix     = "No issues to fix."
	confirmationQuestion = "Would you like to apply the changes to the files above? [y|n]: "
)

func (ks *Kubescape) Fix(fixInfo *metav1.FixInfo) error {
	logger.L().Info("Reading report file...")
	handler, err := fixhandler.NewFixHandler(fixInfo)
	if err != nil {
		return err
	}

	resourcesToFix := handler.PrepareResourcesToFix(ks.Context())

	if len(resourcesToFix) == 0 {
		logger.L().Info(noResourcesToFix)
		return nil
	}

	handler.PrintExpectedChanges(resourcesToFix)

	if fixInfo.DryRun {
		logger.L().Info(noChangesApplied)
		return nil
	}

	if !fixInfo.NoConfirm && !userConfirmed() {
		logger.L().Info(noChangesApplied)
		return nil
	}

	updatedFilesCount, errors := handler.ApplyChanges(ks.Context(), resourcesToFix)
	logger.L().Info(fmt.Sprintf("Fixed resources in %d files.", updatedFilesCount))

	if len(errors) > 0 {
		for _, err := range errors {
			logger.L().Ctx(ks.Context()).Warning(err.Error())
		}
		return fmt.Errorf("failed to fix some resources, check the logs for more details")
	}

	return nil
}

func userConfirmed() bool {
	var input string

	for {
		fmt.Println(confirmationQuestion)
		if _, err := fmt.Scanln(&input); err != nil {
			continue
		}

		input = strings.ToLower(input)
		switch input {
		case "y", "yes":
			return true
		case "n", "no":
			return false
		}
	}
}
