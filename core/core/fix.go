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
	helmSuggestions := handler.PrepareHelmSuggestions(ks.Context())

	if len(resourcesToFix) == 0 && len(helmSuggestions) == 0 {
		logger.L().Info(noResourcesToFix)
		return nil
	}

	// Helm guidance is print-only — applied to none of the apply/confirm
	// path below, since we do not auto-edit chart templates or values.yaml.
	handler.PrintHelmSuggestions(helmSuggestions)

	if len(resourcesToFix) == 0 {
		logger.L().Info(noResourcesToFix)
		// Even with nothing to auto-fix, surface controls that still need manual remediation.
		handler.PrintUnfixedControls(fixhandler.PhasePlanned)
		return nil
	}

	handler.PrintExpectedChanges(resourcesToFix)

	if fixInfo.DryRun {
		logger.L().Info(noChangesApplied)
		handler.PrintUnfixedControls(fixhandler.PhasePlanned)
		return nil
	}

	if !fixInfo.NoConfirm && !userConfirmed() {
		logger.L().Info(noChangesApplied)
		handler.PrintUnfixedControls(fixhandler.PhasePlanned)
		return nil
	}

	plannedFiles := make(map[string]bool, len(resourcesToFix))
	for _, r := range resourcesToFix {
		plannedFiles[r.FilePath] = true
	}
	plannedFilesCount := len(plannedFiles)

	updatedFilesCount, errors := handler.ApplyChanges(ks.Context(), resourcesToFix)
	plannedControls := handler.FixedControlsCount()
	totalFailed := plannedControls + len(handler.UnfixedControls())

	// "Auto-fixed" is only honest when every planned file actually wrote.
	// Otherwise (apply errors, partial writes) we report planning numbers and
	// flag the discrepancy.
	fullySucceeded := updatedFilesCount == plannedFilesCount && len(errors) == 0
	if fullySucceeded {
		logger.L().Info(fmt.Sprintf("Fixed %d of %d flagged control instances across %d file(s).",
			plannedControls, totalFailed, updatedFilesCount))
		handler.PrintUnfixedControls(fixhandler.PhaseApplied)
	} else {
		logger.L().Info(fmt.Sprintf(
			"Planned fixes for %d of %d flagged control instances across %d file(s); applied to %d file(s) — the remaining files errored, see warnings below.",
			plannedControls, totalFailed, plannedFilesCount, updatedFilesCount))
		handler.PrintUnfixedControls(fixhandler.PhasePlanned)
	}

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
