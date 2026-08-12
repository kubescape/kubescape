package core

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v3/core/pkg/fixhandler"
	"github.com/mattn/go-isatty"
)

const (
	noChangesApplied     = "No changes were applied."
	noResourcesToFix     = "No issues to fix."
	confirmationQuestion = "Would you like to apply the changes to the files above? [y|n]: "

	// maxConfirmRetries bounds retries on a read error we don't recognize as
	// permanent, so any stdin state the isTerminal check doesn't catch still
	// can't turn into the unbounded hot loop from #2711.
	maxConfirmRetries = 100

	nonInteractiveWarning = "stdin is not interactive; treating the fix confirmation as declined and applying no changes (pass --no-confirm to apply without a prompt)"
	stdinClosedWarning    = "stdin was closed before a confirmation was given; treating the fix confirmation as declined and applying no changes (pass --no-confirm to apply without a prompt)"
)

// isTerminal and isCygwinTerminal are vars (not direct isatty calls) so tests
// can stub them. Both must be checked: on Windows under mintty (Git Bash,
// MSYS2), stdin is a named pipe rather than a console, so IsTerminal alone
// returns false for a real interactive session — IsCygwinTerminal is the
// isatty-recommended way to detect that case.
var (
	isTerminal       = isatty.IsTerminal
	isCygwinTerminal = isatty.IsCygwinTerminal
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
			logger.L().Ctx(ks.Context()).Warning("failed to fix resource", helpers.Error(err))
		}
		return fmt.Errorf("failed to fix some resources, check the logs for more details")
	}

	return nil
}

func userConfirmed() bool {
	fd := os.Stdin.Fd()
	if !isTerminal(fd) && !isCygwinTerminal(fd) {
		// Non-interactive stdin (closed, /dev/null, a redirected file, a pipe
		// whose reads fail outright, ...) will never produce an answer: no
		// amount of retrying fmt.Scanln fixes that. Treat it as a decline up
		// front instead of ever entering the retry loop.
		logger.L().Warning(nonInteractiveWarning)
		return false
	}
	return confirm(os.Stdin)
}

// confirm reads y/n answers from in, reprompting on unparseable input (e.g. a
// bare Enter). It is bounded and treats EOF as a decline so a read that can
// never succeed can't turn into an unbounded retry loop (#2711).
func confirm(in io.Reader) bool {
	var input string

	for attempt := 0; attempt < maxConfirmRetries; attempt++ {
		fmt.Println(confirmationQuestion)
		if _, err := fmt.Fscanln(in, &input); err != nil {
			if errors.Is(err, io.EOF) {
				logger.L().Warning(stdinClosedWarning)
				return false
			}
			continue
		}

		switch strings.ToLower(input) {
		case "y", "yes":
			return true
		case "n", "no":
			return false
		}
	}

	logger.L().Warning("no valid confirmation received after repeated attempts; treating as declined and applying no changes")
	return false
}
