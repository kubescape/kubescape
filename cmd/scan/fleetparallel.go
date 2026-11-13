package scan

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/fleet"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// fleetCommandLine is the scan command as the user ran it, which each child process repeats for one context.
type fleetCommandLine struct {
	cmd  *cobra.Command
	args []string
}

var fleetInvocation fleetCommandLine

// fleetChildCommand builds the process that scans one context; tests replace it to run the test binary.
var fleetChildCommand = func(ctx context.Context, args []string) (*exec.Cmd, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return exec.CommandContext(ctx, executable, args...), nil
}

// fleetOutcome is what scanning one context produced, in this process or in a child.
type fleetOutcome struct {
	cluster  fleet.ClusterResult
	scanned  bool
	attempts int
	err      error
}

// fleetOnlyFlags are set per child, or only make sense for the whole run.
var fleetOnlyFlags = map[string]bool{
	"kube-contexts": true, "fleet-report": true, "reference-cluster": true,
	"retries": true, "fleet-config": true, "parallel": true, "output": true, "fleet-child-result": true,
}

// validateParallel rejects an explicit --parallel below 1, and one without --kube-contexts.
func validateParallel(cmd *cobra.Command, scanInfo *cautils.ScanInfo) error {
	if !commandFlagChanged(cmd, "parallel") {
		return nil
	}
	if scanInfo.KubeContextParallel < 1 {
		return fmt.Errorf("--parallel %d must be at least 1", scanInfo.KubeContextParallel)
	}
	if len(scanInfo.KubeContexts) == 0 {
		return fmt.Errorf("--parallel requires --kube-contexts: it sets how many contexts of a multi-context scan run at once")
	}
	return nil
}

// fleetChildBaseArgs is the user's command without the fleet flags, which each child then sets for its own context.
func fleetChildBaseArgs(invocation fleetCommandLine) []string {
	args := strings.Fields(invocation.cmd.CommandPath())[1:]
	invocation.cmd.Flags().Visit(func(flag *pflag.Flag) {
		if fleetOnlyFlags[flag.Name] {
			return
		}
		if values, ok := flag.Value.(pflag.SliceValue); ok {
			for _, value := range values.GetSlice() {
				args = append(args, "--"+flag.Name+"="+value)
			}
			return
		}
		// A map flag prints as "[k=v]", which does not parse back, so each entry is passed on its own.
		if pairs, err := invocation.cmd.Flags().GetStringToString(flag.Name); err == nil {
			for _, key := range slices.Sorted(maps.Keys(pairs)) {
				args = append(args, "--"+flag.Name+"="+key+"="+pairs[key])
			}
			return
		}
		args = append(args, "--"+flag.Name+"="+flag.Value.String())
	})
	return args
}

// fleetChildArgs adds one context's fleet settings and the user's positional arguments to the base arguments.
func fleetChildArgs(base, positional []string, kubeContext, output, result string, retries int) []string {
	args := slices.Clone(base)
	args = append(args, "--kube-contexts="+kubeContext, "--output="+output, "--fleet-child-result="+result, fmt.Sprintf("--retries=%d", retries))
	return append(append(args, "--"), positional...)
}

// scanFleetInProcesses scans every context in its own process, at most KubeContextParallel at once.
func scanFleetInProcesses(ctx context.Context, scanInfo *cautils.ScanInfo, outputPaths map[string]string) []fleetOutcome {
	outcomes := make([]fleetOutcome, len(scanInfo.KubeContexts))
	dir, err := os.MkdirTemp("", "kubescape-fleet-")
	if err != nil {
		for i, kubeContext := range scanInfo.KubeContexts {
			outcomes[i] = failedOutcome(kubeContext, fmt.Errorf("create a directory for the child scans: %w", err), 0)
		}
		return outcomes
	}
	defer os.RemoveAll(dir)

	// Built once, since reading the command's flags is not safe from several goroutines.
	base := fleetChildBaseArgs(fleetInvocation)
	slots := make(chan struct{}, scanInfo.KubeContextParallel)
	var wg sync.WaitGroup
	for i, kubeContext := range scanInfo.KubeContexts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			logger.L().Info("fleet scan: scanning context in its own process", helpers.String("context", kubeContext), helpers.String("output", outputPaths[kubeContext]))
			outcomes[i] = runFleetChild(ctx, kubeContext, scanInfo, base, filepath.Join(dir, fmt.Sprint(i)))
		}()
	}
	wg.Wait()
	return outcomes
}

// runFleetChild scans one context in a child process and reads its outcome back from the result the child writes.
func runFleetChild(ctx context.Context, kubeContext string, scanInfo *cautils.ScanInfo, baseArgs []string, base string) fleetOutcome {
	started := time.Now()
	if err := ctx.Err(); err != nil {
		return failedOutcome(kubeContext, interruptedError{err: err}, time.Since(started))
	}
	resultPath, logPath := base+".json", base+".log"
	command, err := fleetChildCommand(ctx, fleetChildArgs(baseArgs, fleetInvocation.args, kubeContext, scanInfo.Output, resultPath, scanInfo.KubeContextRetries))
	if err != nil {
		return failedOutcome(kubeContext, fmt.Errorf("start the scan: %w", err), time.Since(started))
	}
	logFile, err := os.Create(logPath)
	if err != nil {
		return failedOutcome(kubeContext, fmt.Errorf("start the scan: %w", err), time.Since(started))
	}
	command.Stdout, command.Stderr = logFile, logFile
	runErr := command.Run()
	_ = logFile.Close()

	if ctx.Err() != nil {
		return failedOutcome(kubeContext, interruptedError{err: ctx.Err()}, time.Since(started))
	}
	cluster, readErr := readChildCluster(resultPath, kubeContext)
	if readErr != nil {
		return failedOutcome(kubeContext, fmt.Errorf("the scan wrote no result (%v): %s", runErr, lastLines(logPath, 3)), time.Since(started))
	}
	outcome := fleetOutcome{cluster: cluster, scanned: cluster.Scanned(), attempts: cluster.Attempts}
	if runErr == nil {
		return outcome
	}
	message := childFailure(logPath, kubeContext)
	var exitErr *exec.ExitError
	if outcome.scanned && errors.As(runErr, &exitErr) && exitErr.ExitCode() == exitGateFailed {
		outcome.err = gateFailure(errors.New(message))
	} else {
		outcome.err = errors.New(message)
	}
	return outcome
}

// failedOutcome is a context that has no report, with the status its error implies.
func failedOutcome(kubeContext string, err error, elapsed time.Duration) fleetOutcome {
	return fleetOutcome{cluster: newClusterResult(kubeContext, nil, err, elapsed), err: err}
}

// readChildCluster reads the one cluster a child's result holds.
func readChildCluster(path, kubeContext string) (fleet.ClusterResult, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return fleet.ClusterResult{}, err
	}
	var report fleet.FleetReport
	if err := json.Unmarshal(contents, &report); err != nil {
		return fleet.ClusterResult{}, err
	}
	for _, cluster := range report.Clusters {
		if cluster.Context == kubeContext {
			return cluster, nil
		}
	}
	return fleet.ClusterResult{}, fmt.Errorf("no result for %q", kubeContext)
}

// childFailure finds the child's own "<context>: <error>" line, which its fleet summary prints on failure.
func childFailure(logPath, kubeContext string) string {
	file, err := os.Open(logPath)
	if err != nil {
		return "the scan failed"
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		if message, ok := strings.CutPrefix(scanner.Text(), kubeContext+": "); ok {
			// The parent adds the attempt count itself, so the child's copy is dropped.
			if i := strings.LastIndex(message, " (after "); i >= 0 && strings.HasSuffix(message, " attempts)") {
				message = message[:i]
			}
			return message
		}
	}
	return "the scan failed: " + lastLines(logPath, 3)
}

// lastLines returns the end of a child's log, for errors that left no report behind.
func lastLines(path string, n int) string {
	contents, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(string(contents)), "\n")
	return strings.Join(lines[max(0, len(lines)-n):], " | ")
}

// writeFleetChildResult saves a child's result for the parent; under --hide or --encrypt the scan already protected it.
func writeFleetChildResult(path string, clusters []fleet.ClusterResult) {
	if err := writeFleetReport(path, &fleet.FleetReport{Clusters: clusters}); err != nil {
		logger.L().Error("fleet scan: result for the parent not written", helpers.Error(err))
	}
}
