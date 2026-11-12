package fix

import (
	"errors"
	"fmt"
	"strings"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/meta"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/spf13/cobra"
)

var fixCmdExamples = fmt.Sprintf(`
  Fix command is for fixing kubernetes manifest files based on a scan command output.
  Use with caution, this command will change your files in-place unless
  --output-dir is given.

  # Fix kubernetes YAML manifest files based on a scan command output (output.json)
  1) %[1]s scan . --format json --output output.json
  2) %[1]s fix output.json

  # Leave the manifests untouched and write the fixed copies to a directory instead
  %[1]s fix output.json --output-dir ./fixed

  The copies recreate the scanned tree, and a multi-document file stays one
  file. Inside a git repository the tree starts at the repository root, so
  ./k8s/prod/deploy.yaml is written to ./fixed/k8s/prod/deploy.yaml. Outside
  one it starts at the scanned directory, or for several scanned directories
  at the directory they share, so two inputs that both hold a deploy.yaml each
  keep their own copy. Nothing is edited in place, so there is no
  confirmation prompt; a directory that is not empty is refused unless
  --no-confirm is passed, and one where a copy would overwrite a scanned
  manifest is refused regardless.

  # Leave the manifests untouched and export the fixes as one unified diff
  1) %[1]s fix output.json --output-patch remediation.patch
  2) review remediation.patch, then from the repository root (inside git), or
     from the scanned directory outside git (the directory the inputs share,
     for several):
     git apply --check remediation.patch && git apply remediation.patch
     (or: patch -p1 < remediation.patch)
     git skips, and still exits 0 for, a patch whose paths are not under the
     directory it runs in, so run it from the right one, or use git apply -v.

  The patch holds the same edits a fix in place would make, so the only
  difference is that you apply them. File paths are laid out as with
  --output-dir. No manifest is modified and there is no confirmation prompt; an
  existing patch file is replaced only with --no-confirm, and the path of a
  scanned manifest or of the report is refused regardless. If no manifest would
  change, no file is written. Controls that cannot be fixed automatically are
  listed, so a patch is not a claim that every finding is resolved.

  The report file's own recorded scan location is trusted by default. If the
  report comes from a source you don't fully trust (e.g. a shared CI
  artifact), pass --base-path to require that location to resolve inside a
  directory you control:
  3) %[1]s fix output.json --base-path .

  A cluster scan has no manifests to rewrite, so its fixes are printed instead
  of applied. Nothing is ever written to the cluster — applying is your call.

  # Fix misconfigurations found by a cluster scan
  1) %[1]s scan --format json --output cluster.json
  2) %[1]s fix cluster.json

  # Review, then apply
  %[1]s fix cluster.json | kubectl apply -f -

  # For a cluster with many findings, write one manifest per resource instead
  %[1]s fix cluster.json --output-dir ./fixes

  # Generate Kustomize JSON 6902 patches for Helm-rendered resources
  # (use when the Helm chart is third-party or managed via GitOps and you
  # cannot modify the original chart)
  1) %[1]s scan ./my-chart --format json --output output.json
  2) %[1]s fix output.json --output-kustomize ./patches
  Apply: kustomize build ./patches | kubectl apply -f -

  # Generate an executable Helm --post-renderer script alongside Kustomize patches
  1) %[1]s scan ./my-chart --format json --output output.json
  2) %[1]s fix output.json --output-kustomize ./patches --output-post-renderer ./patches
  Apply: helm install my-release ./my-chart --post-renderer ./patches/renderer.sh

  # Apply the fixes, then rescan to check each fixed finding is resolved
  %[1]s fix output.json --verify

  --verify rescans the scanned directories after the fixes are written in place
  and reports, for each fixed control, resolved, still failing or unverified. It
  exits with an error unless every fix is resolved, so it can gate a pipeline. A
  resource that is missing from the rescan, or a rescan that did not fully
  complete, is unverified, never resolved. The rescan uses the controls
  configuration the report records, or the file given with --controls-config,
  and refuses to run, before anything is changed or written, if that file cannot
  be read or holds no control inputs. It uses the defaults for what the report
  does not record (exceptions, controls version, policy sources), so scan again
  with your own settings if the original scan used others. It needs the
  manifests changed, so it cannot be combined with --dry-run, --output-dir or
  --output-patch, and a cluster scan has none.

  The manifests reflect the cluster as it was scanned, not a live read: a
  resource that changed since the scan should be re-scanned before applying.

  Resources whose scan record is redacted are declined rather than emitted,
  since a manifest built from one would overwrite your real configuration:
  workloads with container environment variables, plus Secrets and ConfigMaps.
  For Helm-rendered resources (--output-kustomize), container workloads are
  declined because ordinary scan reports redact container environment configuration
  and programmatic scan-time provenance (UnredactedBase or FidelityProvenance)
  is not supplied through the ordinary producer. Eligible non-container Helm
  resources (such as Services) are emitted normally.
  Owner-managed resources are declined too — fix the owner instead. Each is
  listed with its reason. Fixing manifest files is unaffected.

`, cautils.ExecName())

func GetFixCmd(ks meta.IKubescape) *cobra.Command {
	var fixInfo metav1.FixInfo

	fixCmd := &cobra.Command{
		Use:     "fix <report output file>",
		Short:   "Propose a fix for the misconfiguration found when scanning Kubernetes manifest files",
		Long:    ``,
		Example: fixCmdExamples,
		// At most one: zero is left to RunE so it keeps its friendlier message.
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return errors.New("report output file is required")
			}
			if strings.TrimSpace(args[0]) == "" {
				return errors.New("report output file cannot be empty")
			}
			if ks == nil {
				return errors.New("uninitialized kubescape interface")
			}
			fixInfo.ReportFile = strings.TrimSpace(args[0])
			fixInfo.Writer = cmd.OutOrStdout()

			if err := validateControlSelection(&fixInfo); err != nil {
				return err
			}
			if cmd.Flags().Changed("output-dir") {
				trimmed := strings.TrimSpace(fixInfo.OutputDir)
				if trimmed == "" {
					return errors.New("--output-dir needs a directory path")
				}
				fixInfo.OutputDir = trimmed
			}
			if cmd.Flags().Changed("output-kustomize") {
				trimmed := strings.TrimSpace(fixInfo.KustomizeDir)
				if trimmed == "" {
					return errors.New("--output-kustomize needs a directory path")
				}
				fixInfo.KustomizeDir = trimmed
			}
			if cmd.Flags().Changed("output-post-renderer") {
				trimmed := strings.TrimSpace(fixInfo.PostRendererDir)
				if trimmed == "" {
					return errors.New("--output-post-renderer needs a directory path")
				}
				fixInfo.PostRendererDir = trimmed
			}
			// The post-renderer only applies the Kustomize patches, so without
			// them fix would carry on as if the flag had not been passed.
			if fixInfo.PostRendererDir != "" && fixInfo.KustomizeDir == "" {
				return errors.New("--output-post-renderer requires --output-kustomize")
			}
			if cmd.Flags().Changed("base-path") {
				trimmed := strings.TrimSpace(fixInfo.BasePath)
				if trimmed == "" {
					return errors.New("--base-path needs a directory path")
				}
				fixInfo.BasePath = trimmed
			}
			if cmd.Flags().Changed("container-profile") {
				trimmed := strings.TrimSpace(fixInfo.ContainerProfilePath)
				if trimmed == "" {
					return errors.New("--container-profile needs a file path")
				}
				fixInfo.ContainerProfilePath = trimmed
			}
			if err := validateOutputPatch(&fixInfo, cmd.Flags().Changed("output-patch")); err != nil {
				return err
			}

			if cmd.Flags().Changed("controls-config") {
				trimmed := strings.TrimSpace(fixInfo.ControlsConfig)
				if trimmed == "" {
					return errors.New("--controls-config needs a file path")
				}
				fixInfo.ControlsConfig = trimmed
			}
			if err := fixInfo.ValidateVerify(); err != nil {
				return err
			}

			return ks.Fix(&fixInfo)
		},
	}

	fixCmd.PersistentFlags().BoolVar(&fixInfo.NoConfirm, "no-confirm", false, "No confirmation will be given to the user before applying the fix (default false)")
	fixCmd.PersistentFlags().BoolVarP(&fixInfo.Interactive, "interactive", "i", false, "Show each resource's changes and ask before fixing it. Only manifest files fixed in place are asked about: with --dry-run, --no-confirm, --output-dir, --output-patch or a cluster scan the changes are shown without asking (default false)")
	fixCmd.PersistentFlags().BoolVar(&fixInfo.DryRun, "dry-run", false, "No changes will be applied (default false)")
	fixCmd.PersistentFlags().BoolVar(&fixInfo.SkipUserValues, "skip-user-values", true, "Changes which involve user-defined values will be skipped")
	fixCmd.PersistentFlags().StringVar(&fixInfo.BasePath, "base-path", "", "Restrict fixes to this directory: the report's own recorded scan location must resolve inside it. Use this when the report file comes from a source you don't fully trust (e.g. a shared CI artifact); without it, the report's recorded location is trusted as-is")
	fixCmd.PersistentFlags().StringVar(&fixInfo.ContainerProfilePath, "container-profile", "", "Path to a JSON file containing a ContainerProfile to use for drift detection")
	fixCmd.PersistentFlags().StringSliceVar(&fixInfo.IncludeControls, "include-controls", nil, "Remediate only these control IDs (comma-separated, case-insensitive). Controls outside the list are left untouched and are not reported as unfixed; disables --container-profile drift remediation")
	fixCmd.PersistentFlags().StringSliceVar(&fixInfo.SkipControls, "skip-controls", nil, "Leave these control IDs untouched (comma-separated, case-insensitive). Takes precedence over --include-controls; disables --container-profile drift remediation")
	fixCmd.PersistentFlags().StringVar(&fixInfo.OutputDir, "output-dir", "", "Write the fixes into this directory instead of their default destination. For manifest files: fixed copies that mirror the scanned tree, leaving the originals untouched instead of fixing them in place. For cluster scans: one patched manifest per resource, instead of printing them to stdout. A non-empty directory is refused unless --no-confirm is passed")
	fixCmd.PersistentFlags().StringVar(&fixInfo.OutputPatch, "output-patch", "", "Write the fixes for manifest files to this file as one unified diff instead of changing the manifests. Apply it from the scanned directory with: git apply <file> (or patch -p1 < <file>). The manifests are never modified, and an existing file is replaced only with --no-confirm. Not for cluster scans; cannot be combined with --output-dir, --dry-run or --verify")
	fixCmd.PersistentFlags().BoolVar(&fixInfo.Verify, "verify", false, "After the fixes are applied in place, rescan the manifests and report for each fixed control whether the finding is resolved, still failing or could not be verified. Exits with an error unless every fix is resolved. A missing resource or a degraded rescan is never a resolution. The rescan uses the controls configuration the report records and the defaults for what it does not (exceptions, controls version, policy sources). Cannot be combined with --dry-run, --output-dir or --output-patch, and does not apply to cluster scans (default false)")
	fixCmd.PersistentFlags().StringVar(&fixInfo.ControlsConfig, "controls-config", "", "With --verify, the controls-config file the rescan uses instead of the one the report records. The report records only its path, and a rescan under another configuration could judge a control differently, so --verify refuses to run when the recorded file cannot be read or holds no control inputs; give the file here. Only applies to --verify")
	fixCmd.PersistentFlags().StringVar(&fixInfo.KustomizeDir, "output-kustomize", "", "Write a kustomization.yaml and JSON 6902 patch files for Helm-rendered resources into this directory. Apply with: kustomize build <dir> | kubectl apply -f -. Note: container resources from ordinary scan reports are declined because environment configuration is redacted and programmatic scan-time provenance is not supplied through the ordinary producer")
	fixCmd.PersistentFlags().StringVar(&fixInfo.PostRendererDir, "output-post-renderer", "", "Write an executable Helm --post-renderer script into this directory. Requires --output-kustomize to also be set. Apply with: helm install <release> <chart> --post-renderer <dir>/renderer.sh")
	fixCmd.PersistentFlags().StringSliceVarP(&fixInfo.HelmValueOptions.ValueFiles, "values", "f", nil, "Specify values in a YAML file (can specify multiple)")
	fixCmd.PersistentFlags().StringArrayVar(&fixInfo.HelmValueOptions.Values, "set", nil, "Set values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)")
	fixCmd.PersistentFlags().StringArrayVar(&fixInfo.HelmValueOptions.StringValues, "set-string", nil, "Set STRING values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)")
	fixCmd.PersistentFlags().StringArrayVar(&fixInfo.HelmValueOptions.FileValues, "set-file", nil, "Set values from respective files specified via the command line (can specify multiple or separate values with commas: key1=path1,key2=path2)")
	fixCmd.PersistentFlags().StringVar(&fixInfo.HelmValueOptions.ReleaseName, "release-name", "", "Release name to use when rendering Helm charts")
	fixCmd.PersistentFlags().StringVar(&fixInfo.HelmValueOptions.ReleaseNamespace, "release-namespace", "", "Release namespace to use when rendering Helm charts")

	return fixCmd
}

// validateOutputPatch applies the rules FixInfo.ValidateOutputPatch holds, which
// Kubescape.Fix applies too. What only the command can see is whether the flag
// was passed: an empty path is an error then, as in --output-patch "$PATCH" with
// PATCH unset. Taken as "not given" it would fall through to fixing the
// manifests in place, the opposite of what was asked for.
func validateOutputPatch(fixInfo *metav1.FixInfo, flagPassed bool) error {
	if flagPassed {
		trimmed := strings.TrimSpace(fixInfo.OutputPatch)
		if trimmed == "" {
			return errors.New("--output-patch needs a file path")
		}
		fixInfo.OutputPatch = trimmed
	}
	return fixInfo.ValidateOutputPatch()
}

func validateControlSelection(fixInfo *metav1.FixInfo) error {
	for _, selection := range []struct {
		flag     string
		controls []string
	}{
		{"--include-controls", fixInfo.IncludeControls},
		{"--skip-controls", fixInfo.SkipControls},
	} {
		for _, control := range selection.controls {
			if strings.TrimSpace(control) == "" {
				return fmt.Errorf("%s contains an empty control identifier", selection.flag)
			}
		}
	}
	return nil
}
