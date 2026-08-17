package vap

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/opaprocessor/cel"
	"github.com/spf13/cobra"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/yaml"
)

var vapHelperCmdExamples = fmt.Sprintf(`
  vap command can be used for managing Validating Admission Policies in a Kubernetes cluster.
  This is an experimental feature and it might change.

  Examples:

  # Install Kubescape CEL admission policy library (the copy embedded in this binary)
  %[1]s vap deploy-library | kubectl apply -f -
  # Install a specific cel-admission-library release instead of the embedded copy
  %[1]s vap deploy-library --from-release v0.11 | kubectl apply -f -
  # Create a policy binding by Kubescape control ID
  %[1]s vap create-policy-binding --name my-policy-binding --control C-0016 --namespace=my-namespace | kubectl apply -f -
  # Create a policy binding by ValidatingAdmissionPolicy name
  %[1]s vap create-policy-binding --name my-policy-binding --policy kubescape-c-0016-allow-privilege-escalation --namespace=my-namespace | kubectl apply -f -
  # Roll a control out in report-only mode before switching it to Deny
  %[1]s vap create-policy-binding --name my-policy-binding --control C-0016 --action Audit --action Warn | kubectl apply -f -
`, cautils.ExecName())

func GetVapHelperCmd() *cobra.Command {

	vapHelperCmd := &cobra.Command{
		Use:     "vap",
		Short:   "Helper commands for managing Validating Admission Policies in a Kubernetes cluster",
		Long:    ``,
		Example: vapHelperCmdExamples,
	}

	// Create subcommands
	vapHelperCmd.AddCommand(getDeployLibraryCmd())
	vapHelperCmd.AddCommand(getCreatePolicyBindingCmd())

	return vapHelperCmd
}

// defaultDownloadTimeout bounds each --from-release download. It matches the
// 30s used by the other outbound HTTP clients in the codebase (the repository
// scanner and the cluster connector).
const defaultDownloadTimeout = 30 * time.Second

func getDeployLibraryCmd() *cobra.Command {
	var outputFile string
	var fromRelease string
	var timeout time.Duration

	cmd := &cobra.Command{
		Use:   "deploy-library",
		Short: "Install Kubescape CEL admission policy library",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			content, err := deployLibrary(fromRelease, timeout)
			if err != nil {
				return err
			}
			return writeOutput(content, outputFile)
		},
	}
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write output to file instead of stdout")
	cmd.Flags().StringVar(&fromRelease, "from-release", "", "Download the library from this cel-admission-library release tag (e.g. v0.11) instead of using the embedded copy")
	cmd.Flags().DurationVar(&timeout, "timeout", defaultDownloadTimeout, "HTTP request timeout per download, only used with --from-release (e.g. 30s, 1m). 0 disables the timeout")

	return cmd
}

func getCreatePolicyBindingCmd() *cobra.Command {
	var policyBindingName string
	var policyName string
	var controlID string
	var namespaceArr []string
	var labelArr []string
	var actionArr []string
	var parameterReference string
	var outputFile string

	createPolicyBindingCmd := &cobra.Command{
		Use:   "create-policy-binding",
		Short: "Create a policy binding",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate the inputs
			if err := isValidK8sObjectName(policyBindingName); err != nil {
				return fmt.Errorf("invalid policy binding name %s: %w", policyBindingName, err)
			}
			resolvedPolicyName, err := resolvePolicyName(policyName, controlID)
			if err != nil {
				return err
			}
			// A policy that declares a paramKind needs a ParamRef on its binding
			// to be functional, so refuse to emit a silently broken binding. The
			// check covers both flags: --control reads the paramKind off the
			// control's policy, --policy off the named policy (a name outside
			// the embedded bundle is left unchecked — we know nothing about it).
			normalizedControlID := strings.ToUpper(strings.TrimSpace(controlID))
			if parameterReference == "" {
				if normalizedControlID != "" {
					paramKind, err := cel.ParamKindForControl(normalizedControlID)
					if err != nil {
						return err
					}
					if paramKind != nil {
						return fmt.Errorf("control %s requires --parameter-reference because its CEL policy uses params", normalizedControlID)
					}
				} else {
					paramKind, found, err := cel.ParamKindForPolicy(resolvedPolicyName)
					if err != nil {
						return err
					}
					if found && paramKind != nil {
						return fmt.Errorf("policy %s requires --parameter-reference because it uses params", resolvedPolicyName)
					}
				}
			}
			if err := isValidK8sObjectName(resolvedPolicyName); err != nil {
				return fmt.Errorf("invalid policy name %s: %w", resolvedPolicyName, err)
			}
			for _, namespace := range namespaceArr {
				if err := isValidNamespace(namespace); err != nil {
					return fmt.Errorf("invalid namespace %s: %w", namespace, err)
				}
			}
			for _, label := range labelArr {
				parsed, err := labels.Parse(label)
				if err != nil {
					return fmt.Errorf("invalid label selector: %s", label)
				}
				requirements, _ := parsed.Requirements()
				for _, r := range requirements {
					if r.Operator() != selection.Equals {
						return fmt.Errorf("only '=' equality label selectors are supported: %s", label)
					}
				}
			}
			actions, err := parseValidationActions(actionArr)
			if err != nil {
				return err
			}
			if parameterReference != "" {
				if err := isValidK8sObjectName(parameterReference); err != nil {
					return fmt.Errorf("invalid parameter reference %s: %w", parameterReference, err)
				}
			}

			content, err := createPolicyBinding(policyBindingName, resolvedPolicyName, actions, parameterReference, namespaceArr, labelArr)
			if err != nil {
				return err
			}
			return writeOutput(content, outputFile)
		},
	}
	// Must specify the name of the policy binding
	createPolicyBindingCmd.Flags().StringVarP(&policyBindingName, "name", "n", "", "Name of the policy binding")
	_ = createPolicyBindingCmd.MarkFlagRequired("name") // #nosec G104 -- flag is defined on this command; MarkFlagRequired only errors for an unknown flag
	createPolicyBindingCmd.Flags().StringVarP(&policyName, "policy", "p", "", "Name of the ValidatingAdmissionPolicy to bind resources to")
	createPolicyBindingCmd.Flags().StringVarP(&controlID, "control", "c", "", "Kubescape control ID to bind resources to")
	createPolicyBindingCmd.Flags().StringSliceVar(&namespaceArr, "namespace", []string{}, "Resource namespace selector")
	createPolicyBindingCmd.Flags().StringSliceVar(&labelArr, "label", []string{}, "Resource label selector")
	createPolicyBindingCmd.Flags().StringSliceVarP(&actionArr, "action", "a", []string{string(admissionv1.Deny)}, "Action to take when policy fails, repeatable (Deny, Warn, Audit). Deny and Warn cannot be combined")
	createPolicyBindingCmd.Flags().StringVarP(&parameterReference, "parameter-reference", "r", "", "Parameter reference object name")
	createPolicyBindingCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write output to file instead of stdout")

	return createPolicyBindingCmd
}

// resolvePolicyName resolves the --policy/--control pair to a policy name.
// Control IDs resolve against the VAP bundle embedded in the CEL engine, so the
// answer always matches the deployable YAML instead of a hand-maintained copy.
// Policy names are lowercased like control IDs are uppercased: both flags then
// accept any casing of their canonical form.
func resolvePolicyName(policyName, controlID string) (string, error) {
	policyName = strings.ToLower(strings.TrimSpace(policyName))
	controlID = strings.ToUpper(strings.TrimSpace(controlID))

	if policyName == "" && controlID == "" {
		return "", fmt.Errorf("either --policy or --control must be specified")
	}
	if policyName != "" && controlID != "" {
		return "", fmt.Errorf("only one of --policy or --control can be specified")
	}
	if policyName != "" {
		return policyName, nil
	}

	resolved, err := cel.PolicyNameForControl(controlID)
	if err != nil {
		return "", fmt.Errorf("unsupported control ID %s: %w", controlID, err)
	}
	return resolved, nil
}

// Implementation of the VAP helper commands
// deploy-library
//
// By default the library comes from the bundle embedded in this binary: the
// same copy the scan engine evaluates and create-policy-binding resolves
// metadata from, so what gets deployed is exactly what this build was tested
// against. Downloading a release instead is an explicit opt-in via
// --from-release; it can serve a library this binary knows nothing about, so
// it is never the silent default (issue #2507).
func deployLibrary(fromRelease string, timeout time.Duration) (string, error) {
	if fromRelease != "" {
		return downloadLibrary(fromRelease, timeout)
	}
	return cel.EmbeddedLibraryYAML()
}

// libraryReleaseFiles are the release assets that make up the deployable
// library, in apply order (the CRD first, then the configuration, then the
// policies). Must stay in sync with the assets `make sync-vap` vendors.
var libraryReleaseFiles = []string{
	"policy-configuration-definition.yaml",
	"basic-control-configuration.yaml",
	"kubescape-validating-admission-policies.yaml",
}

// releaseTagPattern is the shape a cel-admission-library release tag may take.
// It is deliberately an allowlist: the tag is interpolated into the release
// URL, so any character that carries meaning in a URL path has to stay out.
// Requiring an alphanumeric first character also rules out "." and ".." on its
// own. Real tags ("v0.11") and the usual semver decorations ("v1.2.3-rc1",
// "v1.2.3+build.5") all satisfy it.
var releaseTagPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)

// validateReleaseTag rejects a tag that would change the shape of the release
// URL rather than just name a release within it. Without this the tag can walk
// out of the kubescape release path entirely ("../../../../owner/repo/..."):
// Go's HTTP client forwards the "../" segments verbatim and GitHub resolves
// them server-side, so the library is served from an unrelated repository while
// the log line still names the requested kubescape release. A "?" or "#" is the
// same class of bug without an attacker - it truncates the URL, so every file
// in libraryReleaseFiles resolves to the same object and the concatenated
// output is silently wrong.
func validateReleaseTag(tag string) error {
	if !releaseTagPattern.MatchString(tag) {
		return fmt.Errorf("invalid release tag %q: expected a release tag such as v0.11", tag)
	}
	return nil
}

// downloadLibrary fetches the library files from one pinned release tag and
// concatenates them into a single multi-document YAML stream. The tag is
// always explicit — downloading whatever "latest" points at would reintroduce
// the skew deployLibrary's embedded default exists to prevent.
func downloadLibrary(tag string, timeout time.Duration) (string, error) {
	if err := validateReleaseTag(tag); err != nil {
		return "", err
	}

	logger.L().Info(fmt.Sprintf("Downloading the Kubescape CEL admission policy library release %s", tag))

	parts := make([]string, 0, len(libraryReleaseFiles))
	for _, file := range libraryReleaseFiles {
		url := fmt.Sprintf("https://github.com/kubescape/cel-admission-library/releases/download/%s/%s", tag, file)
		content, err := downloadFileToString(url, timeout)
		if err != nil {
			return "", fmt.Errorf("download %s from release %s: %w", file, tag, err)
		}
		parts = append(parts, content)
	}

	logger.L().Info("Successfully downloaded admission policy library")
	return strings.Join(parts, "\n---\n") + "\n", nil
}

func downloadFileToString(url string, timeout time.Duration) (string, error) {
	client := &http.Client{
		Timeout: timeout,
	}
	response, err := client.Get(url)
	if err != nil {
		return "", err // Return an empty string and the error if the request fails
	}
	defer response.Body.Close()

	// Check for a successful response (HTTP 200 OK)
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to download file: %s", response.Status)
	}

	// Read the response body
	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err // Return an empty string and the error if reading fails
	}

	// Convert the byte slice to a string
	bodyString := string(bodyBytes)
	return bodyString, nil
}

func writeOutput(content string, outputFile string) error {
	if outputFile != "" {
		if err := os.MkdirAll(filepath.Dir(outputFile), 0750); err != nil {
			return err
		}
		return os.WriteFile(outputFile, []byte(content), 0600)
	}
	fmt.Print(content)
	return nil
}

func isValidK8sObjectName(name string) error {
	if errs := validation.IsDNS1123Subdomain(name); len(errs) > 0 {
		return fmt.Errorf("invalid name: %s", strings.Join(errs, "; "))
	}
	return nil
}

func isValidNamespace(name string) error {
	if errs := validation.IsDNS1123Label(name); len(errs) > 0 {
		return fmt.Errorf("invalid namespace: %s", strings.Join(errs, "; "))
	}
	return nil
}

// supportedValidationActions are the enforcement actions the admission API
// accepts on a binding, matched case-sensitively as the API spells them.
var supportedValidationActions = []admissionv1.ValidationAction{
	admissionv1.Deny,
	admissionv1.Warn,
	admissionv1.Audit,
}

// parseValidationActions turns the --action values into the binding's
// validationActions set. The field is a set on the API, so a binding can carry
// more than one action — the usual rollout is Audit plus Warn first and Deny
// once the findings are clean, which a single-valued flag could not express.
//
// The two combinations the apiserver rejects are refused here rather than at
// apply time: a repeated action (the field is a listType=set) and Deny with
// Warn, which the API forbids because it would report the same failure twice.
// Order is preserved so the emitted YAML reads back the way it was asked for.
func parseValidationActions(values []string) ([]admissionv1.ValidationAction, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("at least one --action is required")
	}
	actions := make([]admissionv1.ValidationAction, 0, len(values))
	seen := make(map[admissionv1.ValidationAction]struct{}, len(values))
	for _, value := range values {
		action := admissionv1.ValidationAction(strings.TrimSpace(value))
		if !isSupportedValidationAction(action) {
			return nil, fmt.Errorf("invalid action: %s", value)
		}
		if _, dup := seen[action]; dup {
			return nil, fmt.Errorf("duplicate action: %s", action)
		}
		seen[action] = struct{}{}
		actions = append(actions, action)
	}
	if _, deny := seen[admissionv1.Deny]; deny {
		if _, warn := seen[admissionv1.Warn]; warn {
			return nil, fmt.Errorf("actions Deny and Warn cannot be combined")
		}
	}
	return actions, nil
}

func isSupportedValidationAction(action admissionv1.ValidationAction) bool {
	for _, supported := range supportedValidationActions {
		if action == supported {
			return true
		}
	}
	return false
}

// Create a policy binding
func createPolicyBinding(bindingName string, policyName string, actions []admissionv1.ValidationAction, paramRefName string, namespaceArr []string, labelMatch []string) (string, error) {
	// Create a policy binding struct
	policyBinding := &admissionv1.ValidatingAdmissionPolicyBinding{}
	policyBinding.APIVersion = "admissionregistration.k8s.io/v1"
	policyBinding.Name = bindingName
	policyBinding.Kind = "ValidatingAdmissionPolicyBinding"
	policyBinding.Spec.PolicyName = policyName
	policyBinding.Spec.MatchResources = &admissionv1.MatchResources{}
	if len(namespaceArr) > 0 {
		policyBinding.Spec.MatchResources.NamespaceSelector = &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      "kubernetes.io/metadata.name",
					Operator: metav1.LabelSelectorOpIn,
					Values:   namespaceArr,
				},
			},
		}
	}

	if len(labelMatch) > 0 {
		policyBinding.Spec.MatchResources.ObjectSelector = &metav1.LabelSelector{}
		policyBinding.Spec.MatchResources.ObjectSelector.MatchLabels = make(map[string]string)
		for _, label := range labelMatch {
			parsed, err := labels.Parse(label)
			if err != nil {
				continue
			}
			requirements, _ := parsed.Requirements()
			for _, r := range requirements {
				if len(r.Values().List()) > 0 {
					policyBinding.Spec.MatchResources.ObjectSelector.MatchLabels[r.Key()] = r.Values().List()[0]
				}
			}
		}
	}

	policyBinding.Spec.ValidationActions = actions
	paramAction := admissionv1.DenyAction
	if paramRefName != "" {
		policyBinding.Spec.ParamRef = &admissionv1.ParamRef{
			Name:                    paramRefName,
			ParameterNotFoundAction: &paramAction,
		}
	}
	// Marshal the policy binding to YAML
	out, err := yaml.Marshal(policyBinding)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
