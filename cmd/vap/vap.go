package vap

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v3/core/cautils"
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

  # Install Kubescape CEL admission policy library
  %[1]s vap deploy-library | kubectl apply -f -
  # Create a policy binding by Kubescape control ID
  %[1]s vap create-policy-binding --name my-policy-binding --control C-0016 --namespace=my-namespace | kubectl apply -f -
  # Create a policy binding by ValidatingAdmissionPolicy name
  %[1]s vap create-policy-binding --name my-policy-binding --policy kubescape-c-0016-allow-privilege-escalation --namespace=my-namespace | kubectl apply -f -
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

func getDeployLibraryCmd() *cobra.Command {
	var outputFile string
	var timeout time.Duration

	cmd := &cobra.Command{
		Use:   "deploy-library",
		Short: "Install Kubescape CEL admission policy library",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			content, err := deployLibrary(timeout)
			if err != nil {
				return err
			}
			return writeOutput(content, outputFile)
		},
	}
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write output to file instead of stdout")
	cmd.Flags().DurationVar(&timeout, "timeout", 0, "HTTP request timeout per download (e.g. 30s, 1m)")

	return cmd
}

func getCreatePolicyBindingCmd() *cobra.Command {
	var policyBindingName string
	var policyName string
	var controlID string
	var namespaceArr []string
	var labelArr []string
	var action string
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
			normalizedControlID := strings.ToUpper(strings.TrimSpace(controlID))
			if normalizedControlID != "" && parameterReference == "" && celAdmissionControlsRequiringParams[normalizedControlID] {
				return fmt.Errorf("control %s requires --parameter-reference because its CEL policy uses params", normalizedControlID)
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
			if action != "Deny" && action != "Audit" && action != "Warn" {
				return fmt.Errorf("invalid action: %s", action)
			}
			if parameterReference != "" {
				if err := isValidK8sObjectName(parameterReference); err != nil {
					return fmt.Errorf("invalid parameter reference %s: %w", parameterReference, err)
				}
			}

			content, err := createPolicyBinding(policyBindingName, resolvedPolicyName, action, parameterReference, namespaceArr, labelArr)
			if err != nil {
				return err
			}
			return writeOutput(content, outputFile)
		},
	}
	// Must specify the name of the policy binding
	createPolicyBindingCmd.Flags().StringVarP(&policyBindingName, "name", "n", "", "Name of the policy binding")
	createPolicyBindingCmd.MarkFlagRequired("name")
	createPolicyBindingCmd.Flags().StringVarP(&policyName, "policy", "p", "", "Name of the ValidatingAdmissionPolicy to bind resources to")
	createPolicyBindingCmd.Flags().StringVarP(&controlID, "control", "c", "", "Kubescape control ID to bind resources to")
	createPolicyBindingCmd.Flags().StringSliceVar(&namespaceArr, "namespace", []string{}, "Resource namespace selector")
	createPolicyBindingCmd.Flags().StringSliceVar(&labelArr, "label", []string{}, "Resource label selector")
	createPolicyBindingCmd.Flags().StringVarP(&action, "action", "a", "Deny", "Action to take when policy fails")
	createPolicyBindingCmd.Flags().StringVarP(&parameterReference, "parameter-reference", "r", "", "Parameter reference object name")
	createPolicyBindingCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write output to file instead of stdout")

	return createPolicyBindingCmd
}

var celAdmissionPolicyByControlID = map[string]string{
	"C-0001": "kubescape-c-0001-deny-forbidden-container-registries",
	"C-0004": "kubescape-c-0004-deny-resources-with-memory-limit-or-request-not-set",
	"C-0009": "kubescape-c-0009-deny-resources-with-memory-or-cpu-limit-not-set",
	"C-0012": "kubescape-c-0012-deny-resources-with-sensitive-information-in-environment-variables",
	"C-0013": "kubescape-c-0013-deny-resources-with-capability-to-run-as-root",
	"C-0016": "kubescape-c-0016-allow-privilege-escalation",
	"C-0017": "kubescape-c-0017-deny-resources-with-mutable-container-filesystem",
	"C-0018": "kubescape-c-0018-deny-resources-without-configured-readiness-probes",
	"C-0020": "kubescape-c-0020-deny-resources-having-volumes-with-potential-access-to-known-cloud-credentials",
	"C-0026": "kubescape-c-0026-deny-cronjobs",
	"C-0034": "kubescape-c-0034-deny-resources-with-automount-service-account-token-enabled",
	"C-0038": "kubescape-c-0038-deny-resources-with-host-ipc-or-pid-privileges",
	"C-0041": "kubescape-c-0041-deny-resources-with-host-network-access",
	"C-0042": "kubescape-c-0042-deny-resources-with-ssh-server-running",
	"C-0044": "kubescape-c-0044-deny-resources-with-host-port",
	"C-0045": "kubescape-c-0045-deny-workloads-with-hostpath-volumes-readonly-not-false",
	"C-0046": "kubescape-c-0046-deny-resources-with-insecure-capabilities",
	"C-0048": "kubescape-c-0048-deny-workloads-with-hostpath-mounts",
	"C-0050": "kubescape-c-0050-deny-resources-with-cpu-limit-or-request-not-set",
	"C-0055": "kubescape-c-0055-linux-hardening",
	"C-0056": "kubescape-c-0056-deny-resources-without-configured-liveliness-probes",
	"C-0057": "kubescape-c-0057-privileged-container-denied",
	"C-0061": "kubescape-c-0061-deny-workloads-in-default-namespace",
	"C-0062": "kubescape-c-0062-deny-resources-having-containers-with-sudo-in-entrypoint",
	"C-0073": "kubescape-c-0073-deny-naked-pods",
	"C-0074": "kubescape-c-0074-resources-mounting-docker-socket-denied",
	"C-0075": "kubescape-c-0075-deny-resources-with-image-pull-policy-not-set-to-always-for-latest-tag",
	"C-0076": "kubescape-c-0076-deny-resources-without-configured-list-of-labels-not-set",
	"C-0077": "kubescape-c-0077-deny-resources-without-configured-list-of-k8s-common-labels-not-set",
	"C-0078": "kubescape-c-0078-only-allow-images-from-allowed-registry",
	"C-0198": "kubescape-c-0198-deny-root-containers",
	"C-0210": "kubescape-c-0210-deny-seccomp-profile-unconfined",
	"C-0268": "kubescape-c-0268-deny-resources-with-cpu-request-not-set",
	"C-0269": "kubescape-c-0269-deny-resources-with-memory-request-not-set",
	"C-0270": "kubescape-c-0270-deny-resources-with-cpu-limit-not-set",
	"C-0271": "kubescape-c-0271-deny-resources-with-memory-limit-not-set",
	"C-0280": "kubescape-c-0280-deny-access-to-csr-approval-subresource",
}

var celAdmissionControlsRequiringParams = map[string]bool{
	"C-0001": true,
	"C-0004": true,
	"C-0012": true,
	"C-0020": true,
	"C-0046": true,
	"C-0050": true,
	"C-0076": true,
	"C-0077": true,
	"C-0078": true,
	"C-0268": true,
	"C-0269": true,
	"C-0270": true,
	"C-0271": true,
}

func resolvePolicyName(policyName, controlID string) (string, error) {
	policyName = strings.TrimSpace(policyName)
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

	resolved, ok := celAdmissionPolicyByControlID[controlID]
	if !ok {
		return "", fmt.Errorf("unsupported control ID %s", controlID)
	}
	return resolved, nil
}

// Implementation of the VAP helper commands
// deploy-library
func deployLibrary(timeout time.Duration) (string, error) {
	logger.L().Info("Downloading the Kubescape CEL admission policy library")
	// Download the policy-configuration-definition.yaml from the latest release URL
	policyConfigurationDefinitionURL := "https://github.com/kubescape/cel-admission-library/releases/latest/download/policy-configuration-definition.yaml"
	policyConfigurationDefinition, err := downloadFileToString(policyConfigurationDefinitionURL, timeout)
	if err != nil {
		return "", err
	}

	// Download the basic-control-configuration.yaml from the latest release URL
	basicControlConfigurationURL := "https://github.com/kubescape/cel-admission-library/releases/latest/download/basic-control-configuration.yaml"
	basicControlConfiguration, err := downloadFileToString(basicControlConfigurationURL, timeout)
	if err != nil {
		return "", err
	}

	// Download the kubescape-validating-admission-policies.yaml from the latest release URL
	kubescapeValidatingAdmissionPoliciesURL := "https://github.com/kubescape/cel-admission-library/releases/latest/download/kubescape-validating-admission-policies.yaml"
	kubescapeValidatingAdmissionPolicies, err := downloadFileToString(kubescapeValidatingAdmissionPoliciesURL, timeout)
	if err != nil {
		return "", err
	}

	logger.L().Info("Successfully downloaded admission policy library")

	// Concatenate the downloaded files into a single YAML document with --- separators
	var result strings.Builder
	result.WriteString(policyConfigurationDefinition)
	result.WriteString("\n---\n")
	result.WriteString(basicControlConfiguration)
	result.WriteString("\n---\n")
	result.WriteString(kubescapeValidatingAdmissionPolicies)
	result.WriteString("\n")

	return result.String(), nil
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
		if err := os.MkdirAll(filepath.Dir(outputFile), 0755); err != nil {
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

// Create a policy binding
func createPolicyBinding(bindingName string, policyName string, action string, paramRefName string, namespaceArr []string, labelMatch []string) (string, error) {
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

	policyBinding.Spec.ValidationActions = []admissionv1.ValidationAction{admissionv1.ValidationAction(action)}
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
