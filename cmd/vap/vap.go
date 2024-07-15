package vap

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"sigs.k8s.io/yaml"

	"github.com/spf13/cobra"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var vapHelperCmdExamples = fmt.Sprintf(`
  vap command can be used for managing Validating Admission Policies in a Kubernetes cluster.
  This is an experimental feature and it might change.

  Examples:

  # Install Kubescape CEL admission policy library
  %[1]s vap deploy-library | kubectl apply -f -
  # Create a policy binding
  %[1]s vap create-policy-binding --name my-policy-binding --policy c-0016 --namespace=my-namespace | kubectl apply -f -
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
	return &cobra.Command{
		Use:   "deploy-library",
		Short: "Install Kubescape CEL admission policy library",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			return deployLibrary()
		},
	}
}

func getCreatePolicyBindingCmd() *cobra.Command {
	var policyBindingName string
	var policyName string
	var namespaceArr []string
	var labelArr []string
	var action string
	var parameterReference string

	createPolicyBindingCmd := &cobra.Command{
		Use:   "create-policy-binding",
		Short: "Create a policy binding",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate the inputs
			if err := isValidK8sObjectName(policyBindingName); err != nil {
				return fmt.Errorf("invalid policy binding name %s: %w", policyBindingName, err)
			}
			if err := isValidK8sObjectName(policyName); err != nil {
				return fmt.Errorf("invalid policy name %s: %w", policyName, err)
			}
			for _, namespace := range namespaceArr {
				if err := isValidK8sObjectName(namespace); err != nil {
					return fmt.Errorf("invalid namespace %s: %w", namespace, err)
				}
			}
			for _, label := range labelArr {
				// Label selector must be in the format key=value
				if !regexp.MustCompile(`^[a-zA-Z0-9]+=[a-zA-Z0-9]+$`).MatchString(label) {
					return fmt.Errorf("invalid label selector: %s", label)
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

			return createPolicyBinding(policyBindingName, policyName, action, parameterReference, namespaceArr, labelArr)
		},
	}
	// Must specify the name of the policy binding
	createPolicyBindingCmd.Flags().StringVarP(&policyBindingName, "name", "n", "", "Name of the policy binding")
	createPolicyBindingCmd.MarkFlagRequired("name")
	createPolicyBindingCmd.Flags().StringVarP(&policyName, "policy", "p", "", "Name of the policy to bind the resources to")
	createPolicyBindingCmd.MarkFlagRequired("policy")
	createPolicyBindingCmd.Flags().StringSliceVar(&namespaceArr, "namespace", []string{}, "Resource namespace selector")
	createPolicyBindingCmd.Flags().StringSliceVar(&labelArr, "label", []string{}, "Resource label selector")
	createPolicyBindingCmd.Flags().StringVarP(&action, "action", "a", "Deny", "Action to take when policy fails")
	createPolicyBindingCmd.Flags().StringVarP(&parameterReference, "parameter-reference", "r", "", "Parameter reference object name")

	return createPolicyBindingCmd
}

// Implementation of the VAP helper commands
// deploy-library
func deployLibrary() error {
	logger.L().Info("Downloading the Kubescape CEL admission policy library")
	// Download the policy-configuration-definition.yaml from the latest release URL
	policyConfigurationDefinitionURL := "https://github.com/kubescape/cel-admission-library/releases/latest/download/policy-configuration-definition.yaml"
	policyConfigurationDefinition, err := downloadFileToString(policyConfigurationDefinitionURL)
	if err != nil {
		return err
	}

	// Download the basic-control-configuration.yaml from the latest release URL
	basicControlConfigurationURL := "https://github.com/kubescape/cel-admission-library/releases/latest/download/basic-control-configuration.yaml"
	basicControlConfiguration, err := downloadFileToString(basicControlConfigurationURL)
	if err != nil {
		return err
	}

	// Download the kubescape-validating-admission-policies.yaml from the latest release URL
	kubescapeValidatingAdmissionPoliciesURL := "https://github.com/kubescape/cel-admission-library/releases/latest/download/kubescape-validating-admission-policies.yaml"
	kubescapeValidatingAdmissionPolicies, err := downloadFileToString(kubescapeValidatingAdmissionPoliciesURL)
	if err != nil {
		return err
	}

	logger.L().Info("Successfully downloaded admission policy library")

	// Print the downloaded files to the STDOUT for the user to apply connecting them to a single YAML with ---
	fmt.Println(policyConfigurationDefinition)
	fmt.Println("---")
	fmt.Println(basicControlConfiguration)
	fmt.Println("---")
	fmt.Println(kubescapeValidatingAdmissionPolicies)

	return nil
}

func downloadFileToString(url string) (string, error) {
	// Send an HTTP GET request to the URL
	response, err := http.Get(url) //nolint:gosec
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

func isValidK8sObjectName(name string) error {
	// Kubernetes object names must consist of lower case alphanumeric characters, '-' or '.',
	// and must start and end with an alphanumeric character (e.g., 'example.com', regex used for validation is '[a-z0-9]([-a-z0-9]*[a-z0-9])?')
	// Max length of 63 characters.
	if len(name) > 63 {
		return errors.New("name should be less than 63 characters")
	}

	regex := regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	if !regex.MatchString(name) {
		return errors.New("name should consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character")
	}

	return nil
}

// Create a policy binding
func createPolicyBinding(bindingName string, policyName string, action string, paramRefName string, namespaceArr []string, labelMatch []string) error {
	// Create a policy binding struct
	policyBinding := &admissionv1.ValidatingAdmissionPolicyBinding{}
	// Print the policy binding after marshalling it to YAML to the STDOUT
	// The user can apply the output to the cluster
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
			labelParts := regexp.MustCompile(`=`).Split(label, 2)
			policyBinding.Spec.MatchResources.ObjectSelector.MatchLabels[labelParts[0]] = labelParts[1]
		}
	}

	policyBinding.Spec.ValidationActions = []admissionv1.ValidationAction{admissionv1.ValidationAction(action)}
	if paramRefName != "" {
		policyBinding.Spec.ParamRef = &admissionv1.ParamRef{
			Name: paramRefName,
		}
	}
	// Marshal the policy binding to YAML
	out, err := yaml.Marshal(policyBinding)
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}
