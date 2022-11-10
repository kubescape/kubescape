package core

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	metav1 "github.com/kubescape/kubescape/v2/core/meta/datastructures/v1"
)

var listFunc = map[string]func(*metav1.ListPolicies) ([]string, error){
	"controls":   listControls,
	"frameworks": listFrameworks,
	"exceptions": listExceptions,
}

var listFormatFunc = map[string]func(*metav1.ListPolicies, []string){
	"pretty-print": prettyPrintListFormat,
	"json":         jsonListFormat,
}

func ListSupportActions() []string {
	commands := []string{}
	for k := range listFunc {
		commands = append(commands, k)
	}
	return commands
}
func (ks *Kubescape) List(listPolicies *metav1.ListPolicies) error {
	if policyListerFunc, ok := listFunc[listPolicies.Target]; ok {
		policies, err := policyListerFunc(listPolicies)
		if err != nil {
			return err
		}
		sort.Strings(policies)

		if listFormatFunction, ok := listFormatFunc[listPolicies.Format]; ok {
			listFormatFunction(listPolicies, policies)
		} else {
			return fmt.Errorf("Invalid format \"%s\", Supported formats: 'pretty-print'/'json' ", listPolicies.Format)
		}

		return nil
	}
	return fmt.Errorf("unknown command to download")
}

func listFrameworks(listPolicies *metav1.ListPolicies) ([]string, error) {
	tenant := getTenantConfig(&listPolicies.Credentials, "", "", getKubernetesApi()) // change k8sinterface
	policyGetter := getPolicyGetter(nil, tenant.GetTenantEmail(), true, nil)

	return listFrameworksNames(policyGetter), nil
}

func listControls(listPolicies *metav1.ListPolicies) ([]string, error) {
	tenant := getTenantConfig(&listPolicies.Credentials, "", "", getKubernetesApi()) // change k8sinterface

	policyGetter := getPolicyGetter(nil, tenant.GetTenantEmail(), false, nil)
	return policyGetter.ListControls()
}

func listExceptions(listPolicies *metav1.ListPolicies) ([]string, error) {
	// load tenant metav1
	tenant := getTenantConfig(&listPolicies.Credentials, "", "", getKubernetesApi())

	var exceptionsNames []string
	ksCloudAPI := getExceptionsGetter("", tenant.GetAccountID(), nil)
	exceptions, err := ksCloudAPI.GetExceptions("")
	if err != nil {
		return exceptionsNames, err
	}
	for i := range exceptions {
		exceptionsNames = append(exceptionsNames, exceptions[i].Name)
	}
	return exceptionsNames, nil
}

func prettyPrintListFormat(listPolicies *metav1.ListPolicies, policies []string) {
	sep := "\n  * "
	fmt.Printf("Supported %s:%s%s\n", listPolicies.Target, sep, strings.Join(policies, sep))
}

func jsonListFormat(listPolicies *metav1.ListPolicies, policies []string) {
	j, _ := json.MarshalIndent(policies, "", "  ")
	fmt.Printf("%s\n", j)
}
