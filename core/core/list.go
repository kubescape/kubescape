package core

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/armosec/kubescape/core/cautils/getter"
	metav1 "github.com/armosec/kubescape/core/meta/datastructures/v1"
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
	if f, ok := listFunc[listPolicies.Target]; ok {
		policies, err := f(listPolicies)
		if err != nil {
			return err
		}
		sort.Strings(policies)

		listFormatFunc[listPolicies.Format](listPolicies, policies)

		return nil
	}
	return fmt.Errorf("unknown command to download")
}

func listFrameworks(listPolicies *metav1.ListPolicies) ([]string, error) {
	tenant := getTenantConfig(listPolicies.Account, "", getKubernetesApi()) // change k8sinterface
	g := getPolicyGetter(nil, tenant.GetTennatEmail(), true, nil)

	return listFrameworksNames(g), nil
}

func listControls(listPolicies *metav1.ListPolicies) ([]string, error) {
	tenant := getTenantConfig(listPolicies.Account, "", getKubernetesApi()) // change k8sinterface

	g := getPolicyGetter(nil, tenant.GetTennatEmail(), false, nil)
	l := getter.ListName
	if listPolicies.ListIDs {
		l = getter.ListID
	}
	return g.ListControls(l)
}

func listExceptions(listPolicies *metav1.ListPolicies) ([]string, error) {
	// load tenant metav1
	getTenantConfig(listPolicies.Account, "", getKubernetesApi())

	var exceptionsNames []string
	armoAPI := getExceptionsGetter("")
	exceptions, err := armoAPI.GetExceptions("")
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
