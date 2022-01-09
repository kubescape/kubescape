package clihandler

import (
	"fmt"
	"sort"
	"strings"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/getter"
)

var listFunc = map[string]func(*cautils.ListPolicies) ([]string, error){
	"controls":   listControls,
	"frameworks": listFrameworks,
}

func ListSupportCommands() []string {
	commands := []string{}
	for k := range listFunc {
		commands = append(commands, k)
	}
	return commands
}
func CliList(listPolicies *cautils.ListPolicies) error {
	if f, ok := listFunc[listPolicies.Target]; ok {
		policies, err := f(listPolicies)
		if err != nil {
			return err
		}
		sort.Strings(policies)

		sep := "\n  * "
		usageCmd := strings.TrimSuffix(listPolicies.Target, "s")
		fmt.Printf("Supported %s:%s%s\n", listPolicies.Target, sep, strings.Join(policies, sep))
		fmt.Printf("\nUseage:\n")
		fmt.Printf("$ kubescape scan %s \"name\"\n", usageCmd)
		fmt.Printf("$ kubescape scan %s \"name-0\",\"name-1\"\n\n", usageCmd)
		return nil
	}
	return fmt.Errorf("unknown command to download")
}

func listFrameworks(listPolicies *cautils.ListPolicies) ([]string, error) {
	tenant := getTenantConfig(listPolicies.Account, "", getKubernetesApi()) // change k8sinterface
	g := getPolicyGetter(nil, tenant.GetCustomerGUID(), true, nil)

	return listFrameworksNames(g), nil
}

func listControls(listPolicies *cautils.ListPolicies) ([]string, error) {
	tenant := getTenantConfig(listPolicies.Account, "", getKubernetesApi()) // change k8sinterface
	g := getPolicyGetter(nil, tenant.GetCustomerGUID(), false, nil)
	l := getter.ListName
	if listPolicies.ListIDs {
		l = getter.ListID
	}
	return g.ListControls(l)
}
