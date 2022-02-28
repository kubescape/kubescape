package clihandler

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/armosec/kubescape/cautils/getter"
	"github.com/armosec/kubescape/clihandler/cliobjects"
)

var listFunc = map[string]func(*cliobjects.ListPolicies) ([]string, error){
	"controls":   listControls,
	"frameworks": listFrameworks,
	"exceptions": listExceptions,
}

var listFormatFunc = map[string]func(*cliobjects.ListPolicies, []string){
	"pretty-print": prettyPrintListFormat,
	"json":         jsonListFormat,
}

func ListSupportCommands() []string {
	commands := []string{}
	for k := range listFunc {
		commands = append(commands, k)
	}
	return commands
}
func CliList(listPolicies *cliobjects.ListPolicies) error {
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

func listFrameworks(listPolicies *cliobjects.ListPolicies) ([]string, error) {
	tenant := getTenantConfig(listPolicies.Account, "", getKubernetesApi()) // change k8sinterface
	g := getPolicyGetter(nil, tenant.GetAccountID(), true, nil)

	return listFrameworksNames(g), nil
}

func listControls(listPolicies *cliobjects.ListPolicies) ([]string, error) {
	tenant := getTenantConfig(listPolicies.Account, "", getKubernetesApi()) // change k8sinterface

	g := getPolicyGetter(nil, tenant.GetAccountID(), false, nil)
	l := getter.ListName
	if listPolicies.ListIDs {
		l = getter.ListID
	}
	return g.ListControls(l)
}

func listExceptions(listPolicies *cliobjects.ListPolicies) ([]string, error) {
	// load tenant config
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

func prettyPrintListFormat(listPolicies *cliobjects.ListPolicies, policies []string) {
	sep := "\n  * "
	fmt.Printf("Supported %s:%s%s\n", listPolicies.Target, sep, strings.Join(policies, sep))
}

func jsonListFormat(listPolicies *cliobjects.ListPolicies, policies []string) {
	j, _ := json.MarshalIndent(policies, "", "  ")
	fmt.Printf("%s\n", j)
}
