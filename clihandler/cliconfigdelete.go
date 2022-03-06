package clihandler

func CliDelete() error {

	tenant := getTenantConfig("", "", getKubernetesApi()) // change k8sinterface
	return tenant.DeleteCachedConfig()
}
