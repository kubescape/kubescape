# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# Fails if user account mount tokens in pod by default
deny contains msga if {
	service_accounts := [service_account | service_account = input[_]; service_account.kind == "ServiceAccount"]
	service_account := service_accounts[_]
	service_account.metadata.name == "default"
	result := is_auto_mount(service_account)
	failed_path := get_failed_path(result)
	fixed_path := get_fixed_path(result)

	msga := {
		"alertMessage": sprintf("the following service account: %v in the following namespace: %v mounts service account tokens in pods by default", [service_account.metadata.name, service_account.metadata.namespace]),
		"alertScore": 9,
		"packagename": "armo_builtins",
		"fixPaths": fixed_path,
		"deletePaths": failed_path,
		"failedPaths": failed_path,
		"alertObject": {"k8sApiObjects": [service_account]},
	}
}

get_failed_path(paths) := [paths[0]] if {
	paths[0] != ""
} else := []

get_fixed_path(paths) := [paths[1]] if {
	paths[1] != ""
} else := []

#  -- ----     For SAs     -- ----
is_auto_mount(service_account) := [failed_path, fix_path] if {
	service_account.automountServiceAccountToken == true
	failed_path = "automountServiceAccountToken"
	fix_path = ""
}

is_auto_mount(service_account) := [failed_path, fix_path] if {
	not service_account.automountServiceAccountToken == false
	not service_account.automountServiceAccountToken == true
	fix_path = {"path": "automountServiceAccountToken", "value": "false"}
	failed_path = ""
}
