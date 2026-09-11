# regal ignore:directory-package-mismatch 
package armo_builtins

import rego.v1

# fails if config map has keys with suspicious name
deny contains msga if {
	sensitive_key_names := data.postureControlInputs.sensitiveKeyNames
	configmap := input[_]
	configmap.kind == "ConfigMap"

	# see default-config-inputs.json for list values
	key_name := sensitive_key_names[_]
	map_secret := configmap.data[map_key]
	map_secret != ""

	contains(lower(map_key), lower(key_name))

	# check that value or key weren't allowed by user
	not is_allowed_value(map_secret)
	not is_allowed_key_name(map_key)

	path := sprintf("data[%v]", [map_key])

	msga := {
		"alertMessage": sprintf("this configmap has sensitive information: %v", [configmap.metadata.name]),
		"alertScore": 9,
		"deletePaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [configmap]},
	}
}

# fails if config map has values with suspicious content - not base 64
deny contains msga if {
	# see default-config-inputs.json for list values
	sensitive_values := data.postureControlInputs.sensitiveValues
	value := sensitive_values[_]

	configmap := input[_]
	configmap.kind == "ConfigMap"
	map_secret := configmap.data[map_key]
	map_secret != ""

	regex.match(value, map_secret)

	# check that value or key weren't allowed by user
	not is_allowed_value(map_secret)
	not is_allowed_key_name(map_key)

	path := sprintf("data[%v]", [map_key])

	msga := {
		"alertMessage": sprintf("this configmap has sensitive information: %v", [configmap.metadata.name]),
		"alertScore": 9,
		"deletePaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [configmap]},
	}
}

# fails if config map has values with suspicious content - base 64
deny contains msga if {
	# see default-config-inputs.json for list values
	sensitive_values := data.postureControlInputs.sensitiveValues
	value := sensitive_values[_]

	configmap := input[_]
	configmap.kind == "ConfigMap"
	map_secret := configmap.data[map_key]
	map_secret != ""

	decoded_secret := base64.decode(map_secret)

	regex.match(value, decoded_secret)

	# check that value or key weren't allowed by user
	not is_allowed_value(map_secret)
	not is_allowed_key_name(map_key)

	path := sprintf("data[%v]", [map_key])

	msga := {
		"alertMessage": sprintf("this configmap has sensitive information: %v", [configmap.metadata.name]),
		"alertScore": 9,
		"deletePaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [configmap]},
	}
}

is_allowed_value(value) if {
	allow_val := data.postureControlInputs.sensitiveValuesAllowed[_]
	regex.match(allow_val, value)
}

is_allowed_key_name(key_name) if {
	allow_key := data.postureControlInputs.sensitiveKeyNamesAllowed[_]
	contains(lower(key_name), lower(allow_key))
}
