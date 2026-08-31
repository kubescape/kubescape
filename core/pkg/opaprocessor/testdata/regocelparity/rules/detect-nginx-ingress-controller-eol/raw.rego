# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# Detect nginx ingress controller in Deployments
deny contains msga if {
	workload := input[_]
	workload.kind == "Deployment"
	container := workload.spec.template.spec.containers[i]
	is_nginx_ingress_image(container.image)

	path := sprintf("spec.template.spec.containers[%v].image", [format_int(i, 10)])
	msga := {
		"alertMessage": sprintf("Deployment '%v' uses nginx ingress controller which reaches End of Life in March 2026. No security or functional fixes will be available after this date.", [workload.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 6,
		"reviewPaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"fixCommand": "",
		"alertObject": {"k8sApiObjects": [workload]},
	}
}

# Detect nginx ingress controller in DaemonSets
deny contains msga if {
	workload := input[_]
	workload.kind == "DaemonSet"
	container := workload.spec.template.spec.containers[i]
	is_nginx_ingress_image(container.image)

	path := sprintf("spec.template.spec.containers[%v].image", [format_int(i, 10)])
	msga := {
		"alertMessage": sprintf("DaemonSet '%v' uses nginx ingress controller which reaches End of Life in March 2026. No security or functional fixes will be available after this date.", [workload.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 6,
		"reviewPaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"fixCommand": "",
		"alertObject": {"k8sApiObjects": [workload]},
	}
}

# Detect nginx ingress controller in StatefulSets
deny contains msga if {
	workload := input[_]
	workload.kind == "StatefulSet"
	container := workload.spec.template.spec.containers[i]
	is_nginx_ingress_image(container.image)

	path := sprintf("spec.template.spec.containers[%v].image", [format_int(i, 10)])
	msga := {
		"alertMessage": sprintf("StatefulSet '%v' uses nginx ingress controller which reaches End of Life in March 2026. No security or functional fixes will be available after this date.", [workload.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 6,
		"reviewPaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"fixCommand": "",
		"alertObject": {"k8sApiObjects": [workload]},
	}
}

# Helper function: Check if image is community ingress-nginx controller
# Only matches the community ingress-nginx project that reaches EOL in March 2026
# Does not match NGINX Inc commercial products which have different support lifecycles
is_nginx_ingress_image(image) if {
	contains(image, "ingress-nginx/controller")
}

is_nginx_ingress_image(image) if {
	# Match the official k8s community ingress-nginx images
	contains(image, "k8s.gcr.io/ingress-nginx")
}

is_nginx_ingress_image(image) if {
	# Match the new official registry for community ingress-nginx
	contains(image, "registry.k8s.io/ingress-nginx")
}
