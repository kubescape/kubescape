# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# A ServiceAccount annotated for EKS IRSA or GKE Workload Identity can exchange
# its projected token for cloud provider credentials, so anything able to use
# the token reaches the cloud account behind it.
deny contains msga if {
	sa := input[_]
	sa.kind == "ServiceAccount"

	# annotations are listed inline because a package level constant would be
	# evaluated as a rule response by the rego processor
	provider := [
		{"annotation": "eks.amazonaws.com/role-arn", "description": "AWS IAM role"},
		{"annotation": "iam.gke.io/gcp-service-account", "description": "GCP service account"},
	][_]

	identity := sa.metadata.annotations[provider.annotation]

	failedPath := sprintf("metadata.annotations[%s]", [provider.annotation])

	msga := {
		"alertMessage": sprintf("ServiceAccount: %s is assigned the %s %s", [sa.metadata.name, provider.description, identity]),
		"alertScore": 3,
		"packagename": "armo_builtins",
		"reviewPaths": [failedPath],
		"failedPaths": [failedPath],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [sa]},
	}
}
