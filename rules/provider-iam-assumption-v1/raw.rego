# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# A ServiceAccount annotated for EKS IRSA, GKE Workload Identity, or Azure
# Workload Identity can exchange its projected token for cloud provider
# credentials, so anything able to use the token reaches the cloud account
# behind it.
deny contains msga if {
	sa := input[_]
	sa.kind == "ServiceAccount"

	# annotations are listed inline because a package level constant would be
	# evaluated as a rule response by the rego processor
	provider := [
		{"annotation": "eks.amazonaws.com/role-arn", "description": "AWS IAM role"},
		{"annotation": "iam.gke.io/gcp-service-account", "description": "GCP service account"},
		{"annotation": "azure.workload.identity/client-id", "description": "Azure workload identity client ID"},
	][_]

	identity := sa.metadata.annotations[provider.annotation]

	# An empty or blank value, as a chart renders when no identity is
	# configured, does not name an identity:
	# - For EKS IRSA, the pod identity webhook only mutates pods when the role ARN is non-empty.
	# - For GKE Workload Identity, GKE maps no GCP service account for a blank name.
	# - For Azure Workload Identity, a blank client ID annotation does not name an
	#   identity for this ServiceAccount-level rule to report. Note that while Azure's
	#   webhook still injects the projected token volume if workload identity is enabled,
	#   it skips injecting AZURE_CLIENT_ID. Covering pods that supply their own
	#   AZURE_CLIENT_ID env var is outside this rule's scope, as this rule evaluates
	#   ServiceAccount annotations rather than Pod specs.
	trim_space(identity) != ""

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
