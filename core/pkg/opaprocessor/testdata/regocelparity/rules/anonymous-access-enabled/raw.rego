# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# Fails is rolebinding/clusterrolebinding gives permissions to anonymous user
deny contains msga if {
	rolebindings := [rolebinding | rolebinding = input[_]; endswith(rolebinding.kind, "Binding")]
	rolebinding := rolebindings[_]
	subject := rolebinding.subjects[i]
	isAnonymous(subject)
	delete_path := sprintf("subjects[%d]", [i])
	msga := {
		"alertMessage": sprintf("the following RoleBinding: %v gives permissions to anonymous users", [rolebinding.metadata.name]),
		"alertScore": 9,
		"deletePaths": [delete_path],
		"failedPaths": [delete_path],
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [rolebinding]},
	}
}

isAnonymous(subject) if {
	subject.name == "system:anonymous"
}

isAnonymous(subject) if {
	subject.name == "system:unauthenticated"
}
