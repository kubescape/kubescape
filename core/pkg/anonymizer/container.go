package anonymizer

import (
	"strings"

	"github.com/kubescape/k8s-interface/workloadinterface"
	corev1 "k8s.io/api/core/v1"
)

func transformContainerMetadata(resource workloadinterface.IMetadata, transformer Transformer) error {

	if resource == nil {
		return nil
	}

	obj := resource.GetObject()
	if obj == nil {
		return nil
	}

	if err := transformPodSpecs(obj, transformer); err != nil {
		return err
	}

	resource.SetObject(obj)

	return nil
}

// transformPodSpecs recursively traverses workload objects looking for
// pod-spec-shaped sections where sensitive container metadata may exist.
//
// Kubernetes resources may reach this layer as either typed objects converted
// into generic maps or as fully unstructured manifests depending on the scan
// source, so traversal stays representation-agnostic and delegates
// shape-specific transformations to dedicated helpers.
func transformPodSpecs(node any, transformer Transformer) error {

	switch v := node.(type) {
	case map[string]any:
		if err := transformContainerList(
			v,
			"containers",
			transformer,
		); err != nil {
			return err
		}

		if err := transformContainerList(
			v,
			"initContainers",
			transformer,
		); err != nil {
			return err
		}

		if err := transformEphemeralContainerList(
			v,
			"ephemeralContainers",
			transformer,
		); err != nil {
			return err
		}

		if err := transformImagePullSecrets(
			v,
			transformer,
		); err != nil {
			return err
		}

		if err := transformServiceAccountName(
			v,
			transformer,
		); err != nil {
			return err
		}

		for _, child := range v {
			if err := transformPodSpecs(
				child,
				transformer,
			); err != nil {
				return err
			}
		}

	case []any:
		for _, item := range v {
			if err := transformPodSpecs(
				item,
				transformer,
			); err != nil {
				return err
			}
		}
	}

	return nil
}

// transformContainerFields applies the supplied Transformer to sensitive
// fields within an unstructured container represented as a
// map[string]any.
//
// This helper preserves the existing traversal behavior while allowing
// callers to choose between deterministic pseudonymization
// (MappingTransformer) and (EncryptionTransformer) provided with a Transformer abstraction above .
func transformContainerFields(container map[string]any, transformer Transformer) error {

	var err error

	if name, ok := container["name"].(string); ok && name != "" {
		name, err = transformValue(transformer, "ctr", name)
		if err != nil {
			return err
		}

		container["name"] = name
	}

	if image, ok := container["image"].(string); ok && image != "" {
		image, err = transformValue(transformer, "img", image)
		if err != nil {
			return err
		}

		container["image"] = image
	}

	if err := transformUnstructuredEnv(container, transformer); err != nil {
		return err
	}

	if err := transformUnstructuredEnvFrom(container, transformer); err != nil {
		return err
	}

	return nil
}

func transformContainerList(obj map[string]any, key string, transformer Transformer) error {

	rawContainers, ok := obj[key]
	if !ok || rawContainers == nil {
		return nil
	}

	var err error

	if containers, ok := rawContainers.([]corev1.Container); ok {
		for i := range containers {

			if containers[i].Name != "" {
				containers[i].Name, err = transformValue(transformer, "ctr", containers[i].Name)
				if err != nil {
					return err
				}
			}

			if containers[i].Image != "" {
				containers[i].Image, err = transformValue(transformer, "img", containers[i].Image)
				if err != nil {
					return err
				}
			}

			if err := transformTypedEnv(containers[i].Env, transformer); err != nil {
				return err
			}

			if err := transformTypedEnvFrom(containers[i].EnvFrom, transformer); err != nil {
				return err
			}
		}

		obj[key] = containers
		return nil
	}

	if containers, ok := rawContainers.([]any); ok {
		for _, item := range containers {
			container, ok := item.(map[string]any)
			if !ok {
				continue
			}

			if err := transformContainerFields(container, transformer); err != nil {
				return err
			}
		}

		obj[key] = containers
	}

	return nil
}

// transformEphemeralContainerList applies the supplied Transformer to
// ephemeral container metadata across both typed and unstructured
// workload representations.
//
// Container identifiers, image references, environment variables, and
// referenced Kubernetes resources are transformed while preserving the
// original workload structure.
func transformEphemeralContainerList(obj map[string]any, key string, transformer Transformer) error {

	rawContainers, ok := obj[key]
	if !ok || rawContainers == nil {
		return nil
	}

	var err error

	if containers, ok := rawContainers.([]corev1.EphemeralContainer); ok {
		for i := range containers {

			if containers[i].Name != "" {
				containers[i].Name, err = transformValue(transformer, "ctr", containers[i].Name)
				if err != nil {
					return err
				}
			}

			if containers[i].Image != "" {
				containers[i].Image, err = transformValue(transformer, "img", containers[i].Image)
				if err != nil {
					return err
				}
			}

			if err := transformTypedEnv(containers[i].Env, transformer); err != nil {
				return err
			}

			if err := transformTypedEnvFrom(containers[i].EnvFrom, transformer); err != nil {
				return err
			}
		}

		obj[key] = containers
		return nil
	}

	if containers, ok := rawContainers.([]any); ok {
		for _, item := range containers {
			container, ok := item.(map[string]any)
			if !ok {
				continue
			}

			if err := transformContainerFields(container, transformer); err != nil {
				return err
			}
		}

		obj[key] = containers
	}

	return nil
}

// transformTypedEnv applies the supplied Transformer to sensitive
// environment variable values and referenced Kubernetes resources.
//
// Literal environment values are transformed only when they appear
// sensitive, while Secret and ConfigMap references are always
// transformed when present.
func transformTypedEnv(envVars []corev1.EnvVar, transformer Transformer) error {
	var err error

	for i := range envVars {
		envVar := &envVars[i]

		if envVar.Value != "" &&
			(isSensitiveEnvName(envVar.Name) ||
				isSensitiveEnvValue(envVar.Value)) {

			envVar.Value, err = transformValue(
				transformer,
				"env",
				envVar.Value,
			)
			if err != nil {
				return err
			}
		}

		if envVar.ValueFrom == nil {
			continue
		}

		if secretRef := envVar.ValueFrom.SecretKeyRef; secretRef != nil &&
			secretRef.Name != "" {

			secretRef.Name, err = transformValue(transformer, "ref", secretRef.Name)
			if err != nil {
				return err
			}
		}

		if configMapRef := envVar.ValueFrom.ConfigMapKeyRef; configMapRef != nil &&
			configMapRef.Name != "" {

			configMapRef.Name, err = transformValue(transformer, "ref", configMapRef.Name)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// transformUnstructuredEnv applies the supplied Transformer to sensitive
// environment variable values and referenced Kubernetes resources within
// unstructured container definitions.
// Literal environment values are transformed only when they appear
// sensitive, while SecretKeyRef and ConfigMapKeyRef references are
// transformed whenever present.

func transformUnstructuredEnv(container map[string]any, transformer Transformer) error {

	rawEnv, exists := container["env"]
	if !exists || rawEnv == nil {
		return nil
	}

	envVars, ok := rawEnv.([]any)
	if !ok {
		return nil
	}

	var err error

	for _, item := range envVars {
		envVar, ok := item.(map[string]any)
		if !ok {
			continue
		}

		name, _ := envVar["name"].(string)

		if value, ok := envVar["value"].(string); ok &&
			value != "" &&
			(isSensitiveEnvName(name) ||
				isSensitiveEnvValue(value)) {

			value, err = transformValue(transformer, "env", value)
			if err != nil {
				return err
			}

			envVar["value"] = value
		}

		rawValueFrom, exists := envVar["valueFrom"]
		if !exists || rawValueFrom == nil {
			continue
		}

		valueFrom, ok := rawValueFrom.(map[string]any)
		if !ok {
			continue
		}

		if err := transformUnstructuredReference(valueFrom, "secretKeyRef", transformer); err != nil {
			return err
		}

		if err := transformUnstructuredReference(valueFrom, "configMapKeyRef", transformer); err != nil {
			return err
		}
	}

	return nil
}

// transformTypedEnvFrom applies the supplied Transformer to resource
// references contained in typed EnvFromSource definitions.
//
// Secret and ConfigMap references are transformed when present while
// preserving the original workload structure.
func transformTypedEnvFrom(envFrom []corev1.EnvFromSource, transformer Transformer) error {
	var err error

	for i := range envFrom {
		source := &envFrom[i]

		if source.SecretRef != nil && source.SecretRef.Name != "" {
			source.SecretRef.Name, err = transformValue(transformer, "ref", source.SecretRef.Name)
			if err != nil {
				return err
			}
		}

		if source.ConfigMapRef != nil && source.ConfigMapRef.Name != "" {
			source.ConfigMapRef.Name, err = transformValue(transformer, "ref", source.ConfigMapRef.Name)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// transformUnstructuredEnvFrom applies the supplied Transformer to
// resource references contained in unstructured envFrom definitions.
//
// Secret and ConfigMap references are transformed while preserving the
// original workload structure.
func transformUnstructuredEnvFrom(container map[string]any, transformer Transformer) error {

	rawEnvFrom, ok := container["envFrom"].([]any)
	if !ok {
		return nil
	}

	for _, item := range rawEnvFrom {
		envFrom, ok := item.(map[string]any)
		if !ok {
			continue
		}

		if err := transformUnstructuredReference(envFrom, "secretRef", transformer); err != nil {
			return err
		}

		if err := transformUnstructuredReference(envFrom, "configMapRef", transformer); err != nil {
			return err
		}
	}

	return nil
}

// transformUnstructuredReference applies the supplied Transformer to the
// name field of an unstructured Kubernetes object reference.
//
// References that do not contain a name are left unchanged.
func transformUnstructuredReference(obj map[string]any, key string, transformer Transformer) error {
	ref, ok := obj[key].(map[string]any)
	if !ok {
		return nil
	}

	name, ok := ref["name"].(string)
	if !ok || name == "" {
		return nil
	}

	transformedName, err := transformValue(transformer, "ref", name)
	if err != nil {
		return err
	}

	ref["name"] = transformedName

	return nil
}

// isSensitiveEnvValue reports whether an env var value looks like a secret.
func isSensitiveEnvValue(value string) bool {
	value = strings.ToLower(value)

	sensitivePatterns := []string{
		"://", // postgres:// redis:// mongodb:// etc
		"password=",
		"pwd=",
		"user id=",
		"userid=",
		"dsn=",
		"sslmode=",
	}

	for _, pattern := range sensitivePatterns {
		if strings.Contains(value, pattern) {
			return true
		}
	}

	return false
}

// isSensitiveEnvName reports whether an env var name looks like a credential.
func isSensitiveEnvName(name string) bool {
	name = strings.ToLower(name)

	// strip common separators so APIKEY matches api_key
	normalized := name
	for _, sep := range []string{"_", "-", ".", " "} {
		normalized = strings.ReplaceAll(normalized, sep, "")
	}

	sensitivePatterns := []string{
		"password",
		"passwd",
		"pwd",
		"secret",
		"token",
		"apikey",
		"accesskey",
		"privatekey",
		"credential",
		"databaseurl",
		"dburl",
		"redisurl",
		"mongouri",
		"mongodburi",
		"dsn",
		"connectionstring",
	}

	for _, pattern := range sensitivePatterns {
		if strings.Contains(normalized, pattern) {
			return true
		}
	}

	return false
}

// transformImagePullSecrets applies the supplied Transformer to pod image
// pull secret references across both typed and unstructured workload
// representations.
// Image pull secret names are transformed while preserving the original
// workload structure.
func transformImagePullSecrets(obj map[string]any, transformer Transformer) error {

	rawRefs, ok := obj["imagePullSecrets"]
	if !ok || rawRefs == nil {
		return nil
	}

	var err error

	// Typed Kubernetes objects (manifest decoding path)
	if refs, ok := rawRefs.([]corev1.LocalObjectReference); ok {
		for i := range refs {
			if refs[i].Name != "" {
				refs[i].Name, err = transformValue(
					transformer,
					"ref",
					refs[i].Name,
				)
				if err != nil {
					return err
				}
			}
		}

		obj["imagePullSecrets"] = refs
		return nil
	}

	// Unstructured objects (runtime / normalized object path)
	if refs, ok := rawRefs.([]any); ok {
		for _, item := range refs {
			ref, ok := item.(map[string]any)
			if !ok {
				continue
			}

			name, ok := ref["name"].(string)
			if !ok || name == "" {
				continue
			}

			name, err = transformValue(
				transformer,
				"ref",
				name,
			)
			if err != nil {
				return err
			}

			ref["name"] = name
		}

		obj["imagePullSecrets"] = refs
	}

	return nil
}

// transformServiceAccountName applies the supplied Transformer to pod-level
// service account references across both typed and unstructured workload
// representations.
//
// Service account names are transformed while preserving the workload
// structure.
func transformServiceAccountName(obj map[string]any, transformer Transformer) error {

	var err error

	for _, key := range []string{
		"serviceAccountName",
		"serviceAccount",
	} {
		rawName, ok := obj[key]
		if !ok || rawName == nil {
			continue
		}

		name, ok := rawName.(string)
		if !ok || name == "" {
			continue
		}

		name, err = transformValue(transformer, "sa", name)
		if err != nil {
			return err
		}

		obj[key] = name
	}

	return nil
}
