package anonymizer

import (
	"strings"

	"github.com/kubescape/k8s-interface/workloadinterface"
	corev1 "k8s.io/api/core/v1"
)

func anonymizeContainerMetadata(resource workloadinterface.IMetadata, mapping *Mapping) {
	if resource == nil {
		return
	}

	obj := resource.GetObject()
	if obj == nil {
		return
	}

	anonymizePodSpecs(obj, mapping)
	resource.SetObject(obj)
}

// anonymizePodSpecs recursively traverses workload objects looking for pod-spec
// shaped sections where container-related metadata may exist.
//
// Kubernetes resources may reach this layer as either typed objects converted
// into generic maps or as fully unstructured manifests depending on the scan source,
// so traversal stays representation-agnostic and delegates shape-specific handling
// to dedicated helpers.
func anonymizePodSpecs(node interface{}, mapping *Mapping) {
	switch v := node.(type) {
	case map[string]interface{}:
		anonymizeContainerList(v, "containers", mapping)
		anonymizeContainerList(v, "initContainers", mapping)
		anonymizeEphemeralContainerList(v, "ephemeralContainers", mapping)
		anonymizeImagePullSecrets(v, mapping)
		anonymizeServiceAccountName(v, mapping)

		for _, child := range v {
			anonymizePodSpecs(child, mapping)
		}

	case []interface{}:
		for _, item := range v {
			anonymizePodSpecs(item, mapping)
		}
	}
}

// anonymizeContainerFields handles unstructured container objects represented
// as map[string]interface{}.
func anonymizeContainerFields(container map[string]interface{}, mapping *Mapping) {
	if name, ok := container["name"].(string); ok && name != "" {
		container["name"] = mapping.GetOrCreate("ctr", name)
	}

	if image, ok := container["image"].(string); ok && image != "" {
		container["image"] = mapping.GetOrCreate("img", image)
	}

	anonymizeUnstructuredEnv(container, mapping)
	anonymizeUnstructuredEnvFrom(container, mapping)
}

func anonymizeContainerList(
	obj map[string]interface{},
	key string,
	mapping *Mapping,
) {
	rawContainers, ok := obj[key]
	if !ok || rawContainers == nil {
		return
	}

	if containers, ok := rawContainers.([]corev1.Container); ok {
		for i := range containers {
			if containers[i].Name != "" {
				containers[i].Name = mapping.GetOrCreate("ctr", containers[i].Name)
			}

			if containers[i].Image != "" {
				containers[i].Image = mapping.GetOrCreate("img", containers[i].Image)
			}

			anonymizeTypedEnv(containers[i].Env, mapping)
			anonymizeTypedEnvFrom(containers[i].EnvFrom, mapping)
		}

		obj[key] = containers
		return
	}

	if containers, ok := rawContainers.([]interface{}); ok {
		for _, item := range containers {
			container, ok := item.(map[string]interface{})
			if !ok {
				continue
			}

			anonymizeContainerFields(container, mapping)
		}

		obj[key] = containers
	}
}

func anonymizeEphemeralContainerList(
	obj map[string]interface{},
	key string,
	mapping *Mapping,
) {
	rawContainers, ok := obj[key]
	if !ok || rawContainers == nil {
		return
	}

	if containers, ok := rawContainers.([]corev1.EphemeralContainer); ok {
		for i := range containers {
			if containers[i].Name != "" {
				containers[i].Name = mapping.GetOrCreate("ctr", containers[i].Name)
			}

			if containers[i].Image != "" {
				containers[i].Image = mapping.GetOrCreate("img", containers[i].Image)
			}

			anonymizeTypedEnv(containers[i].Env, mapping)
			anonymizeTypedEnvFrom(containers[i].EnvFrom, mapping)
		}

		obj[key] = containers
		return
	}

	if containers, ok := rawContainers.([]interface{}); ok {
		for _, item := range containers {
			container, ok := item.(map[string]interface{})
			if !ok {
				continue
			}

			anonymizeContainerFields(container, mapping)
		}

		obj[key] = containers
	}
}

// anonymizeTypedEnv anonymizes literal env values and resource references
// inside typed EnvVar definitions.
func anonymizeTypedEnv(envVars []corev1.EnvVar, mapping *Mapping) {
	for i := range envVars {
		envVar := &envVars[i]

		if envVar.Value != "" &&
			(isSensitiveEnvName(envVar.Name) || isSensitiveEnvValue(envVar.Value)) {
			envVar.Value = mapping.GetOrCreate("env", envVar.Value)
		}

		if envVar.ValueFrom == nil {
			continue
		}

		if secretRef := envVar.ValueFrom.SecretKeyRef; secretRef != nil &&
			secretRef.Name != "" {
			secretRef.Name = mapping.GetOrCreate("ref", secretRef.Name)
		}

		if configMapRef := envVar.ValueFrom.ConfigMapKeyRef; configMapRef != nil &&
			configMapRef.Name != "" {
			configMapRef.Name = mapping.GetOrCreate("ref", configMapRef.Name)
		}
	}
}

// anonymizeUnstructuredEnv handles env entries in generic manifest maps.
func anonymizeUnstructuredEnv(container map[string]interface{}, mapping *Mapping) {
	rawEnv, exists := container["env"]
	if !exists || rawEnv == nil {
		return
	}

	envVars, ok := rawEnv.([]interface{})
	if !ok {
		return
	}

	for _, item := range envVars {
		envVar, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		name, _ := envVar["name"].(string)

		if value, ok := envVar["value"].(string); ok &&
			value != "" &&
			(isSensitiveEnvName(name) || isSensitiveEnvValue(value)) {
			envVar["value"] = mapping.GetOrCreate("env", value)
		}

		rawValueFrom, exists := envVar["valueFrom"]
		if !exists || rawValueFrom == nil {
			continue
		}

		valueFrom, ok := rawValueFrom.(map[string]interface{})
		if !ok {
			continue
		}

		anonymizeUnstructuredReference(valueFrom, "secretKeyRef", mapping)
		anonymizeUnstructuredReference(valueFrom, "configMapKeyRef", mapping)
	}
}

// anonymizeTypedEnvFrom anonymizes typed envFrom resource references.
func anonymizeTypedEnvFrom(envFrom []corev1.EnvFromSource, mapping *Mapping) {
	for i := range envFrom {
		source := &envFrom[i]

		if source.SecretRef != nil && source.SecretRef.Name != "" {
			source.SecretRef.Name = mapping.GetOrCreate(
				"ref",
				source.SecretRef.Name,
			)
		}

		if source.ConfigMapRef != nil && source.ConfigMapRef.Name != "" {
			source.ConfigMapRef.Name = mapping.GetOrCreate(
				"ref",
				source.ConfigMapRef.Name,
			)
		}
	}
}

// anonymizeUnstructuredEnvFrom handles envFrom entries in generic manifest maps.
func anonymizeUnstructuredEnvFrom(container map[string]interface{}, mapping *Mapping) {
	rawEnvFrom, ok := container["envFrom"].([]interface{})
	if !ok {
		return
	}

	for _, item := range rawEnvFrom {
		envFrom, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		anonymizeUnstructuredReference(envFrom, "secretRef", mapping)
		anonymizeUnstructuredReference(envFrom, "configMapRef", mapping)
	}
}

func anonymizeUnstructuredReference(
	obj map[string]interface{},
	key string,
	mapping *Mapping,
) {
	ref, ok := obj[key].(map[string]interface{})
	if !ok {
		return
	}

	name, ok := ref["name"].(string)
	if !ok || name == "" {
		return
	}

	ref["name"] = mapping.GetOrCreate("ref", name)
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

func anonymizeImagePullSecrets(
	obj map[string]interface{},
	mapping *Mapping,
) {
	rawRefs, ok := obj["imagePullSecrets"]
	if !ok || rawRefs == nil {
		return
	}

	// Typed Kubernetes objects (manifest decoding path)
	if refs, ok := rawRefs.([]corev1.LocalObjectReference); ok {
		for i := range refs {
			if refs[i].Name != "" {
				refs[i].Name = mapping.GetOrCreate("ref", refs[i].Name)
			}
		}

		obj["imagePullSecrets"] = refs
		return
	}

	// Unstructured objects (runtime / normalized object path)
	if refs, ok := rawRefs.([]interface{}); ok {
		for _, item := range refs {
			ref, ok := item.(map[string]interface{})
			if !ok {
				continue
			}

			name, ok := ref["name"].(string)
			if !ok || name == "" {
				continue
			}

			ref["name"] = mapping.GetOrCreate("ref", name)
		}

		obj["imagePullSecrets"] = refs
	}
}

// anonymizeServiceAccountName anonymizes pod-level service account references
// across both typed and unstructured workload representations.
func anonymizeServiceAccountName(
	obj map[string]interface{},
	mapping *Mapping,
) {
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

		obj[key] = mapping.GetOrCreate("sa", name)
	}
}
