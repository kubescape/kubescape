package reportcrypto

import (
	"fmt"

	"github.com/kubescape/k8s-interface/workloadinterface"
	corev1 "k8s.io/api/core/v1"
)

// DecryptContainerMetadata restores encrypted container names and image
// references contained within a workload.
//
// This mirrors the traversal used during encryption while applying
// decryption to container-specific metadata.

func DecryptContainerMetadata(resource workloadinterface.IMetadata, dek []byte) error {

	if resource == nil {
		return nil
	}

	obj := resource.GetObject()
	if obj == nil {
		return nil
	}

	if err := decryptPodSpecs(obj, dek); err != nil {
		return err
	}

	resource.SetObject(obj)

	return nil
}

// decryptPodSpecs recursively traverses workload objects looking for
// pod-spec-shaped sections containing container metadata.
func decryptPodSpecs(node any, dek []byte) error {

	switch v := node.(type) {

	case map[string]any:
		if err := decryptContainerList(v, "containers", dek); err != nil {
			return err
		}

		if err := decryptContainerList(v, "initContainers", dek); err != nil {
			return err
		}

		if err := decryptEphemeralContainerList(v, "ephemeralContainers", dek); err != nil {
			return err
		}

		if err := decryptImagePullSecrets(v, dek); err != nil {
			return err
		}

		if err := decryptServiceAccountName(v, dek); err != nil {
			return err
		}

		for _, child := range v {
			if err := decryptPodSpecs(child, dek); err != nil {
				return err
			}
		}

	case []any:
		for _, item := range v {
			if err := decryptPodSpecs(item, dek); err != nil {
				return err
			}
		}
	}

	return nil
}

// decryptContainerFields restores encrypted container names and image
// references contained in an unstructured container definition.

func decryptContainerFields(container map[string]any, dek []byte) error {

	var err error

	if name, ok := container["name"].(string); ok && name != "" {
		name, err = decryptIfEncrypted(name, dek)
		if err != nil {
			return err
		}

		container["name"] = name
	}

	if image, ok := container["image"].(string); ok && image != "" {
		image, err = decryptIfEncrypted(image, dek)
		if err != nil {
			return err
		}

		container["image"] = image
	}

	if err := decryptUnstructuredEnv(container, dek); err != nil {
		return err
	}

	if err := decryptUnstructuredEnvFrom(container, dek); err != nil {
		return err
	}
	return nil
}

// decryptContainerList restores encrypted metadata for typed and
// unstructured containers.

func decryptContainerList(obj map[string]any, key string, dek []byte) error {

	rawContainers, ok := obj[key]
	if !ok || rawContainers == nil {
		return nil
	}

	var err error

	if containers, ok := rawContainers.([]corev1.Container); ok {

		for i := range containers {

			if containers[i].Name != "" {
				containers[i].Name, err =
					decryptIfEncrypted(containers[i].Name, dek)
				if err != nil {
					return fmt.Errorf("failed to decrypt container name: %w", err)
				}
			}

			if containers[i].Image != "" {
				containers[i].Image, err =
					decryptIfEncrypted(containers[i].Image, dek)
				if err != nil {
					return fmt.Errorf("failed to decrypt container image: %w", err)
				}
			}

			if err := decryptTypedEnv(containers[i].Env, dek); err != nil {
				return err
			}

			if err := decryptTypedEnvFrom(containers[i].EnvFrom, dek); err != nil {
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

			if err := decryptContainerFields(container, dek); err != nil {
				return err
			}
		}

		obj[key] = containers
	}

	return nil
}

// decryptEphemeralContainerList restores encrypted metadata for typed
// and unstructured ephemeral containers.

func decryptEphemeralContainerList(obj map[string]any, key string, dek []byte) error {

	rawContainers, ok := obj[key]
	if !ok || rawContainers == nil {
		return nil
	}

	var err error

	if containers, ok := rawContainers.([]corev1.EphemeralContainer); ok {

		for i := range containers {

			if containers[i].Name != "" {
				containers[i].Name, err =
					decryptIfEncrypted(containers[i].Name, dek)
				if err != nil {
					return fmt.Errorf("failed to decrypt ephemeral container name: %w", err)
				}
			}

			if containers[i].Image != "" {
				containers[i].Image, err =
					decryptIfEncrypted(containers[i].Image, dek)
				if err != nil {
					return fmt.Errorf("failed to decrypt ephemeral container image: %w", err)
				}
			}

			if err := decryptTypedEnv(containers[i].Env, dek); err != nil {
				return err
			}

			if err := decryptTypedEnvFrom(containers[i].EnvFrom, dek); err != nil {
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

			if err := decryptContainerFields(container, dek); err != nil {
				return err
			}
		}

		obj[key] = containers
	}

	return nil
}

// decryptTypedEnv restores encrypted environment variable values and
// referenced Kubernetes resources contained in typed EnvVar definitions.
//
// Literal environment values are decrypted only when they match the
// sensitivity rules used during encryption, while Secret and ConfigMap
// references are always decrypted when present.

func decryptTypedEnv(envVars []corev1.EnvVar, dek []byte) error {

	var err error

	for i := range envVars {
		envVar := &envVars[i]

		if envVar.Value != "" {
			envVar.Value, err = decryptIfEncrypted(envVar.Value, dek)
			if err != nil {
				return err
			}
		}

		if envVar.ValueFrom == nil {
			continue
		}

		if secretRef := envVar.ValueFrom.SecretKeyRef; secretRef != nil &&
			secretRef.Name != "" {

			secretRef.Name, err = decryptIfEncrypted(secretRef.Name, dek)
			if err != nil {
				return err
			}
		}

		if configMapRef := envVar.ValueFrom.ConfigMapKeyRef; configMapRef != nil &&
			configMapRef.Name != "" {

			configMapRef.Name, err = decryptIfEncrypted(configMapRef.Name, dek)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// decryptUnstructuredEnv restores encrypted environment variable values
// and referenced Kubernetes resources contained within unstructured
// container definitions.
//
// Literal environment values are decrypted only when they match the
// sensitivity rules used during encryption, while SecretKeyRef and
// ConfigMapKeyRef references are always decrypted when present.

func decryptUnstructuredEnv(container map[string]any, dek []byte) error {

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

		if value, ok := envVar["value"].(string); ok && value != "" {
			value, err = decryptIfEncrypted(value, dek)
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

		if err := decryptUnstructuredReference(valueFrom, "secretKeyRef", dek); err != nil {
			return err
		}

		if err := decryptUnstructuredReference(valueFrom, "configMapKeyRef", dek); err != nil {
			return err
		}
	}

	return nil
}

// decryptTypedEnvFrom restores encrypted resource references contained in
// typed EnvFromSource definitions.
//
// Secret and ConfigMap references are decrypted when present while
// preserving the original workload structure.

func decryptTypedEnvFrom(envFrom []corev1.EnvFromSource, dek []byte) error {

	var err error

	for i := range envFrom {
		source := &envFrom[i]

		if source.SecretRef != nil && source.SecretRef.Name != "" {
			source.SecretRef.Name, err = decryptIfEncrypted(source.SecretRef.Name, dek)
			if err != nil {
				return err
			}
		}

		if source.ConfigMapRef != nil && source.ConfigMapRef.Name != "" {
			source.ConfigMapRef.Name, err = decryptIfEncrypted(source.ConfigMapRef.Name, dek)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// decryptUnstructuredEnvFrom restores encrypted resource references
// contained in unstructured envFrom definitions.
//
// Secret and ConfigMap references are decrypted while preserving the
// original workload structure.

func decryptUnstructuredEnvFrom(container map[string]any, dek []byte) error {

	rawEnvFrom, ok := container["envFrom"].([]any)
	if !ok {
		return nil
	}

	for _, item := range rawEnvFrom {
		envFrom, ok := item.(map[string]any)
		if !ok {
			continue
		}

		if err := decryptUnstructuredReference(envFrom, "secretRef", dek); err != nil {
			return err
		}

		if err := decryptUnstructuredReference(envFrom, "configMapRef", dek); err != nil {
			return err
		}
	}

	return nil
}

// decryptUnstructuredReference restores the name field of an
// unstructured Kubernetes object reference.
//
// References that do not contain a name are left unchanged.

func decryptUnstructuredReference(obj map[string]any, key string, dek []byte) error {

	ref, ok := obj[key].(map[string]any)
	if !ok {
		return nil
	}

	name, ok := ref["name"].(string)
	if !ok || name == "" {
		return nil
	}

	decryptedName, err := decryptIfEncrypted(name, dek)
	if err != nil {
		return err
	}

	ref["name"] = decryptedName

	return nil
}

// decryptImagePullSecrets restores encrypted pod image pull secret
// references across both typed and unstructured workload
// representations.
//
// Image pull secret names are decrypted while preserving the original
// workload structure.

func decryptImagePullSecrets(obj map[string]any, dek []byte) error {

	rawRefs, ok := obj["imagePullSecrets"]
	if !ok || rawRefs == nil {
		return nil
	}

	var err error

	// Typed Kubernetes objects (manifest decoding path)
	if refs, ok := rawRefs.([]corev1.LocalObjectReference); ok {
		for i := range refs {
			if refs[i].Name != "" {
				refs[i].Name, err = decryptIfEncrypted(
					refs[i].Name,
					dek,
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

			name, err = decryptIfEncrypted(
				name,
				dek,
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

// decryptServiceAccountName restores encrypted pod-level service account
// references across both typed and unstructured workload
// representations.
//
// Service account names are decrypted while preserving the workload
// structure.

func decryptServiceAccountName(obj map[string]any, dek []byte) error {

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

		name, err = decryptIfEncrypted(
			name,
			dek,
		)
		if err != nil {
			return err
		}

		obj[key] = name
	}

	return nil
}
