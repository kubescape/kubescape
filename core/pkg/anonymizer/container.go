package anonymizer

import (

	corev1 "k8s.io/api/core/v1"

	"github.com/kubescape/k8s-interface/workloadinterface"
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

func anonymizePodSpecs(node interface{}, mapping *Mapping) {
	switch v := node.(type) {
	case map[string]interface{}:
		anonymizeContainerList(v, "containers", mapping)
		anonymizeContainerList(v, "initContainers", mapping)
		anonymizeEphemeralContainerList(v, "ephemeralContainers", mapping)

		for _, child := range v {
			anonymizePodSpecs(child, mapping)
		}

	case []interface{}:
		for _, item := range v {
			anonymizePodSpecs(item, mapping)
		}
	}
}

func anonymizeContainerFields(container map[string]interface{}, mapping *Mapping) {
	if name, ok := container["name"].(string); ok && name != "" {
		container["name"] = mapping.GetOrCreate("ctr", name)
	}

	if image, ok := container["image"].(string); ok && image != "" {
		container["image"] = mapping.GetOrCreate("img", image)
	}
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
