package k8sinterface

func PodSpec(kind string) []string {
	switch kind {
	case "Pod", "Namespace":
		return []string{"spec"}
	case "CronJob":
		return []string{"spec", "jobTemplate", "spec", "template", "spec"}
	default:
		return []string{"spec", "template", "spec"}
	}
}

func PodMetadata(kind string) []string {
	switch kind {
	case "Pod", "Namespace", "Secret":
		return []string{"metadata"}
	case "CronJob":
		return []string{"spec", "jobTemplate", "spec", "template", "metadata"}
	default:
		return []string{"spec", "template", "metadata"}
	}
}
