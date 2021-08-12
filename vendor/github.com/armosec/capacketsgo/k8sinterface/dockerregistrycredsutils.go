package k8sinterface

import (
	"context"
	"fmt"

	"github.com/armosec/capacketsgo/secrethandling"
	"github.com/docker/docker/api/types"
	"github.com/golang/glog"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func listPodImagePullSecrets(pod *corev1.Pod) ([]string, error) {
	if pod == nil {
		return []string{}, fmt.Errorf("in listPodImagePullSecrets pod is nil")
	}
	secrets := []string{}
	for _, i := range pod.Spec.ImagePullSecrets {
		secrets = append(secrets, i.Name)
	}
	return secrets, nil
}

func listServiceAccountImagePullSecrets(k8sAPI *KubernetesApi, pod *corev1.Pod) ([]string, error) {
	if pod == nil {
		return []string{}, fmt.Errorf("in listServiceAccountImagePullSecrets pod is nil")
	}
	secrets := []string{}
	serviceAccountName := pod.Spec.ServiceAccountName
	if serviceAccountName == "" {
		return secrets, nil
	}

	serviceAccount, err := k8sAPI.KubernetesClient.CoreV1().ServiceAccounts(pod.ObjectMeta.Namespace).Get(k8sAPI.Context, serviceAccountName, metav1.GetOptions{})
	if err != nil {
		return secrets, fmt.Errorf("in listServiceAccountImagePullSecrets failed to get ServiceAccounts: %v", err)
	}
	for i := range serviceAccount.ImagePullSecrets {
		secrets = append(secrets, serviceAccount.ImagePullSecrets[i].Name)
	}
	return secrets, nil
}

func getImagePullSecret(k8sAPI *KubernetesApi, secrets []string, namespace string) map[string]types.AuthConfig {

	secretsAuthConfig := make(map[string]types.AuthConfig)

	for i := range secrets {
		res, err := k8sAPI.KubernetesClient.CoreV1().Secrets(namespace).Get(context.Background(), secrets[i], metav1.GetOptions{})
		if err != nil {
			glog.Errorf("%s", err.Error())
			continue
		}
		sec, err := secrethandling.ParseSecret(res, secrets[i])
		if err == nil {
			secretsAuthConfig[secrets[i]] = *sec
		} else {
			glog.Errorf("unable to get secret: %s", err.Error())
		}

	}

	// glog.Infof("secrets array: %v", secretsAuthConfig)
	return secretsAuthConfig
}

// GetImageRegistryCredentials returns various credentials for images in the pod
// imageTag empty means returns all of the credentials for all images in pod spec containers
// pod.ObjectMeta.Namespace must be well setted
func GetImageRegistryCredentials(imageTag string, pod *corev1.Pod) (map[string]types.AuthConfig, error) {
	k8sAPI := NewKubernetesApi()
	listSecret, _ := listPodImagePullSecrets(pod)
	listServiceSecret, _ := listServiceAccountImagePullSecrets(k8sAPI, pod)
	listSecret = append(listSecret, listServiceSecret...)
	secrets := getImagePullSecret(k8sAPI, listSecret, pod.ObjectMeta.Namespace)

	if len(secrets) == 0 {
		secrets = make(map[string]types.AuthConfig)
	}

	if imageTag != "" {
		cloudVendorSecrets, err := GetCloudVendorRegistryCredentials(imageTag)
		if err != nil {
			glog.Errorf("Failed to GetCloudVendorRegistryCredentials(%s): %v", imageTag, err)

		} else if len(cloudVendorSecrets) > 0 {
			for secName := range cloudVendorSecrets {
				secrets[secName] = cloudVendorSecrets[secName]
			}
		}
	} else {
		for contIdx := range pod.Spec.Containers {
			imageTag := pod.Spec.Containers[contIdx].Image
			glog.Infof("GetCloudVendorRegistryCredentials for image: %v", imageTag)
			cloudVendorSecrets, err := GetCloudVendorRegistryCredentials(imageTag)
			if err != nil {
				glog.Errorf("Failed to GetCloudVendorRegistryCredentials(%s): %v", imageTag, err)

			} else if len(cloudVendorSecrets) > 0 {
				for secName := range cloudVendorSecrets {
					secrets[secName] = cloudVendorSecrets[secName]
				}
			}
		}
	}

	return secrets, nil
}
