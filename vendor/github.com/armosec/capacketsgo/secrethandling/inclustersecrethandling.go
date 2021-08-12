package secrethandling

import (
	"context"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/golang/glog"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// DockerConfigJsonstructure -
type DockerConfigJsonstructure map[string]map[string]types.AuthConfig

func updateSecret(authConfig *types.AuthConfig, serverAddress string) {
	if authConfig.ServerAddress == "" {
		authConfig.ServerAddress = serverAddress
	}
	if authConfig.Username == "" || authConfig.Password == "" {
		glog.Infof("secret missing user name or password, using auth")
		auth := authConfig.Auth
		decodedAuth, err := b64.StdEncoding.DecodeString(auth)
		if err != nil {
			glog.Errorf("error: %s", err.Error())
			return
		}

		splittedAuth := strings.Split(string(decodedAuth), ":")
		if len(splittedAuth) == 2 {
			authConfig.Username = splittedAuth[0]
			authConfig.Password = splittedAuth[1]
		}
	}
	if authConfig.Auth == "" {
		auth := fmt.Sprintf("%s:%s", authConfig.Username, authConfig.Password)
		authConfig.Auth = b64.StdEncoding.EncodeToString([]byte(auth))
	}
}

func parseEncodedSecret(sec map[string][]byte) (string, string) {
	buser := sec[corev1.BasicAuthUsernameKey]
	bpsw := sec[corev1.BasicAuthPasswordKey]
	duser, _ := b64.StdEncoding.DecodeString(string(buser))
	dpsw, _ := b64.StdEncoding.DecodeString(string(bpsw))
	return string(duser), string(dpsw)

}
func parseDecodedSecret(sec map[string]string) (string, string) {
	user := sec[corev1.BasicAuthUsernameKey]
	psw := sec[corev1.BasicAuthPasswordKey]
	return user, psw

}

// ReadSecret -
func ReadSecret(secret interface{}, secretName string) (types.AuthConfig, error) {
	// Store secret based on it's structure
	var authConfig types.AuthConfig
	if sec, ok := secret.(*types.AuthConfig); ok {
		return *sec, nil
	}
	if sec, ok := secret.(map[string]string); ok {
		return types.AuthConfig{Username: sec["username"]}, nil
	}
	if sec, ok := secret.(DockerConfigJsonstructure); ok {
		if _, k := sec["auths"]; !k {
			return authConfig, fmt.Errorf("cant find auths")
		}
		for serverAddress, authConfig := range sec["auths"] {
			updateSecret(&authConfig, serverAddress)
			return authConfig, nil
		}
	}

	return authConfig, fmt.Errorf("cant find secret")
}

func GetSecret(clientset *kubernetes.Clientset, namespace, name string) (*types.AuthConfig, error) {
	res, err := clientset.CoreV1().Secrets(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		glog.Errorf("%v", err)
	}

	// Read secret
	secret, err := GetSecretContent(res)
	if err != nil {
		glog.Error(err)
		return nil, err
	}

	if secret == nil {
		err := fmt.Errorf("secret %s not found", name)
		glog.Error(err)
		return nil, err
	}
	sec, err := ReadSecret(secret, name)
	if err != nil {
		return &sec, err
	}
	return &sec, nil

}

// GetSecretContent -
func GetSecretContent(secret *corev1.Secret) (interface{}, error) {

	// Secret types- https://github.com/kubernetes/kubernetes/blob/7693a1d5fe2a35b6e2e205f03ae9b3eddcdabc6b/pkg/apis/core/types.go#L4394-L4478
	switch secret.Type {
	case corev1.SecretTypeDockerConfigJson:
		sec := make(DockerConfigJsonstructure)
		if err := json.Unmarshal(secret.Data[corev1.DockerConfigJsonKey], &sec); err != nil {
			return nil, err
		}
		return sec, nil
	default:
		user, psw := "", ""
		if len(secret.Data) != 0 {
			user, psw = parseEncodedSecret(secret.Data)
		} else if len(secret.StringData) != 0 {
			userD, pswD := parseDecodedSecret(secret.StringData)
			if userD != "" {
				user = userD
			}
			if pswD != "" {
				psw = pswD
			}
		} else {
			return nil, fmt.Errorf("data not found in secret")
		}
		if user == "" || psw == "" {
			return nil, fmt.Errorf("username  or password not found")
		}

		return &types.AuthConfig{Username: user, Password: psw}, nil
	}
}

func ParseSecret(res *corev1.Secret, name string) (*types.AuthConfig, error) {

	// Read secret
	secret, err := GetSecretContent(res)
	if err != nil {
		glog.Error(err)
		return nil, err
	}

	if secret == nil {
		err := fmt.Errorf("secret %s not found", name)
		glog.Error(err)
		return nil, err
	}
	sec, err := ReadSecret(secret, name)
	if err != nil {
		return &sec, err
	}
	return &sec, nil

}
