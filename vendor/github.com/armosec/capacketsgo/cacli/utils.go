package cacli

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"

	"github.com/golang/glog"
)

func StoreObjTmpFile(obj interface{}) (string, error) {

	bet, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	file := fmt.Sprintf("/tmp/%d.json", rand.Int())
	if err := ioutil.WriteFile(file, bet, 0644); err != nil {
		return "", err
	}
	return file, nil
}

func DeleteObjTmpFile(path string) {
	// delete file
	var err = os.Remove(path)
	if err != nil {
		glog.Error(err)
	}
}

func SetArgs(wlid, cluster, namespace string, attributes map[string]string) []string {
	args := []string{}
	if wlid != "" {
		args = append(args, "--workload-id")
		args = append(args, wlid)
	}
	if cluster != "" {
		args = append(args, "--cluster")
		args = append(args, cluster)
	}
	if namespace != "" {
		args = append(args, "--namespace")
		args = append(args, namespace)
	}
	return args
}

func ConvertObjectTOFile(obj interface{}) (string, error) {
	if obj == nil {
		return "", fmt.Errorf("missing wt and fileName, you must provide one of them")
	}
	f, err := StoreObjTmpFile(obj)
	if err != nil {
		return "", err
	}
	return f, nil
}

func LoadCredentials() (*CredStruct, error) {
	credentials := CredStruct{}
	credentialsPath := getCredentialsPath()
	customer, err := ioutil.ReadFile(filepath.Join(credentialsPath, "customer"))
	if err != nil || len(customer) == 0 {
		glog.Warningf("'customer' not found in credentials secret. path: %s", filepath.Join(credentialsPath, "customer"))
	}
	credentials.Customer = string(customer)

	username, err := ioutil.ReadFile(filepath.Join(credentialsPath, "username"))
	if err != nil || len(username) == 0 {
		return nil, fmt.Errorf("'username' not found in credentials secret. path: %s", filepath.Join(credentialsPath, "username"))
	}
	credentials.User = string(username)

	password, err := ioutil.ReadFile(filepath.Join(credentialsPath, "password"))
	if err != nil || len(password) == 0 {
		return nil, fmt.Errorf("'password' not found in credentials secret. path: %s", filepath.Join(credentialsPath, "password"))
	}
	credentials.Password = string(password)

	return &credentials, nil
}
func getCredentialsPath() string {
	if credentialsPath := os.Getenv(DefaultCredentialsPathEnv); credentialsPath != "" {
		return credentialsPath
	}
	return DefaultCredentialsPath
}

func (cacli *Cacli) setCredentialsInEnv() error {
	if err := os.Setenv("CA_USERNAME", cacli.credentials.User); err != nil {
		return err
	}
	if err := os.Setenv("CA_PASSWORD", cacli.credentials.Password); err != nil {
		return err
	}
	if cacli.credentials.Customer != "" {
		if err := os.Setenv("CA_CUSTOMER", cacli.credentials.Customer); err != nil {
			return err
		}
	}
	return nil
}
