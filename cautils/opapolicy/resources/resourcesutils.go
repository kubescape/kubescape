package resources

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/armosec/kubescape/cautils/k8sinterface"

	"github.com/golang/glog"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/util"
	"k8s.io/client-go/rest"
)

var (
	RegoDependenciesPath = "/resources/rego/dependencies"
)

type RegoDependenciesData struct {
	K8sConfig RegoK8sConfig `json:"k8sconfig"`
}

type RegoK8sConfig struct {
	Token         string `json:"token"`
	IP            string `json:"ip"`
	Host          string `json:"host"`
	Port          string `json:"port"`
	CrtFile       string `json:"crtfile"`
	ClientCrtFile string `json:"clientcrtfile"`
	ClientKeyFile string `json:"clientkeyfile"`
	// ClientKeyFile string `json:"crtfile"`
}

func NewRegoDependenciesDataMock() *RegoDependenciesData {
	return NewRegoDependenciesData(k8sinterface.GetK8sConfig())
}

func NewRegoDependenciesData(k8sConfig *rest.Config) *RegoDependenciesData {

	regoDependenciesData := RegoDependenciesData{
		K8sConfig: *NewRegoK8sConfig(k8sConfig),
	}
	return &regoDependenciesData
}
func NewRegoK8sConfig(k8sConfig *rest.Config) *RegoK8sConfig {

	host := k8sConfig.Host
	if host == "" {
		ip := os.Getenv("KUBERNETES_SERVICE_HOST")
		port := os.Getenv("KUBERNETES_SERVICE_PORT")
		host = fmt.Sprintf("https://%s:%s", ip, port)
	}

	token := ""
	if k8sConfig.BearerToken != "" {
		token = fmt.Sprintf("Bearer %s", k8sConfig.BearerToken)
	}

	// crtFile := os.Getenv("KUBERNETES_CRT_PATH")
	// if crtFile == "" {
	// 	crtFile = k8sConfig.CAFile
	// 	// crtFile = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	// }

	// glog.Infof("===========================================================================")
	// glog.Infof(fmt.Sprintf("%v", k8sConfig.String()))
	// glog.Infof("===========================================================================")

	regoK8sConfig := RegoK8sConfig{
		Token:         token,
		Host:          k8sConfig.Host,
		CrtFile:       k8sConfig.CAFile,
		ClientCrtFile: k8sConfig.CertFile,
		ClientKeyFile: k8sConfig.KeyFile,
	}
	return &regoK8sConfig
}
func (data *RegoDependenciesData) TOStorage() (storage.Store, error) {
	var jsonObj map[string]interface{}
	bytesData, err := json.Marshal(*data)
	if err != nil {
		return nil, err
	}
	// glog.Infof("RegoDependenciesData: %s", bytesData)
	if err := util.UnmarshalJSON(bytesData, &jsonObj); err != nil {
		return nil, err
	}
	return inmem.NewFromObject(jsonObj), nil
}

// LoadRegoDependenciesFromDir loads the policies list from *.rego file in given directory
func LoadRegoFiles(dir string) map[string]string {

	modules := make(map[string]string)

	// Compile the module. The keys are used as identifiers in error messages.
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err == nil && strings.HasSuffix(path, ".rego") && !info.IsDir() {
			content, err := ioutil.ReadFile(path)
			if err != nil {
				glog.Errorf("LoadRegoFiles, Failed to load: %s: %v", path, err)
			} else {
				modules[strings.Trim(filepath.Base(path), ".rego")] = string(content)
			}
		}
		return nil
	})

	return modules
}

// LoadRegoModules loads the policies from variables
func LoadRegoModules() map[string]string {

	modules := make(map[string]string)
	modules["cautils"] = RegoCAUtils
	modules["designators"] = RegoDesignators
	modules["kubernetes.api.client"] = RegoKubernetesApiClient

	return modules
}
