package cautils

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/armosec/kubescape/cautils/getter"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/armosec/kubescape/cautils/k8sinterface"
	corev1 "k8s.io/api/core/v1"
)

const (
	configMapName  = "kubescape"
	ConfigFileName = "config"
)

type ConfigObj struct {
	CustomerGUID       string `json:"customerGUID"`
	Token              string `json:"invitationParam"`
	CustomerAdminEMail string `json:"adminMail"`
}

func (co *ConfigObj) Json() []byte {
	if b, err := json.Marshal(co); err == nil {
		return b
	}
	return []byte{}
}

type IClusterConfig interface {
	SetCustomerGUID() error
	GetCustomerGUID() string
	GenerateURL()
}

type ClusterConfig struct {
	k8s       *k8sinterface.KubernetesApi
	defaultNS string
	armoAPI   *getter.ArmoAPI
	configObj *ConfigObj
}

type EmptyConfig struct {
}

func (c *EmptyConfig) GenerateURL() {
}

func (c *EmptyConfig) SetCustomerGUID() error {
	return nil
}

func (c *EmptyConfig) GetCustomerGUID() string {
	return ""
}

func NewEmptyConfig() *EmptyConfig {
	return &EmptyConfig{}
}

func NewClusterConfig(k8s *k8sinterface.KubernetesApi, armoAPI *getter.ArmoAPI) *ClusterConfig {
	return &ClusterConfig{
		k8s:       k8s,
		armoAPI:   armoAPI,
		defaultNS: k8sinterface.GetDefaultNamespace(),
	}
}
func createConfigJson() {
	os.WriteFile(getter.GetDefaultPath(ConfigFileName+".json"), nil, 0664)

}

func update(configObj *ConfigObj) {
	os.WriteFile(getter.GetDefaultPath(ConfigFileName+".json"), configObj.Json(), 0664)
}
func (c *ClusterConfig) GenerateURL() {
	u := url.URL{}
	u.Scheme = "https"
	u.Host = getter.ArmoFEURL
	if c.configObj == nil {
		return
	}
	if c.configObj.CustomerAdminEMail != "" {
		msgStr := fmt.Sprintf("To view all controls and get remediation's ask access permissions to %s from %s", u.String(), c.configObj.CustomerAdminEMail)
		InfoTextDisplay(os.Stdout, msgStr+"\n")
		return
	}
	u.Path = "account/sign-up"
	q := u.Query()
	q.Add("invitationToken", c.configObj.Token)
	q.Add("customerGUID", c.configObj.CustomerGUID)

	u.RawQuery = q.Encode()
	fmt.Println("To view all controls and get remediation's visit:")
	InfoTextDisplay(os.Stdout, u.String()+"\n")

}

func (c *ClusterConfig) GetCustomerGUID() string {
	if c.configObj != nil {
		return c.configObj.CustomerGUID
	}
	return ""
}

func (c *ClusterConfig) GetValueByKeyFromConfigMap(key string) (string, error) {

	configMap, err := c.k8s.KubernetesClient.CoreV1().ConfigMaps(c.defaultNS).Get(context.Background(), configMapName, metav1.GetOptions{})

	if err != nil {
		return "", err
	}
	if val, ok := configMap.Data[key]; ok {
		return val, nil
	} else {
		return "", fmt.Errorf("value does not exist")
	}

}

func GetValueFromConfigJson(key string) (string, error) {
	data, err := os.ReadFile(getter.GetDefaultPath(ConfigFileName + ".json"))
	if err != nil {
		return "", err
	}
	var obj map[string]interface{}
	err = json.Unmarshal(data, &obj)
	if val, ok := obj[key]; ok {
		return fmt.Sprint(val), nil
	} else {
		return "", fmt.Errorf("value does not exist")
	}

}

func SetKeyValueInConfigJson(key string, value string) error {
	data, err := os.ReadFile(getter.GetDefaultPath(ConfigFileName + ".json"))
	if err != nil {
		return err
	}
	var obj map[string]interface{}
	err = json.Unmarshal(data, &obj)

	if err != nil {
		return err
	}
	obj[key] = value
	newData, err := json.Marshal(obj)
	if err != nil {
		return err
	}

	return os.WriteFile(getter.GetDefaultPath(ConfigFileName+".json"), newData, 0664)

}

func (c *ClusterConfig) SetKeyValueInConfigmap(key string, value string) error {

	configMap, err := c.k8s.KubernetesClient.CoreV1().ConfigMaps(c.defaultNS).Get(context.Background(), configMapName, metav1.GetOptions{})
	if err != nil {
		configMap = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name: configMapName,
			},
		}
	}

	if len(configMap.Data) == 0 {
		configMap.Data = make(map[string]string)
	}

	configMap.Data[key] = value

	if err != nil {
		_, err = c.k8s.KubernetesClient.CoreV1().ConfigMaps(c.defaultNS).Create(context.Background(), configMap, metav1.CreateOptions{})
	} else {
		_, err = c.k8s.KubernetesClient.CoreV1().ConfigMaps(configMap.Namespace).Update(context.Background(), configMap, metav1.UpdateOptions{})
	}

	return err
}

func (c *ClusterConfig) SetCustomerGUID() error {

	// get from configMap
	if c.existsConfigMap() {
		c.configObj, _ = c.loadConfigFromConfigMap()
	} else if existsConfigJson() { // get from file
		c.configObj, _ = loadConfigFromFile()
	} else {
		c.createConfigMap()
		createConfigJson()
	}

	customerGUID := c.GetCustomerGUID()

	// get from armoBE
	tenantResponse, err := c.armoAPI.GetCustomerGUID(customerGUID)
	if err == nil && tenantResponse != nil {
		if tenantResponse.AdminMail != "" { // this customer already belongs to some user
			if existsConfigJson() {
				update(&ConfigObj{CustomerGUID: customerGUID, CustomerAdminEMail: tenantResponse.AdminMail})
			}
			if c.existsConfigMap() {
				c.configObj.CustomerAdminEMail = tenantResponse.AdminMail
				c.updateConfigMap()
			}
		} else {
			if existsConfigJson() {
				update(&ConfigObj{CustomerGUID: tenantResponse.TenantID, Token: tenantResponse.Token})
			}
			if c.existsConfigMap() {
				c.configObj = &ConfigObj{CustomerGUID: tenantResponse.TenantID, Token: tenantResponse.Token}
				c.updateConfigMap()
			}
		}
	} else {
		if err != nil && strings.Contains(err.Error(), "already exists") {
			return nil
		}
		return err
	}
	return nil
}

func (c *ClusterConfig) loadConfigFromConfigMap() (*ConfigObj, error) {
	if c.k8s == nil {
		return nil, nil
	}
	configMap, err := c.k8s.KubernetesClient.CoreV1().ConfigMaps(c.defaultNS).Get(context.Background(), configMapName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	if bData, err := json.Marshal(configMap.Data); err == nil {
		return readConfig(bData)
	}
	return nil, nil
}

func (c *ClusterConfig) existsConfigMap() bool {
	_, err := c.k8s.KubernetesClient.CoreV1().ConfigMaps(c.defaultNS).Get(context.Background(), configMapName, metav1.GetOptions{})
	return err == nil
}

func existsConfigJson() bool {
	_, err := os.ReadFile(getter.GetDefaultPath(ConfigFileName + ".json"))

	return err == nil

}

func (c *ClusterConfig) createConfigMap() error {
	if c.k8s == nil {
		return nil
	}
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: configMapName,
		},
	}
	c.updateConfigData(configMap)

	_, err := c.k8s.KubernetesClient.CoreV1().ConfigMaps(c.defaultNS).Create(context.Background(), configMap, metav1.CreateOptions{})
	return err
}

func (c *ClusterConfig) updateConfigMap() error {
	if c.k8s == nil {
		return nil
	}
	configMap, err := c.k8s.KubernetesClient.CoreV1().ConfigMaps(c.defaultNS).Get(context.Background(), configMapName, metav1.GetOptions{})

	if err != nil {
		return err
	}

	c.updateConfigData(configMap)

	_, err = c.k8s.KubernetesClient.CoreV1().ConfigMaps(configMap.Namespace).Update(context.Background(), configMap, metav1.UpdateOptions{})
	return err
}

func (c *ClusterConfig) updateConfigData(configMap *corev1.ConfigMap) {
	if len(configMap.Data) == 0 {
		configMap.Data = make(map[string]string)
	}
	m := c.ToMapString()
	for k, v := range m {
		if s, ok := v.(string); ok {
			configMap.Data[k] = s
		}
	}
}
func loadConfigFromFile() (*ConfigObj, error) {
	dat, err := os.ReadFile(getter.GetDefaultPath(ConfigFileName + ".json"))
	if err != nil {
		return nil, err
	}

	return readConfig(dat)
}
func readConfig(dat []byte) (*ConfigObj, error) {

	if len(dat) == 0 {
		return nil, nil
	}
	configObj := &ConfigObj{}
	err := json.Unmarshal(dat, configObj)

	return configObj, err
}
func (c *ClusterConfig) ToMapString() map[string]interface{} {
	m := map[string]interface{}{}
	bc, _ := json.Marshal(c.configObj)
	json.Unmarshal(bc, &m)
	return m
}
