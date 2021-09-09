package cautils

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/url"

	"github.com/armosec/kubescape/cautils/getter"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/armosec/kubescape/cautils/k8sinterface"
	corev1 "k8s.io/api/core/v1"
)

const (
	configMapName  = "kubescape"
	configFileName = "config"
)

type ConfigObj struct {
	CustomerGUID string `json:"customerGUID"`
	ClusterName  string `json:"clusterName"`
	Token        string `json:"token"`
}
type IClusterConfig interface {
	SetCustomerGUID()
	SetClusterName()

	GetCustomerGUID()
	GetClusterName()

	GenerateURL() string
}

type ClusterConfig struct {
	k8s       *k8sinterface.KubernetesApi
	defaultNS string
	armoAPI   *getter.ArmoAPI
	configObj *ConfigObj
}

func NewClusterConfig(k8s *k8sinterface.KubernetesApi, armoAPI *getter.ArmoAPI) *ClusterConfig {
	return &ClusterConfig{
		k8s:       k8s,
		armoAPI:   armoAPI,
		defaultNS: "default", // TODO - load default namespace from k8s api
	}
}
func (c *ClusterConfig) update(configObj *ConfigObj) {
	c.configObj = configObj
}
func (c *ClusterConfig) SetClusterName() {
	// k8sinterface.K8SConfig.
}
func (c *ClusterConfig) GenerateURL() string {
	u := url.URL{}
	u.Scheme = "https"
	u.Host = getter.ArmoFEURL
	u.Path = "account/signup"
	q := u.Query()
	q.Add("invitationToken", c.configObj.Token)
	q.Add("customerGUID", c.configObj.CustomerGUID)

	u.RawQuery = q.Encode()

	return u.String()
}
func (c *ClusterConfig) GetClusterName() string {
	return c.configObj.ClusterName
}
func (c *ClusterConfig) GetCustomerGUID() string {
	return c.configObj.CustomerGUID
}
func (c *ClusterConfig) SetCustomerGUID() error {

	// get from configMap
	if configObj, _ := c.loadConfigFromConfigMap(); configObj != nil {
		c.update(configObj)
		return nil
	}

	// get from file
	if configObj, _ := c.loadConfigFromFile(); configObj != nil {
		c.update(configObj)
		c.updateConfigMap()
		return nil
	}

	// get from armoBE
	if tenantResponse, err := c.armoAPI.GetCustomerGUID(); tenantResponse != nil {
		c.update(&ConfigObj{CustomerGUID: tenantResponse.TenantID, Token: tenantResponse.Token})
		return c.updateConfigMap()
	} else {
		return err
	}
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

func (c *ClusterConfig) updateConfigMap() error {
	configMap, err := c.k8s.KubernetesClient.CoreV1().ConfigMaps(c.defaultNS).Get(context.Background(), configMapName, metav1.GetOptions{})
	if err != nil {
		configMap = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name: configMapName,
			},
		}
	}

	c.updateConfigMapData(configMap)

	if err != nil {
		_, err = c.k8s.KubernetesClient.CoreV1().ConfigMaps(c.defaultNS).Create(context.Background(), configMap, metav1.CreateOptions{})
	} else {
		_, err = c.k8s.KubernetesClient.CoreV1().ConfigMaps(configMap.Namespace).Update(context.Background(), configMap, metav1.UpdateOptions{})
	}
	return err
}
func (c *ClusterConfig) updateConfigMapData(configMap *corev1.ConfigMap) {
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
func (c *ClusterConfig) loadConfigFromFile() (*ConfigObj, error) {
	dat, err := ioutil.ReadFile(configFileName)
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
