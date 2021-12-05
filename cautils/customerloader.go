package cautils

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/kubescape/cautils/getter"
	corev1 "k8s.io/api/core/v1"
)

const (
	configMapName  = "kubescape"
	configFileName = "config"
)

func ConfigFileFullPath() string { return getter.GetDefaultPath(configFileName + ".json") }

// ======================================================================================
// =============================== Config structure =====================================
// ======================================================================================

type ConfigObj struct {
	CustomerGUID       string `json:"customerGUID"`
	Token              string `json:"invitationParam"`
	CustomerAdminEMail string `json:"adminMail"`
	ClusterName        string `json:"clusterName"`
}

func (co *ConfigObj) Json() []byte {
	if b, err := json.Marshal(co); err == nil {
		return b
	}
	return []byte{}
}

// Config - convert ConfigObj to config file
func (co *ConfigObj) Config() []byte {
	clusterName := co.ClusterName
	co.ClusterName = "" // remove cluster name before saving to file
	b, err := json.Marshal(co)
	co.ClusterName = clusterName

	if err == nil {
		return b
	}

	return []byte{}
}

// ======================================================================================
// =============================== interface ============================================
// ======================================================================================
type ITenantConfig interface {
	// set
	SetTenant() error

	// getters
	GetClusterName() string
	GetCustomerGUID() string
	GetConfigObj() *ConfigObj
	// GetBackendAPI() getter.IBackend
	// GenerateURL()

	IsConfigFound() bool
}

// ======================================================================================
// ============================ Local Config ============================================
// ======================================================================================
// Config when scanning YAML files or URL but not a Kubernetes cluster
type LocalConfig struct {
	backendAPI getter.IBackend
	configObj  *ConfigObj
}

func NewLocalConfig(backendAPI getter.IBackend, customerGUID string) *LocalConfig {
	var configObj *ConfigObj

	lc := &LocalConfig{
		backendAPI: backendAPI,
		configObj:  &ConfigObj{},
	}
	// get from configMap
	if existsConfigFile() { // get from file
		configObj, _ = loadConfigFromFile()
	} else {
		configObj = &ConfigObj{}
	}
	if configObj != nil {
		lc.configObj = configObj
	}
	if customerGUID != "" {
		lc.configObj.CustomerGUID = customerGUID // override config customerGUID
	}
	if lc.configObj.CustomerGUID != "" {
		if err := lc.SetTenant(); err != nil {
			fmt.Println(err)
		}
	}

	return lc
}

func (lc *LocalConfig) GetConfigObj() *ConfigObj { return lc.configObj }
func (lc *LocalConfig) GetCustomerGUID() string  { return lc.configObj.CustomerGUID }
func (lc *LocalConfig) GetClusterName() string   { return "" }
func (lc *LocalConfig) IsConfigFound() bool      { return existsConfigFile() }
func (lc *LocalConfig) SetTenant() error {
	// ARMO tenant GUID
	if err := getTenantConfigFromBE(lc.backendAPI, lc.configObj); err != nil {
		return err
	}
	updateConfigFile(lc.configObj)
	return nil

}

func getTenantConfigFromBE(backendAPI getter.IBackend, configObj *ConfigObj) error {

	// get from armoBE
	tenantResponse, err := backendAPI.GetCustomerGUID(configObj.CustomerGUID)
	if err == nil && tenantResponse != nil {
		if tenantResponse.AdminMail != "" { // registered tenant
			configObj.CustomerAdminEMail = tenantResponse.AdminMail
		} else { // new tenant
			configObj.Token = tenantResponse.Token
			configObj.CustomerGUID = tenantResponse.TenantID
		}
	} else {
		if err != nil && !strings.Contains(err.Error(), "already exists") {
			return err
		}
	}

	return nil
}

// ======================================================================================
// ========================== Cluster Config ============================================
// ======================================================================================

type ClusterConfig struct {
	k8s        *k8sinterface.KubernetesApi
	defaultNS  string
	backendAPI getter.IBackend
	configObj  *ConfigObj
}

func NewClusterConfig(k8s *k8sinterface.KubernetesApi, backendAPI getter.IBackend, customerGUID string) *ClusterConfig {
	defaultNS := k8sinterface.GetDefaultNamespace()
	var configObj *ConfigObj
	c := &ClusterConfig{
		k8s:        k8s,
		backendAPI: backendAPI,
		configObj:  &ConfigObj{},
		defaultNS:  defaultNS,
	}

	// get from configMap
	if existsConfigMap(k8s, defaultNS) {
		configObj, _ = loadConfigFromConfigMap(k8s, defaultNS)
	} else if existsConfigFile() { // get from file
		configObj, _ = loadConfigFromFile()
	}
	if configObj != nil {
		c.configObj = configObj
	}
	if customerGUID != "" {
		c.configObj.CustomerGUID = customerGUID // override config customerGUID
	}
	if c.configObj.CustomerGUID != "" {
		if err := c.SetTenant(); err != nil {
			fmt.Println(err)
		}
	}
	if c.configObj.ClusterName == "" {
		c.configObj.ClusterName = adoptClusterName(k8sinterface.GetClusterName())
	}

	return c
}

func (c *ClusterConfig) GetConfigObj() *ConfigObj { return c.configObj }
func (c *ClusterConfig) GetDefaultNS() string     { return c.defaultNS }
func (c *ClusterConfig) GetCustomerGUID() string  { return c.configObj.CustomerGUID }
func (c *ClusterConfig) IsConfigFound() bool {
	return existsConfigFile() || existsConfigMap(c.k8s, c.defaultNS)
}

func (c *ClusterConfig) SetTenant() error {

	// ARMO tenant GUID
	if err := getTenantConfigFromBE(c.backendAPI, c.configObj); err != nil {
		return err
	}
	// update/create config
	if existsConfigMap(c.k8s, c.defaultNS) {
		c.updateConfigMap()
	} else {
		c.createConfigMap()
	}
	updateConfigFile(c.configObj)
	return nil

}

func (c *ClusterConfig) GetClusterName() string {
	return c.configObj.ClusterName
}

func (c *ClusterConfig) ToMapString() map[string]interface{} {
	m := map[string]interface{}{}
	if bc, err := json.Marshal(c.configObj); err == nil {
		json.Unmarshal(bc, &m)
	}
	return m
}
func loadConfigFromConfigMap(k8s *k8sinterface.KubernetesApi, ns string) (*ConfigObj, error) {
	configMap, err := k8s.KubernetesClient.CoreV1().ConfigMaps(ns).Get(context.Background(), configMapName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	if bData, err := json.Marshal(configMap.Data); err == nil {
		return readConfig(bData)
	}
	return nil, nil
}

func existsConfigMap(k8s *k8sinterface.KubernetesApi, ns string) bool {
	_, err := k8s.KubernetesClient.CoreV1().ConfigMaps(ns).Get(context.Background(), configMapName, metav1.GetOptions{})
	// TODO - check if has customerGUID
	return err == nil
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
	data, err := os.ReadFile(ConfigFileFullPath())
	if err != nil {
		return "", err
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return "", err
	}
	if val, ok := obj[key]; ok {
		return fmt.Sprint(val), nil
	} else {
		return "", fmt.Errorf("value does not exist")
	}

}

func SetKeyValueInConfigJson(key string, value string) error {
	data, err := os.ReadFile(ConfigFileFullPath())
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

	return os.WriteFile(ConfigFileFullPath(), newData, 0664)

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

func existsConfigFile() bool {
	_, err := os.ReadFile(ConfigFileFullPath())
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

func updateConfigFile(configObj *ConfigObj) error {
	if err := os.WriteFile(ConfigFileFullPath(), configObj.Config(), 0664); err != nil {
		return err
	}
	return nil
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
	dat, err := os.ReadFile(ConfigFileFullPath())
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

// Check if the customer is submitted
func (clusterConfig *ClusterConfig) IsSubmitted() bool {
	return existsConfigMap(clusterConfig.k8s, clusterConfig.defaultNS) || existsConfigFile()
}

// Check if the customer is registered
func (clusterConfig *ClusterConfig) IsRegistered() bool {

	// get from armoBE
	tenantResponse, err := clusterConfig.backendAPI.GetCustomerGUID(clusterConfig.GetCustomerGUID())
	if err == nil && tenantResponse != nil {
		if tenantResponse.AdminMail != "" { // this customer already belongs to some user
			return true
		}
	}
	return false
}

func (clusterConfig *ClusterConfig) DeleteConfig() error {
	if err := DeleteConfigMap(clusterConfig.k8s); err != nil {
		return err
	}
	if err := DeleteConfigFile(); err != nil {
		return err
	}
	return nil
}
func DeleteConfigMap(k8s *k8sinterface.KubernetesApi) error {
	return k8s.KubernetesClient.CoreV1().ConfigMaps(k8sinterface.GetDefaultNamespace()).Delete(context.Background(), configMapName, metav1.DeleteOptions{})
}

func DeleteConfigFile() error {
	return os.Remove(ConfigFileFullPath())
}

func adoptClusterName(clusterName string) string {
	return strings.ReplaceAll(clusterName, "/", "-")
}
