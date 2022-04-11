package cautils

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/kubescape/core/cautils/getter"
	"github.com/armosec/kubescape/core/cautils/logger"
	corev1 "k8s.io/api/core/v1"
)

const configFileName = "config"

func ConfigFileFullPath() string { return getter.GetDefaultPath(configFileName + ".json") }

// ======================================================================================
// =============================== Config structure =====================================
// ======================================================================================

type ConfigObj struct {
	AccountID          string `json:"accountID,omitempty"`
	ClientID           string `json:"clientID,omitempty"`
	SecretKey          string `json:"secretKey,omitempty"`
	CustomerGUID       string `json:"customerGUID,omitempty"` // Deprecated
	Token              string `json:"invitationParam,omitempty"`
	CustomerAdminEMail string `json:"adminMail,omitempty"`
	ClusterName        string `json:"clusterName,omitempty"`
}

// Config - convert ConfigObj to config file
func (co *ConfigObj) Config() []byte {

	// remove cluster name before saving to file
	clusterName := co.ClusterName
	customerAdminEMail := co.CustomerAdminEMail
	token := co.Token
	co.ClusterName = ""
	co.Token = ""
	co.CustomerAdminEMail = ""

	b, err := json.MarshalIndent(co, "", "  ")

	co.ClusterName = clusterName
	co.CustomerAdminEMail = customerAdminEMail
	co.Token = token

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
	UpdateCachedConfig() error
	DeleteCachedConfig() error

	// getters
	GetContextName() string
	GetAccountID() string
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

func NewLocalConfig(
	backendAPI getter.IBackend, customerGUID, clusterName string) *LocalConfig {
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
		lc.configObj.AccountID = customerGUID // override config customerGUID
	}
	if clusterName != "" {
		lc.configObj.ClusterName = AdoptClusterName(clusterName) // override config clusterName
	}
	getAccountFromEnv(lc.configObj)

	lc.backendAPI.SetAccountID(lc.configObj.AccountID)
	lc.backendAPI.SetClientID(lc.configObj.ClientID)
	lc.backendAPI.SetSecretKey(lc.configObj.SecretKey)

	return lc
}

func (lc *LocalConfig) GetConfigObj() *ConfigObj { return lc.configObj }
func (lc *LocalConfig) GetAccountID() string     { return lc.configObj.AccountID }
func (lc *LocalConfig) GetContextName() string   { return lc.configObj.ClusterName }
func (lc *LocalConfig) IsConfigFound() bool      { return existsConfigFile() }
func (lc *LocalConfig) SetTenant() error {

	// ARMO tenant GUID
	if err := getTenantConfigFromBE(lc.backendAPI, lc.configObj); err != nil {
		return err
	}
	lc.UpdateCachedConfig()
	return nil

}
func (lc *LocalConfig) UpdateCachedConfig() error {
	return updateConfigFile(lc.configObj)
}

func (lc *LocalConfig) DeleteCachedConfig() error {
	if err := DeleteConfigFile(); err != nil {
		logger.L().Warning(err.Error())
	}
	return nil
}

func getTenantConfigFromBE(backendAPI getter.IBackend, configObj *ConfigObj) error {

	// get from armoBE
	tenantResponse, err := backendAPI.GetTenant()
	if err == nil && tenantResponse != nil {
		if tenantResponse.AdminMail != "" { // registered tenant
			configObj.CustomerAdminEMail = tenantResponse.AdminMail
		} else { // new tenant
			configObj.Token = tenantResponse.Token
			configObj.AccountID = tenantResponse.TenantID
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

// ClusterConfig configuration of specific cluster
/*

Supported environments variables:
KS_DEFAULT_CONFIGMAP_NAME  // name of configmap, if not set default is 'kubescape'
KS_DEFAULT_CONFIGMAP_NAMESPACE   // configmap namespace, if not set default is 'default'

KS_ACCOUNT_ID
KS_CLIENT_ID
KS_SECRET_KEY

TODO - supprot:
KS_CACHE // path to cached files
*/
type ClusterConfig struct {
	k8s                *k8sinterface.KubernetesApi
	configMapName      string
	configMapNamespace string
	backendAPI         getter.IBackend
	configObj          *ConfigObj
}

func NewClusterConfig(k8s *k8sinterface.KubernetesApi, backendAPI getter.IBackend, customerGUID, clusterName string) *ClusterConfig {
	var configObj *ConfigObj
	c := &ClusterConfig{
		k8s:                k8s,
		backendAPI:         backendAPI,
		configObj:          &ConfigObj{},
		configMapName:      getConfigMapName(),
		configMapNamespace: getConfigMapNamespace(),
	}

	// get from configMap
	if c.existsConfigMap() {
		configObj, _ = c.loadConfigFromConfigMap()
	}
	if configObj == nil && existsConfigFile() { // get from file
		configObj, _ = loadConfigFromFile()
	}
	if configObj != nil {
		c.configObj = configObj
	}
	if customerGUID != "" {
		c.configObj.AccountID = customerGUID // override config customerGUID
	}
	if clusterName != "" {
		c.configObj.ClusterName = AdoptClusterName(clusterName) // override config clusterName
	}
	getAccountFromEnv(c.configObj)

	if c.configObj.ClusterName == "" {
		c.configObj.ClusterName = AdoptClusterName(k8sinterface.GetContextName())
	} else { // override the cluster name if it has unwanted characters
		c.configObj.ClusterName = AdoptClusterName(c.configObj.ClusterName)
	}

	c.backendAPI.SetAccountID(c.configObj.AccountID)
	c.backendAPI.SetClientID(c.configObj.ClientID)
	c.backendAPI.SetSecretKey(c.configObj.SecretKey)

	return c
}

func (c *ClusterConfig) GetConfigObj() *ConfigObj { return c.configObj }
func (c *ClusterConfig) GetDefaultNS() string     { return c.configMapNamespace }
func (c *ClusterConfig) GetAccountID() string     { return c.configObj.AccountID }
func (c *ClusterConfig) IsConfigFound() bool      { return existsConfigFile() || c.existsConfigMap() }

func (c *ClusterConfig) SetTenant() error {

	// ARMO tenant GUID
	if err := getTenantConfigFromBE(c.backendAPI, c.configObj); err != nil {
		return err
	}
	c.UpdateCachedConfig()
	return nil

}

func (c *ClusterConfig) UpdateCachedConfig() error {
	// update/create config
	if c.existsConfigMap() {
		if err := c.updateConfigMap(); err != nil {
			return err
		}
	} else {
		if err := c.createConfigMap(); err != nil {
			return err
		}
	}
	return updateConfigFile(c.configObj)
}

func (c *ClusterConfig) DeleteCachedConfig() error {
	if err := c.deleteConfigMap(); err != nil {
		logger.L().Warning(err.Error())
	}
	if err := DeleteConfigFile(); err != nil {
		logger.L().Warning(err.Error())
	}
	return nil
}
func (c *ClusterConfig) GetContextName() string {
	return c.configObj.ClusterName
}

func (c *ClusterConfig) ToMapString() map[string]interface{} {
	m := map[string]interface{}{}
	if bc, err := json.Marshal(c.configObj); err == nil {
		json.Unmarshal(bc, &m)
	}
	return m
}
func (c *ClusterConfig) loadConfigFromConfigMap() (*ConfigObj, error) {
	configMap, err := c.k8s.KubernetesClient.CoreV1().ConfigMaps(c.configMapNamespace).Get(context.Background(), c.configMapName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	if bData, err := json.Marshal(configMap.Data); err == nil {
		return readConfig(bData)
	}
	return nil, nil
}

func (c *ClusterConfig) existsConfigMap() bool {
	_, err := c.k8s.KubernetesClient.CoreV1().ConfigMaps(c.configMapNamespace).Get(context.Background(), c.configMapName, metav1.GetOptions{})
	// TODO - check if has customerGUID
	return err == nil
}

func (c *ClusterConfig) GetValueByKeyFromConfigMap(key string) (string, error) {

	configMap, err := c.k8s.KubernetesClient.CoreV1().ConfigMaps(c.configMapNamespace).Get(context.Background(), c.configMapName, metav1.GetOptions{})

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

func (c *ClusterConfig) SetKeyValueInConfigmap(key string, value string) error {

	configMap, err := c.k8s.KubernetesClient.CoreV1().ConfigMaps(c.configMapNamespace).Get(context.Background(), c.configMapName, metav1.GetOptions{})
	if err != nil {
		configMap = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name: c.configMapName,
			},
		}
	}

	if len(configMap.Data) == 0 {
		configMap.Data = make(map[string]string)
	}

	configMap.Data[key] = value

	if err != nil {
		_, err = c.k8s.KubernetesClient.CoreV1().ConfigMaps(c.configMapNamespace).Create(context.Background(), configMap, metav1.CreateOptions{})
	} else {
		_, err = c.k8s.KubernetesClient.CoreV1().ConfigMaps(c.configMapNamespace).Update(context.Background(), configMap, metav1.UpdateOptions{})
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
			Name: c.configMapName,
		},
	}
	c.updateConfigData(configMap)

	_, err := c.k8s.KubernetesClient.CoreV1().ConfigMaps(c.configMapNamespace).Create(context.Background(), configMap, metav1.CreateOptions{})
	return err
}

func (c *ClusterConfig) updateConfigMap() error {
	if c.k8s == nil {
		return nil
	}
	configMap, err := c.k8s.KubernetesClient.CoreV1().ConfigMaps(c.configMapNamespace).Get(context.Background(), c.configMapName, metav1.GetOptions{})

	if err != nil {
		return err
	}

	c.updateConfigData(configMap)

	_, err = c.k8s.KubernetesClient.CoreV1().ConfigMaps(c.configMapNamespace).Update(context.Background(), configMap, metav1.UpdateOptions{})
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
	if err := json.Unmarshal(dat, configObj); err != nil {
		return nil, err
	}
	if configObj.AccountID == "" {
		configObj.AccountID = configObj.CustomerGUID
	}
	configObj.CustomerGUID = ""
	return configObj, nil
}

// Check if the customer is submitted
func (clusterConfig *ClusterConfig) IsSubmitted() bool {
	return clusterConfig.existsConfigMap() || existsConfigFile()
}

// Check if the customer is registered
func (clusterConfig *ClusterConfig) IsRegistered() bool {

	// get from armoBE
	tenantResponse, err := clusterConfig.backendAPI.GetTenant()
	if err == nil && tenantResponse != nil {
		if tenantResponse.AdminMail != "" { // this customer already belongs to some user
			return true
		}
	}
	return false
}

func (clusterConfig *ClusterConfig) deleteConfigMap() error {
	return clusterConfig.k8s.KubernetesClient.CoreV1().ConfigMaps(clusterConfig.configMapNamespace).Delete(context.Background(), clusterConfig.configMapName, metav1.DeleteOptions{})
}

func DeleteConfigFile() error {
	return os.Remove(ConfigFileFullPath())
}

func AdoptClusterName(clusterName string) string {
	return strings.ReplaceAll(clusterName, "/", "-")
}

func getConfigMapName() string {
	if n := os.Getenv("KS_DEFAULT_CONFIGMAP_NAME"); n != "" {
		return n
	}
	return "kubescape"
}

func getConfigMapNamespace() string {
	if n := os.Getenv("KS_DEFAULT_CONFIGMAP_NAMESPACE"); n != "" {
		return n
	}
	return "default"
}

func getAccountFromEnv(configObj *ConfigObj) {
	// load from env
	if accountID := os.Getenv("KS_ACCOUNT_ID"); accountID != "" {
		configObj.AccountID = accountID
	}
	if clientID := os.Getenv("KS_CLIENT_ID"); clientID != "" {
		configObj.ClientID = clientID
	}
	if secretKey := os.Getenv("KS_SECRET_KEY"); secretKey != "" {
		configObj.SecretKey = secretKey
	}
}
