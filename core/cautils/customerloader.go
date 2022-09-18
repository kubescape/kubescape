package cautils

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v2/core/cautils/getter"
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
	GetTenantEmail() string
	GetToken() string
	GetClientID() string
	GetSecretKey() string
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
	backendAPI getter.IBackend, credentials *Credentials, clusterName string, customClusterName string) *LocalConfig {

	lc := &LocalConfig{
		backendAPI: backendAPI,
		configObj:  &ConfigObj{},
	}
	// get from configMap
	if existsConfigFile() { // get from file
		loadConfigFromFile(lc.configObj)
	}

	updateCredentials(lc.configObj, credentials)

	// If a custom cluster name is provided then set that name, else use the cluster's original name
	if customClusterName != "" {
		lc.configObj.ClusterName = AdoptCustomClusterName(customClusterName)
	} else if clusterName != "" {
		lc.configObj.ClusterName = AdoptClusterName(clusterName) // override config clusterName
	}

	lc.backendAPI.SetAccountID(lc.configObj.AccountID)
	lc.backendAPI.SetClientID(lc.configObj.ClientID)
	lc.backendAPI.SetSecretKey(lc.configObj.SecretKey)

	return lc
}

func (lc *LocalConfig) GetConfigObj() *ConfigObj { return lc.configObj }
func (lc *LocalConfig) GetTenantEmail() string   { return lc.configObj.CustomerAdminEMail }
func (lc *LocalConfig) GetAccountID() string     { return lc.configObj.AccountID }
func (lc *LocalConfig) GetClientID() string      { return lc.configObj.ClientID }
func (lc *LocalConfig) GetSecretKey() string     { return lc.configObj.SecretKey }
func (lc *LocalConfig) GetContextName() string   { return lc.configObj.ClusterName }
func (lc *LocalConfig) GetToken() string         { return lc.configObj.Token }
func (lc *LocalConfig) IsConfigFound() bool      { return existsConfigFile() }
func (lc *LocalConfig) SetTenant() error {

	// Kubescape Cloud tenant GUID
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

	// get from Kubescape Cloud API
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

TODO - support:
KS_CACHE // path to cached files
*/
type ClusterConfig struct {
	backendAPI         getter.IBackend
	k8s                *k8sinterface.KubernetesApi
	configObj          *ConfigObj
	configMapName      string
	configMapNamespace string
}

func NewClusterConfig(k8s *k8sinterface.KubernetesApi, backendAPI getter.IBackend, credentials *Credentials, clusterName string, customClusterName string) *ClusterConfig {
	// var configObj *ConfigObj
	c := &ClusterConfig{
		k8s:                k8s,
		backendAPI:         backendAPI,
		configObj:          &ConfigObj{},
		configMapName:      getConfigMapName(),
		configMapNamespace: getConfigMapNamespace(),
	}

	// first, load from configMap
	if c.existsConfigMap() {
		c.loadConfigFromConfigMap()
	}

	// second, load from file
	if existsConfigFile() { // get from file
		loadConfigFromFile(c.configObj)
	}
	updateCredentials(c.configObj, credentials)

	// If a custom cluster name is provided then set that name, else use the cluster's original name
	if customClusterName != "" {
		c.configObj.ClusterName = AdoptCustomClusterName(customClusterName)
	} else if clusterName != "" {
		c.configObj.ClusterName = AdoptClusterName(clusterName) // override config clusterName
	}

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
func (c *ClusterConfig) GetClientID() string      { return c.configObj.ClientID }
func (c *ClusterConfig) GetSecretKey() string     { return c.configObj.SecretKey }
func (c *ClusterConfig) GetTenantEmail() string   { return c.configObj.CustomerAdminEMail }
func (c *ClusterConfig) GetToken() string         { return c.configObj.Token }
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
func (c *ClusterConfig) loadConfigFromConfigMap() error {
	configMap, err := c.k8s.KubernetesClient.CoreV1().ConfigMaps(c.configMapNamespace).Get(context.Background(), c.configMapName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	return loadConfigFromData(c.configObj, configMap.Data)
}

func loadConfigFromData(co *ConfigObj, data map[string]string) error {
	var e error
	if jsonConf, ok := data["config.json"]; ok {
		e = readConfig([]byte(jsonConf), co)
	}
	if bData, err := json.Marshal(data); err == nil {
		e = readConfig(bData, co)
	}

	return e
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
func loadConfigFromFile(configObj *ConfigObj) error {
	dat, err := os.ReadFile(ConfigFileFullPath())
	if err != nil {
		return err
	}
	return readConfig(dat, configObj)
}
func readConfig(dat []byte, configObj *ConfigObj) error {

	if len(dat) == 0 {
		return nil
	}

	if err := json.Unmarshal(dat, configObj); err != nil {
		return err
	}
	if configObj.AccountID == "" {
		configObj.AccountID = configObj.CustomerGUID
	}
	configObj.CustomerGUID = ""
	return nil
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

// To check if the custom cluster name is valid:
func AdoptCustomClusterName(customClusterName string) string {
	is_alphanumeric := regexp.MustCompile(`^[a-zA-Z0-9]*$`).MatchString(customClusterName)

	// Check it does not contain special-characters
	if is_alphanumeric == false {
		logger.L().Fatal("custom cluster name cannot contain special characters")
	} else if len(customClusterName) >= 256 { // Check it contains less than 256 characters
		logger.L().Fatal("custom cluster name cannot contain more than 255 characters")
	}
	return customClusterName
}

func AdoptClusterName(clusterName string) string {
	re, err := regexp.Compile(`[^\w]+`)
	if err != nil {
		return clusterName
	}
	return re.ReplaceAllString(clusterName, "-")
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

func getAccountFromEnv(credentials *Credentials) {
	// load from env
	if accountID := os.Getenv("KS_ACCOUNT_ID"); credentials.Account == "" && accountID != "" {
		credentials.Account = accountID
	}
	if clientID := os.Getenv("KS_CLIENT_ID"); credentials.ClientID == "" && clientID != "" {
		credentials.ClientID = clientID
	}
	if secretKey := os.Getenv("KS_SECRET_KEY"); credentials.SecretKey == "" && secretKey != "" {
		credentials.SecretKey = secretKey
	}
}

func updateCredentials(configObj *ConfigObj, credentials *Credentials) {

	if credentials == nil {
		credentials = &Credentials{}
	}
	getAccountFromEnv(credentials)

	if credentials.Account != "" {
		configObj.AccountID = credentials.Account // override config Account
	}
	if credentials.ClientID != "" {
		configObj.ClientID = credentials.ClientID // override config ClientID
	}
	if credentials.SecretKey != "" {
		configObj.SecretKey = credentials.SecretKey // override config SecretKey
	}

}
