package cautils

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/google/uuid"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v2/core/cautils/getter"
	corev1 "k8s.io/api/core/v1"
)

const (
	configFileName         string = "config"
	kubescapeNamespace     string = "kubescape"
	kubescapeConfigMapName string = "kubescape-config"
)

func ConfigFileFullPath() string { return getter.GetDefaultPath(configFileName + ".json") }

// ======================================================================================
// =============================== Config structure =====================================
// ======================================================================================

type ConfigObj struct {
	AccountID      string `json:"accountID,omitempty"`
	ClusterName    string `json:"clusterName,omitempty"`
	CloudReportURL string `json:"cloudReportURL,omitempty"`
	CloudAPIURL    string `json:"cloudAPIURL,omitempty"`
}

// Config - convert ConfigObj to config file
func (co *ConfigObj) Config() []byte {

	// remove cluster name before saving to file
	clusterName := co.ClusterName
	co.ClusterName = ""

	b, err := json.MarshalIndent(co, "", "  ")

	co.ClusterName = clusterName

	if err == nil {
		return b
	}

	return []byte{}
}

func (co *ConfigObj) updateEmptyFields(inCO *ConfigObj) error {
	if inCO.AccountID != "" {
		co.AccountID = inCO.AccountID
	}
	if inCO.CloudAPIURL != "" {
		co.CloudAPIURL = inCO.CloudAPIURL
	}
	if inCO.CloudReportURL != "" {
		co.CloudReportURL = inCO.CloudReportURL
	}
	if inCO.ClusterName != "" {
		co.ClusterName = inCO.ClusterName
	}

	return nil
}

// ======================================================================================
// =============================== interface ============================================
// ======================================================================================
type ITenantConfig interface {
	UpdateCachedConfig() error
	DeleteCachedConfig(ctx context.Context) error
	GenerateAccountID() (string, error)
	DeleteAccountID() error

	// getters
	GetContextName() string
	GetAccountID() string
	GetConfigObj() *ConfigObj
	GetCloudReportURL() string
	GetCloudAPIURL() string

	IsConfigFound() bool
}

// ======================================================================================
// ============================ Local Config ============================================
// ======================================================================================
// Config when scanning YAML files or URL but not a Kubernetes cluster

var _ ITenantConfig = &LocalConfig{}

type LocalConfig struct {
	backendAPI getter.IBackend
	configObj  *ConfigObj
}

func NewLocalConfig(
	backendAPI getter.IBackend, accountID, clusterName string, customClusterName string) *LocalConfig {

	lc := &LocalConfig{
		backendAPI: backendAPI,
		configObj:  &ConfigObj{},
	}
	// get from configMap
	if existsConfigFile() { // get from file
		loadConfigFromFile(lc.configObj)
	}

	updateAccountID(lc.configObj, accountID)
	updateCloudURLs(lc.configObj)

	// If a custom cluster name is provided then set that name, else use the cluster's original name
	if customClusterName != "" {
		lc.configObj.ClusterName = AdoptClusterName(customClusterName)
	} else if clusterName != "" {
		lc.configObj.ClusterName = AdoptClusterName(clusterName) // override config clusterName
	}

	lc.backendAPI.SetAccountID(lc.configObj.AccountID)
	if lc.configObj.CloudAPIURL != "" {
		lc.backendAPI.SetCloudAPIURL(lc.configObj.CloudAPIURL)
	} else {
		lc.configObj.CloudAPIURL = lc.backendAPI.GetCloudAPIURL()
	}

	if lc.configObj.CloudReportURL != "" {
		lc.backendAPI.SetCloudReportURL(lc.configObj.CloudReportURL)
	} else {
		lc.configObj.CloudReportURL = lc.backendAPI.GetCloudReportURL()
	}
	logger.L().Debug("Kubescape Cloud URLs", helpers.String("api", lc.backendAPI.GetCloudAPIURL()), helpers.String("report", lc.backendAPI.GetCloudReportURL()))

	initializeCloudAPI(lc)

	return lc
}

func (lc *LocalConfig) GetConfigObj() *ConfigObj  { return lc.configObj }
func (lc *LocalConfig) GetAccountID() string      { return lc.configObj.AccountID }
func (lc *LocalConfig) GetContextName() string    { return lc.configObj.ClusterName }
func (lc *LocalConfig) GetCloudReportURL() string { return lc.configObj.CloudReportURL }
func (lc *LocalConfig) GetCloudAPIURL() string    { return lc.configObj.CloudAPIURL }
func (lc *LocalConfig) IsConfigFound() bool       { return existsConfigFile() }
func (lc *LocalConfig) GenerateAccountID() (string, error) {
	lc.configObj.AccountID = uuid.NewString()
	err := lc.UpdateCachedConfig()
	return lc.configObj.AccountID, err
}

func (lc *LocalConfig) DeleteAccountID() error {
	lc.configObj.AccountID = ""
	return lc.UpdateCachedConfig()
}

func (lc *LocalConfig) UpdateCachedConfig() error {
	return updateConfigFile(lc.configObj)
}

func (lc *LocalConfig) DeleteCachedConfig(ctx context.Context) error {
	if err := DeleteConfigFile(); err != nil {
		logger.L().Ctx(ctx).Warning(err.Error())
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

TODO - support:
KS_CACHE // path to cached files
*/
var _ ITenantConfig = &ClusterConfig{}

type ClusterConfig struct {
	backendAPI         getter.IBackend
	k8s                *k8sinterface.KubernetesApi
	configObj          *ConfigObj
	configMapName      string
	configMapNamespace string
}

func NewClusterConfig(k8s *k8sinterface.KubernetesApi, backendAPI getter.IBackend, accountID, clusterName string, customClusterName string) *ClusterConfig {
	// var configObj *ConfigObj
	c := &ClusterConfig{
		k8s:                k8s,
		backendAPI:         backendAPI,
		configObj:          &ConfigObj{},
		configMapName:      getConfigMapName(),
		configMapNamespace: GetConfigMapNamespace(),
	}

	// first, load from file
	if existsConfigFile() { // get from file
		loadConfigFromFile(c.configObj)
	}

	// second, load from configMap
	if c.existsConfigMap() {
		c.updateConfigEmptyFieldsFromConfigMap()
	}

	updateAccountID(c.configObj, accountID)
	updateCloudURLs(c.configObj)

	// If a custom cluster name is provided then set that name, else use the cluster's original name
	if customClusterName != "" {
		c.configObj.ClusterName = AdoptClusterName(customClusterName)
	} else if clusterName != "" {
		c.configObj.ClusterName = AdoptClusterName(clusterName) // override config clusterName
	}

	if c.configObj.ClusterName == "" {
		c.configObj.ClusterName = AdoptClusterName(k8sinterface.GetContextName())
	} else { // override the cluster name if it has unwanted characters
		c.configObj.ClusterName = AdoptClusterName(c.configObj.ClusterName)
	}

	c.backendAPI.SetAccountID(c.configObj.AccountID)
	if c.configObj.CloudAPIURL != "" {
		c.backendAPI.SetCloudAPIURL(c.configObj.CloudAPIURL)
	} else {
		c.configObj.CloudAPIURL = c.backendAPI.GetCloudAPIURL()
	}
	if c.configObj.CloudReportURL != "" {
		c.backendAPI.SetCloudReportURL(c.configObj.CloudReportURL)
	} else {
		c.configObj.CloudReportURL = c.backendAPI.GetCloudReportURL()
	}
	logger.L().Debug("Kubescape Cloud URLs", helpers.String("api", c.backendAPI.GetCloudAPIURL()), helpers.String("report", c.backendAPI.GetCloudReportURL()))

	initializeCloudAPI(c)

	return c
}

func (c *ClusterConfig) GetConfigObj() *ConfigObj  { return c.configObj }
func (c *ClusterConfig) GetDefaultNS() string      { return c.configMapNamespace }
func (c *ClusterConfig) GetAccountID() string      { return c.configObj.AccountID }
func (c *ClusterConfig) GetCloudReportURL() string { return c.configObj.CloudReportURL }
func (c *ClusterConfig) GetCloudAPIURL() string    { return c.configObj.CloudAPIURL }

func (c *ClusterConfig) IsConfigFound() bool { return existsConfigFile() || c.existsConfigMap() }

func (c *ClusterConfig) UpdateCachedConfig() error {
	return updateConfigFile(c.configObj)
}

func (c *ClusterConfig) DeleteCachedConfig(ctx context.Context) error {
	if err := DeleteConfigFile(); err != nil {
		logger.L().Ctx(ctx).Warning(err.Error())
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

func (c *ClusterConfig) updateConfigEmptyFieldsFromConfigMap() error {
	configMap, err := c.k8s.KubernetesClient.CoreV1().ConfigMaps(c.configMapNamespace).Get(context.Background(), c.configMapName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	tempCO := ConfigObj{}
	if jsonConf, ok := configMap.Data["config.json"]; ok {
		json.Unmarshal([]byte(jsonConf), &tempCO)
		return c.configObj.updateEmptyFields(&tempCO)
	}
	return err

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

func (c *ClusterConfig) existsNamespace() bool {
	_, err := c.k8s.KubernetesClient.CoreV1().Namespaces().Get(context.Background(), c.configMapNamespace, metav1.GetOptions{})
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

func existsConfigFile() bool {
	_, err := os.ReadFile(ConfigFileFullPath())
	return err == nil
}

func updateConfigFile(configObj *ConfigObj) error {
	return os.WriteFile(ConfigFileFullPath(), configObj.Config(), 0664) //nolint:gosec
}

func (c *ClusterConfig) GenerateAccountID() (string, error) {
	c.configObj.AccountID = uuid.NewString()
	err := c.UpdateCachedConfig()
	return c.configObj.AccountID, err
}

func (c *ClusterConfig) DeleteAccountID() error {
	c.configObj.AccountID = ""
	return c.UpdateCachedConfig()
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
	return nil
}

// Check if the customer is submitted
func (clusterConfig *ClusterConfig) IsSubmitted() bool {
	return clusterConfig.existsConfigMap() || existsConfigFile()
}

func DeleteConfigFile() error {
	return os.Remove(ConfigFileFullPath())
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
	return kubescapeConfigMapName
}

// GetConfigMapNamespace returns the namespace of the cluster config, which is the same for all in-cluster components
func GetConfigMapNamespace() string {
	if n := os.Getenv("KS_DEFAULT_CONFIGMAP_NAMESPACE"); n != "" {
		return n
	}
	return kubescapeNamespace
}

func updateAccountID(configObj *ConfigObj, accountID string) {
	if accountID != "" {
		configObj.AccountID = accountID
	}

	if envAccountID := os.Getenv("KS_ACCOUNT_ID"); envAccountID != "" {
		configObj.AccountID = envAccountID
	}
}

func getCloudURLsFromEnv(cloudURLs *CloudURLs) {
	// load from env
	if cloudAPIURL := os.Getenv("KS_CLOUD_API_URL"); cloudAPIURL != "" {
		cloudURLs.CloudAPIURL = cloudAPIURL
	}
	if cloudReportURL := os.Getenv("KS_CLOUD_REPORT_URL"); cloudReportURL != "" {
		cloudURLs.CloudReportURL = cloudReportURL
	}
}

func updateCloudURLs(configObj *ConfigObj) {
	cloudURLs := &CloudURLs{}

	getCloudURLsFromEnv(cloudURLs)

	if cloudURLs.CloudAPIURL != "" {
		configObj.CloudAPIURL = cloudURLs.CloudAPIURL // override config CloudAPIURL
	}
	if cloudURLs.CloudReportURL != "" {
		configObj.CloudReportURL = cloudURLs.CloudReportURL // override config CloudReportURL
	}

}

func initializeCloudAPI(c ITenantConfig) {
	cloud := getter.GetKSCloudAPIConnector()
	cloud.SetAccountID(c.GetAccountID())
	cloud.SetCloudReportURL(c.GetCloudReportURL())
	cloud.SetCloudAPIURL(c.GetCloudAPIURL())
	getter.SetKSCloudAPIConnector(cloud)
}
