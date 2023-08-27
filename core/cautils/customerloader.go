package cautils

import (
	"context"
	"encoding/json"
	"os"
	"regexp"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/google/uuid"
	v1 "github.com/kubescape/backend/pkg/client/v1"
	"github.com/kubescape/backend/pkg/servicediscovery"
	servicediscoveryv1 "github.com/kubescape/backend/pkg/servicediscovery/v1"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v2/core/cautils/getter"
	corev1 "k8s.io/api/core/v1"
)

const (
	configFileName              string = "config"
	kubescapeNamespace          string = "kubescape"
	kubescapeConfigMapName      string = "kubescape-config"
	kubescapeCloudConfigMapName string = "ks-cloud-config"

	// env vars
	defaultConfigMapNameEnvVar      string = "KS_DEFAULT_CONFIGMAP_NAME"
	defaultCloudConfigMapNameEnvVar string = "KS_DEFAULT_CLOUD_CONFIGMAP_NAME"
	defaultConfigMapNamespaceEnvVar string = "KS_DEFAULT_CONFIGMAP_NAMESPACE"
	accountIdEnvVar                 string = "KS_ACCOUNT_ID"
	cloudApiUrlEnvVar               string = "KS_CLOUD_API_URL"
	cloudReportUrlEnvVar            string = "KS_CLOUD_REPORT_URL"
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
}

// ======================================================================================
// ============================ Local Config ============================================
// ======================================================================================
// Config when scanning YAML files or URL but not a Kubernetes cluster

var _ ITenantConfig = &LocalConfig{}

type LocalConfig struct {
	configObj *ConfigObj
}

func NewLocalConfig(accountID, clusterName string, customClusterName string) *LocalConfig {
	lc := &LocalConfig{
		configObj: &ConfigObj{},
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

	updatedKsCloud := overrideKsCloudAPIFromConfig(lc)
	logger.L().Debug("Kubescape Cloud URLs", helpers.String("api", updatedKsCloud.GetCloudAPIURL()), helpers.String("report", updatedKsCloud.GetCloudReportURL()))

	return lc
}

func (lc *LocalConfig) GetConfigObj() *ConfigObj  { return lc.configObj }
func (lc *LocalConfig) GetAccountID() string      { return lc.configObj.AccountID }
func (lc *LocalConfig) GetContextName() string    { return lc.configObj.ClusterName }
func (lc *LocalConfig) GetCloudReportURL() string { return lc.configObj.CloudReportURL }
func (lc *LocalConfig) GetCloudAPIURL() string    { return lc.configObj.CloudAPIURL }

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
	k8s                  *k8sinterface.KubernetesApi
	configObj            *ConfigObj
	configMapNamespace   string
	ksConfigMapName      string
	ksCloudConfigMapName string
}

func NewClusterConfig(k8s *k8sinterface.KubernetesApi, accountID, clusterName string, customClusterName string) *ClusterConfig {
	c := &ClusterConfig{
		k8s:                  k8s,
		configObj:            &ConfigObj{},
		ksConfigMapName:      getKubescapeConfigMapName(),
		ksCloudConfigMapName: getKubescapeCloudConfigMapName(),
		configMapNamespace:   GetConfigMapNamespace(),
	}

	// first, load from file
	if existsConfigFile() { // get from file
		loadConfigFromFile(c.configObj)
	}

	// second, load from configMap
	if c.existsConfigMap(c.ksConfigMapName) {
		c.updateConfigEmptyFieldsFromKubescapeConfigMap()
	}

	// third, load urls from cloudConfigMap
	if c.existsConfigMap(c.ksCloudConfigMapName) {
		c.updateConfigEmptyFieldsFromKubescapeCloudConfigMap()
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
	updatedKsCloud := overrideKsCloudAPIFromConfig(c)
	logger.L().Debug("Kubescape Cloud URLs", helpers.String("api", updatedKsCloud.GetCloudAPIURL()), helpers.String("report", updatedKsCloud.GetCloudReportURL()))
	return c
}

func (c *ClusterConfig) GetConfigObj() *ConfigObj  { return c.configObj }
func (c *ClusterConfig) GetDefaultNS() string      { return c.configMapNamespace }
func (c *ClusterConfig) GetAccountID() string      { return c.configObj.AccountID }
func (c *ClusterConfig) GetCloudReportURL() string { return c.configObj.CloudReportURL }
func (c *ClusterConfig) GetCloudAPIURL() string    { return c.configObj.CloudAPIURL }

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

func (c *ClusterConfig) updateConfigEmptyFieldsFromKubescapeConfigMap() error {
	configMap, err := c.k8s.KubernetesClient.CoreV1().ConfigMaps(c.configMapNamespace).Get(context.Background(), c.ksConfigMapName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	tempCO := ConfigObj{}
	if jsonConf, ok := configMap.Data["config.json"]; ok {
		if err = json.Unmarshal([]byte(jsonConf), &tempCO); err != nil {
			return err
		}
		return c.configObj.updateEmptyFields(&tempCO)
	}
	return err
}

func (c *ClusterConfig) updateConfigEmptyFieldsFromKubescapeCloudConfigMap() error {
	configMap, err := c.k8s.KubernetesClient.CoreV1().ConfigMaps(c.configMapNamespace).Get(context.Background(), c.ksCloudConfigMapName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	if jsonConf, ok := configMap.Data["services"]; ok {
		services, err := servicediscovery.GetServices(
			servicediscoveryv1.NewServiceDiscoveryStreamV1([]byte(jsonConf)),
		)
		if err != nil {
			return err
		}

		if services.GetApiServerUrl() != "" {
			c.configObj.CloudAPIURL = services.GetApiServerUrl()
		}
		if services.GetReportReceiverHttpUrl() != "" {
			c.configObj.CloudReportURL = services.GetReportReceiverHttpUrl()
		}
	}
	return nil
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

func (c *ClusterConfig) existsConfigMap(name string) bool {
	_, err := c.k8s.KubernetesClient.CoreV1().ConfigMaps(c.configMapNamespace).Get(context.Background(), name, metav1.GetOptions{})
	return err == nil
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

func getKubescapeConfigMapName() string {
	if n := os.Getenv(defaultConfigMapNameEnvVar); n != "" {
		return n
	}
	return kubescapeConfigMapName
}

func getKubescapeCloudConfigMapName() string {
	if n := os.Getenv(defaultCloudConfigMapNameEnvVar); n != "" {
		return n
	}

	return kubescapeCloudConfigMapName
}

// GetConfigMapNamespace returns the namespace of the cluster config, which is the same for all in-cluster components
func GetConfigMapNamespace() string {
	if n := os.Getenv(defaultConfigMapNamespaceEnvVar); n != "" {
		return n
	}
	return kubescapeNamespace
}

func updateAccountID(configObj *ConfigObj, accountID string) {
	if accountID != "" {
		configObj.AccountID = accountID
	}

	if envAccountID := os.Getenv(accountIdEnvVar); envAccountID != "" {
		configObj.AccountID = envAccountID
	}
}

func getCloudURLsFromEnv(cloudURLs *CloudURLs) {
	// load from env
	if cloudAPIURL := os.Getenv(cloudApiUrlEnvVar); cloudAPIURL != "" {
		cloudURLs.CloudAPIURL = cloudAPIURL
	}
	if cloudReportURL := os.Getenv(cloudReportUrlEnvVar); cloudReportURL != "" {
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

func overrideKsCloudAPIFromConfig(c ITenantConfig) *v1.KSCloudAPI {
	// reads the initialized KSCloud
	globalKsCloud := getter.GetKSCloudAPIConnector()

	shouldUpdateConfig := false
	accountId := c.GetAccountID()
	if globalKsCloud.GetAccountID() != "" {
		c.GetConfigObj().AccountID = globalKsCloud.GetAccountID()
		shouldUpdateConfig = true
	}

	cloudApiUrl := c.GetCloudAPIURL()
	if globalKsCloud.GetCloudAPIURL() != "" {
		c.GetConfigObj().CloudAPIURL = globalKsCloud.GetCloudAPIURL()
		shouldUpdateConfig = true
	}

	cloudReportUrl := c.GetCloudReportURL()
	if globalKsCloud.GetCloudReportURL() != "" {
		c.GetConfigObj().CloudReportURL = globalKsCloud.GetCloudReportURL()
		shouldUpdateConfig = true
	}

	if shouldUpdateConfig {
		logger.L().Debug("updating cached config Cloud URLs")
		c.UpdateCachedConfig()
	}
	cloudApi, err := v1.NewKSCloudAPI(cloudApiUrl, cloudReportUrl, accountId)
	if err != nil {
		logger.L().Fatal("failed to create KS Cloud client", helpers.Error(err))
	}

	getter.SetKSCloudAPIConnector(cloudApi)
	return cloudApi
}

func GetTenantConfig(accountID, clusterName, customClusterName string, k8s *k8sinterface.KubernetesApi) ITenantConfig {
	if !k8sinterface.IsConnectedToCluster() || k8s == nil {
		return NewLocalConfig(accountID, clusterName, customClusterName)
	}
	return NewClusterConfig(k8s, accountID, clusterName, customClusterName)
}
