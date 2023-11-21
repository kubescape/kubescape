package cautils

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/google/uuid"
	v1 "github.com/kubescape/backend/pkg/client/v1"
	"github.com/kubescape/backend/pkg/servicediscovery"
	servicediscoveryv1 "github.com/kubescape/backend/pkg/servicediscovery/v1"
	servicediscoveryv2 "github.com/kubescape/backend/pkg/servicediscovery/v2"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	corev1 "k8s.io/api/core/v1"
)

const (
	configFileName     string = "config"
	kubescapeNamespace string = "kubescape"

	kubescapeConfigMapName      string = "kubescape-config" // deprecated - for backward compatibility
	kubescapeCloudConfigMapName string = "ks-cloud-config"  // deprecated - for backward compatibility

	cloudConfigMapLabelSelector string = "kubescape.io/infra=config"
	credsLabelSelectors         string = "kubescape.io/infra=credentials" //nolint:gosec

	// env vars
	defaultConfigMapNamespaceEnvVar string = "KS_DEFAULT_CONFIGMAP_NAMESPACE"
	accountIdEnvVar                 string = "KS_ACCOUNT_ID"
	accessKeyEnvVar                 string = "KS_ACCESS_KEY"
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
	AccessKey      string `json:"accessKey,omitempty"`
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
	DeleteCredentials() error

	// getters
	GetContextName() string
	GetAccountID() string
	GetAccessKey() string
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

func NewLocalConfig(accountID, accessKey, clusterName, customClusterName string) *LocalConfig {
	lc := &LocalConfig{
		configObj: &ConfigObj{},
	}
	// get from configMap
	if existsConfigFile() { // get from file
		loadConfigFromFile(lc.configObj)
	}

	updateCredentials(lc.configObj, accountID, accessKey)
	updateCloudURLs(lc.configObj)

	// If a custom cluster name is provided then set that name, else use the cluster's original name
	if customClusterName != "" {
		lc.configObj.ClusterName = AdoptClusterName(customClusterName)
	} else if clusterName != "" {
		lc.configObj.ClusterName = AdoptClusterName(clusterName) // override config clusterName
	}

	initializeCloudAPI(lc)

	return lc
}

func (lc *LocalConfig) GetConfigObj() *ConfigObj  { return lc.configObj }
func (lc *LocalConfig) GetAccountID() string      { return lc.configObj.AccountID }
func (lc *LocalConfig) GetContextName() string    { return lc.configObj.ClusterName }
func (lc *LocalConfig) GetCloudReportURL() string { return lc.configObj.CloudReportURL }
func (lc *LocalConfig) GetCloudAPIURL() string    { return lc.configObj.CloudAPIURL }
func (lc *LocalConfig) GetAccessKey() string      { return lc.configObj.AccessKey }

func (lc *LocalConfig) GenerateAccountID() (string, error) {
	lc.configObj.AccountID = uuid.NewString()
	err := lc.UpdateCachedConfig()
	return lc.configObj.AccountID, err
}

func (lc *LocalConfig) DeleteCredentials() error {
	lc.configObj.AccessKey = ""
	lc.configObj.AccountID = ""
	return lc.UpdateCachedConfig()
}

func (lc *LocalConfig) UpdateCachedConfig() error {
	logger.L().Debug("updating cached config", helpers.Interface("configObj", lc.configObj))
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
	k8s                *k8sinterface.KubernetesApi
	configObj          *ConfigObj
	configMapNamespace string
}

func NewClusterConfig(k8s *k8sinterface.KubernetesApi, accountID, accessKey, clusterName, customClusterName string) *ClusterConfig {
	c := &ClusterConfig{
		k8s:                k8s,
		configObj:          &ConfigObj{},
		configMapNamespace: GetConfigMapNamespace(),
	}

	// first, load from file
	if existsConfigFile() { // get from file
		loadConfigFromFile(c.configObj)
	}

	// second, load urls from config map
	c.updateConfigEmptyFieldsFromKubescapeConfigMap()

	// third, credentials from secret
	c.updateConfigEmptyFieldsFromCredentialsSecret()

	updateCredentials(c.configObj, accountID, accessKey)
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
	initializeCloudAPI(c)
	return c
}

func (c *ClusterConfig) GetConfigObj() *ConfigObj  { return c.configObj }
func (c *ClusterConfig) GetDefaultNS() string      { return c.configMapNamespace }
func (c *ClusterConfig) GetAccountID() string      { return c.configObj.AccountID }
func (c *ClusterConfig) GetCloudReportURL() string { return c.configObj.CloudReportURL }
func (c *ClusterConfig) GetCloudAPIURL() string    { return c.configObj.CloudAPIURL }
func (c *ClusterConfig) GetAccessKey() string      { return c.configObj.AccessKey }

func (c *ClusterConfig) UpdateCachedConfig() error {
	logger.L().Debug("updating cached config", helpers.Interface("configObj", c.configObj))
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
	configMaps, err := c.k8s.KubernetesClient.CoreV1().ConfigMaps(c.configMapNamespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: cloudConfigMapLabelSelector,
	})
	if err != nil {
		return err
	}
	var ksConfigMap *corev1.ConfigMap
	var urlsConfigMap *corev1.ConfigMap
	if len(configMaps.Items) == 0 {
		// try to find configmaps by name (for backward compatibility)
		ksConfigMap, _ = c.k8s.KubernetesClient.CoreV1().ConfigMaps(c.configMapNamespace).Get(context.Background(), kubescapeConfigMapName, metav1.GetOptions{})
		urlsConfigMap, _ = c.k8s.KubernetesClient.CoreV1().ConfigMaps(c.configMapNamespace).Get(context.Background(), kubescapeCloudConfigMapName, metav1.GetOptions{})
	} else {
		// use the first configmap with the label
		ksConfigMap = &configMaps.Items[0]
		urlsConfigMap = &configMaps.Items[0]
	}

	if ksConfigMap != nil {
		if jsonConf, ok := ksConfigMap.Data["clusterData"]; ok {
			tempCO := ConfigObj{}
			if err = json.Unmarshal([]byte(jsonConf), &tempCO); err != nil {
				return err
			}
			c.configObj.updateEmptyFields(&tempCO)
		}
	}

	if urlsConfigMap != nil {
		if jsonConf, ok := urlsConfigMap.Data["services"]; ok {
			services, err := servicediscovery.GetServices(
				servicediscoveryv2.NewServiceDiscoveryStreamV2([]byte(jsonConf)),
			)
			if err != nil {
				// try to parse as v1
				services, err = servicediscovery.GetServices(
					servicediscoveryv1.NewServiceDiscoveryStreamV1([]byte(jsonConf)),
				)
				if err != nil {
					return err
				}
			}

			if services.GetApiServerUrl() != "" {
				c.configObj.CloudAPIURL = services.GetApiServerUrl()
			}
			if services.GetReportReceiverHttpUrl() != "" {
				c.configObj.CloudReportURL = services.GetReportReceiverHttpUrl()
			}
		}
	}

	return err
}

func (c *ClusterConfig) updateConfigEmptyFieldsFromCredentialsSecret() error {
	secrets, err := c.k8s.KubernetesClient.CoreV1().Secrets(c.configMapNamespace).List(context.Background(),
		metav1.ListOptions{LabelSelector: credsLabelSelectors})
	if err != nil {
		return err
	}

	if len(secrets.Items) == 0 {
		return nil
	}

	if jsonConf, ok := secrets.Items[0].Data["account"]; ok {
		if account := string(jsonConf); account != "" {
			c.configObj.AccountID = account
		}
	}

	if jsonConf, ok := secrets.Items[0].Data["accessKey"]; ok {
		if accessKey := string(jsonConf); accessKey != "" {
			c.configObj.AccessKey = accessKey
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

func existsConfigFile() bool {
	_, err := os.ReadFile(ConfigFileFullPath())
	return err == nil
}

func updateConfigFile(configObj *ConfigObj) error {
	fullPath := ConfigFileFullPath()
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	return os.WriteFile(fullPath, configObj.Config(), 0664) //nolint:gosec
}

func (c *ClusterConfig) GenerateAccountID() (string, error) {
	c.configObj.AccountID = uuid.NewString()
	err := c.UpdateCachedConfig()
	return c.configObj.AccountID, err
}

func (c *ClusterConfig) DeleteCredentials() error {
	c.configObj.AccountID = ""
	c.configObj.AccessKey = ""
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

// GetConfigMapNamespace returns the namespace of the cluster config, which is the same for all in-cluster components
func GetConfigMapNamespace() string {
	if n := os.Getenv(defaultConfigMapNamespaceEnvVar); n != "" {
		return n
	}
	return kubescapeNamespace
}

func updateCredentials(configObj *ConfigObj, accountID, accessKey string) {
	if accessKey != "" {
		configObj.AccessKey = accessKey
	}

	if envAccessKey := os.Getenv(accessKeyEnvVar); envAccessKey != "" {
		configObj.AccessKey = envAccessKey
	}

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
		logger.L().Debug("cloud API URL updated from env var", helpers.Interface(cloudApiUrlEnvVar, cloudAPIURL))
		cloudURLs.CloudAPIURL = cloudAPIURL
	}
	if cloudReportURL := os.Getenv(cloudReportUrlEnvVar); cloudReportURL != "" {
		logger.L().Debug("cloud Report URL updated from env var", helpers.Interface(cloudReportUrlEnvVar, cloudReportURL))
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

func initializeCloudAPI(c ITenantConfig) *v1.KSCloudAPI {
	if ksCloud := getter.GetKSCloudAPIConnector(); ksCloud != nil {

		if val := c.GetCloudAPIURL(); val != "" && val != ksCloud.GetCloudAPIURL() {
			logger.L().Debug("updating KS Cloud API from config", helpers.String("old", ksCloud.GetCloudAPIURL()), helpers.String("new", val))
			ksCloud.SetCloudAPIURL(val)
		}
		if val := c.GetCloudReportURL(); val != "" && val != ksCloud.GetCloudReportURL() {
			logger.L().Debug("updating KS Cloud Report from config", helpers.String("old", ksCloud.GetCloudReportURL()), helpers.String("new", val))
			ksCloud.SetCloudReportURL(val)
		}
		if val := c.GetAccountID(); val != "" && val != ksCloud.GetAccountID() {
			logger.L().Debug("updating Account ID from config", helpers.String("old", ksCloud.GetAccountID()), helpers.String("new", val))
			ksCloud.SetAccountID(val)
		}
		if val := c.GetAccessKey(); val != "" && val != ksCloud.GetAccessKey() {
			logger.L().Debug("updating Access Key from config", helpers.Int("old (len)", len(ksCloud.GetAccessKey())), helpers.Int("new (len)", len(val)))
			ksCloud.SetAccessKey(val)
		}
		getter.SetKSCloudAPIConnector(ksCloud)
	} else {
		logger.L().Debug("initializing KS Cloud API from config", helpers.String("accountID", c.GetAccountID()), helpers.String("cloudAPIURL", c.GetCloudAPIURL()), helpers.String("cloudReportURL", c.GetCloudReportURL()))
		cloud, err := v1.NewKSCloudAPI(
			c.GetCloudAPIURL(),
			c.GetCloudReportURL(),
			c.GetAccountID(),
			c.GetAccessKey())
		if err != nil {
			logger.L().Fatal("failed to create KS Cloud client", helpers.Error(err))
		}
		getter.SetKSCloudAPIConnector(cloud)
	}

	return getter.GetKSCloudAPIConnector()
}

func GetTenantConfig(accountID, accessKey, clusterName, customClusterName string, k8s *k8sinterface.KubernetesApi) ITenantConfig {
	if !k8sinterface.IsConnectedToCluster() || k8s == nil {
		return NewLocalConfig(accountID, accessKey, clusterName, customClusterName)
	}
	return NewClusterConfig(k8s, accountID, accessKey, clusterName, customClusterName)
}

// firstNonEmpty returns the first non-empty string
func firstNonEmpty(s1, s2 string) string {
	if s1 != "" {
		return s1
	}
	return s2
}
