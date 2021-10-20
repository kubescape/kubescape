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

	"github.com/armosec/k8s-interface/k8sinterface"
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
type IClusterConfig interface {

	// set
	SetConfig(customerGUID string) error

	// getters
	GetClusterName() string
	GetCustomerGUID() string
	GetConfigObj() *ConfigObj
	GetK8sAPI() *k8sinterface.KubernetesApi
	GetBackendAPI() getter.IBackend
	GetDefaultNS() string
	GenerateURL()
}

// ClusterConfigSetup - Setup the desired cluster behavior regarding submittion to the Armo BE
func ClusterConfigSetup(scanInfo *ScanInfo, k8s *k8sinterface.KubernetesApi, beAPI getter.IBackend) IClusterConfig {
	/*

		If "First run (local config not found)" -
			Default - Do not send report (local)
			Local - Do not send report
			Submit - Create tenant & Submit report

		If "Submitted but not signed up" -
			Default	- Delete local config & Do not send report (local)
			Local - Delete local config & Do not send report
			Submit - Submit report

		If "Signed up user" -
			Default	- Submit report (submit)
			Local - Do not send report
			Submit - Submit report

	*/
	clusterConfig := NewClusterConfig(k8s, beAPI)
	clusterConfig.LoadConfig()

	if !IsSubmitted(clusterConfig) {
		if scanInfo.Submit {
			return clusterConfig // submit - Create tenant & Submit report
		}
		return NewEmptyConfig() // local/default - Do not send report
	}
	if !IsRegistered(clusterConfig) {
		if scanInfo.Submit {
			return clusterConfig // submit/default - Submit report
		}
		DeleteConfig(k8s)
		return NewEmptyConfig() // local - Delete local config & Do not send report
	}
	if scanInfo.Local {
		return NewEmptyConfig() // local - Do not send report
	}
	return clusterConfig // submit/default -  Submit report
}

// ======================================================================================
// ============================= Mock Config ============================================
// ======================================================================================
type EmptyConfig struct {
}

func NewEmptyConfig() *EmptyConfig                            { return &EmptyConfig{} }
func (c *EmptyConfig) SetConfig(customerGUID string) error    { return nil }
func (c *EmptyConfig) GetConfigObj() *ConfigObj               { return &ConfigObj{} }
func (c *EmptyConfig) GetCustomerGUID() string                { return "" }
func (c *EmptyConfig) GetK8sAPI() *k8sinterface.KubernetesApi { return nil } // TODO: return mock obj
func (c *EmptyConfig) GetDefaultNS() string                   { return k8sinterface.GetDefaultNamespace() }
func (c *EmptyConfig) GetBackendAPI() getter.IBackend         { return nil } // TODO: return mock obj
func (c *EmptyConfig) GetClusterName() string                 { return "unknown" }
func (c *EmptyConfig) GenerateURL() {
	message := fmt.Sprintf("\nCheckout for more cool features: https://%s\n", getter.GetArmoAPIConnector().GetFrontendURL())
	InfoTextDisplay(os.Stdout, fmt.Sprintf("\n%s\n", message))
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

func NewClusterConfig(k8s *k8sinterface.KubernetesApi, backendAPI getter.IBackend) *ClusterConfig {
	return &ClusterConfig{
		k8s:        k8s,
		backendAPI: backendAPI,
		configObj:  &ConfigObj{},
		defaultNS:  k8sinterface.GetDefaultNamespace(),
	}
}
func (c *ClusterConfig) GetConfigObj() *ConfigObj               { return c.configObj }
func (c *ClusterConfig) GetK8sAPI() *k8sinterface.KubernetesApi { return c.k8s }
func (c *ClusterConfig) GetDefaultNS() string                   { return c.defaultNS }
func (c *ClusterConfig) GetBackendAPI() getter.IBackend         { return c.backendAPI }

func (c *ClusterConfig) GenerateURL() {

	u := url.URL{}
	u.Scheme = "https"
	u.Host = getter.GetArmoAPIConnector().GetFrontendURL()
	if c.configObj == nil {
		return
	}
	message := fmt.Sprintf("\nCheckout for more cool features: https://%s\n", getter.GetArmoAPIConnector().GetFrontendURL())
	if c.configObj.CustomerAdminEMail != "" {
		InfoTextDisplay(os.Stdout, message+"\n")
		return
	}
	u.Path = "account/sign-up"
	q := u.Query()
	q.Add("invitationToken", c.configObj.Token)
	q.Add("customerGUID", c.configObj.CustomerGUID)

	u.RawQuery = q.Encode()
	InfoTextDisplay(os.Stdout, message+"\n")

}

func (c *ClusterConfig) GetCustomerGUID() string {
	if c.configObj != nil {
		return c.configObj.CustomerGUID
	}
	return ""
}

func (c *ClusterConfig) SetConfig(customerGUID string) error {
	if c.configObj == nil {
		c.configObj = &ConfigObj{}
	}

	// cluster name
	if c.GetClusterName() == "" {
		c.setClusterName(k8sinterface.GetClusterName())
	}

	// ARMO customer GUID
	if customerGUID != "" && c.GetCustomerGUID() != customerGUID {
		c.setCustomerGUID(customerGUID) // override config customerGUID
	}

	customerGUID = c.GetCustomerGUID()

	// get from armoBE
	tenantResponse, err := c.backendAPI.GetCustomerGUID(customerGUID)
	if err == nil && tenantResponse != nil {
		if tenantResponse.AdminMail != "" { // this customer already belongs to some user
			c.setCustomerAdminEMail(tenantResponse.AdminMail)
		} else {
			c.setToken(tenantResponse.Token)
			c.setCustomerGUID(tenantResponse.TenantID)
		}
	} else {
		if err != nil && !strings.Contains(err.Error(), "already exists") {
			return err
		}
	}

	// update/create config
	if c.existsConfigMap() {
		c.updateConfigMap()
	} else {
		c.createConfigMap()
	}
	c.updateConfigFile()

	return nil
}

func (c *ClusterConfig) setToken(token string) {
	c.configObj.Token = token
}

func (c *ClusterConfig) setCustomerAdminEMail(customerAdminEMail string) {
	c.configObj.CustomerAdminEMail = customerAdminEMail
}
func (c *ClusterConfig) setCustomerGUID(customerGUID string) {
	c.configObj.CustomerGUID = customerGUID
}

func (c *ClusterConfig) setClusterName(clusterName string) {
	c.configObj.ClusterName = clusterName
}
func (c *ClusterConfig) GetClusterName() string {
	return c.configObj.ClusterName
}
func (c *ClusterConfig) LoadConfig() {
	// get from configMap
	if c.existsConfigMap() {
		c.configObj, _ = c.loadConfigFromConfigMap()
	} else if existsConfigFile() { // get from file
		c.configObj, _ = loadConfigFromFile()
	} else {
		c.configObj = &ConfigObj{}
	}
}

func (c *ClusterConfig) ToMapString() map[string]interface{} {
	m := map[string]interface{}{}
	if bc, err := json.Marshal(c.configObj); err == nil {
		json.Unmarshal(bc, &m)
	}
	return m
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

func (c *ClusterConfig) updateConfigFile() error {
	if err := os.WriteFile(ConfigFileFullPath(), c.configObj.Config(), 0664); err != nil {
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
func IsSubmitted(clusterConfig *ClusterConfig) bool {
	return clusterConfig.existsConfigMap() || existsConfigFile()
}

// Check if the customer is registered
func IsRegistered(clusterConfig *ClusterConfig) bool {

	// get from armoBE
	tenantResponse, err := clusterConfig.backendAPI.GetCustomerGUID(clusterConfig.GetCustomerGUID())
	if err == nil && tenantResponse != nil {
		if tenantResponse.AdminMail != "" { // this customer already belongs to some user
			return true
		}
	}
	return false
}

func DeleteConfig(k8s *k8sinterface.KubernetesApi) error {
	if err := DeleteConfigMap(k8s); err != nil {
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
