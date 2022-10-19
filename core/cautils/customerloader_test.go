package cautils

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func mockConfigObj() *ConfigObj {
	return &ConfigObj{
		AccountID:          "aaa",
		ClientID:           "bbb",
		SecretKey:          "ccc",
		ClusterName:        "ddd",
		CustomerAdminEMail: "ab@cd",
		Token:              "eee",
		CloudReport:        "report.armo.cloud",
		CloudAPI:           "api.armosec.io",
		CloudUI:            "cloud.armosec.io",
		CloudAuth:          "auth.armosec.io",
	}
}
func mockLocalConfig() *LocalConfig {
	return &LocalConfig{
		backendAPI: nil,
		configObj:  mockConfigObj(),
	}
}

func mockClusterConfig() *ClusterConfig {
	return &ClusterConfig{
		backendAPI: nil,
		configObj:  mockConfigObj(),
	}
}
func TestConfig(t *testing.T) {
	co := mockConfigObj()
	cop := ConfigObj{}

	assert.NoError(t, json.Unmarshal(co.Config(), &cop))
	assert.Equal(t, co.AccountID, cop.AccountID)
	assert.Equal(t, co.ClientID, cop.ClientID)
	assert.Equal(t, co.SecretKey, cop.SecretKey)
	assert.Equal(t, co.CloudReport, cop.CloudReport)
	assert.Equal(t, co.CloudAPI, cop.CloudAPI)
	assert.Equal(t, co.CloudUI, cop.CloudUI)
	assert.Equal(t, co.CloudAuth, cop.CloudAuth)
	assert.Equal(t, "", cop.ClusterName)        // Not copied to bytes
	assert.Equal(t, "", cop.CustomerAdminEMail) // Not copied to bytes
	assert.Equal(t, "", cop.Token)              // Not copied to bytes

}

func TestITenantConfig(t *testing.T) {
	var lc ITenantConfig
	var c ITenantConfig
	lc = mockLocalConfig()
	c = mockClusterConfig()

	co := mockConfigObj()

	// test LocalConfig methods
	assert.Equal(t, co.AccountID, lc.GetAccountID())
	assert.Equal(t, co.ClientID, lc.GetClientID())
	assert.Equal(t, co.SecretKey, lc.GetSecretKey())
	assert.Equal(t, co.ClusterName, lc.GetContextName())
	assert.Equal(t, co.CustomerAdminEMail, lc.GetTenantEmail())
	assert.Equal(t, co.Token, lc.GetToken())
	assert.Equal(t, co.CloudReport, lc.GetCloudReport())
	assert.Equal(t, co.CloudAPI, lc.GetCloudAPI())
	assert.Equal(t, co.CloudUI, lc.GetCloudUI())
	assert.Equal(t, co.CloudAuth, lc.GetCloudAuth())

	// test ClusterConfig methods
	assert.Equal(t, co.AccountID, c.GetAccountID())
	assert.Equal(t, co.ClientID, c.GetClientID())
	assert.Equal(t, co.SecretKey, c.GetSecretKey())
	assert.Equal(t, co.ClusterName, c.GetContextName())
	assert.Equal(t, co.CustomerAdminEMail, c.GetTenantEmail())
	assert.Equal(t, co.Token, c.GetToken())
	assert.Equal(t, co.CloudReport, c.GetCloudReport())
	assert.Equal(t, co.CloudAPI, c.GetCloudAPI())
	assert.Equal(t, co.CloudUI, c.GetCloudUI())
	assert.Equal(t, co.CloudAuth, c.GetCloudAuth())
}

func TestUpdateConfigData(t *testing.T) {
	c := mockClusterConfig()

	configMap := &corev1.ConfigMap{}

	c.updateConfigData(configMap)

	assert.Equal(t, c.GetAccountID(), configMap.Data["accountID"])
	assert.Equal(t, c.GetClientID(), configMap.Data["clientID"])
	assert.Equal(t, c.GetSecretKey(), configMap.Data["secretKey"])
	assert.Equal(t, c.GetCloudReport(), configMap.Data["cloudReport"])
	assert.Equal(t, c.GetCloudAPI(), configMap.Data["cloudAPI"])
	assert.Equal(t, c.GetCloudUI(), configMap.Data["cloudUI"])
	assert.Equal(t, c.GetCloudAuth(), configMap.Data["cloudAuth"])
}

func TestReadConfig(t *testing.T) {
	com := mockConfigObj()
	co := &ConfigObj{}

	b, e := json.Marshal(com)
	assert.NoError(t, e)

	readConfig(b, co)

	assert.Equal(t, com.AccountID, co.AccountID)
	assert.Equal(t, com.ClientID, co.ClientID)
	assert.Equal(t, com.SecretKey, co.SecretKey)
	assert.Equal(t, com.ClusterName, co.ClusterName)
	assert.Equal(t, com.CustomerAdminEMail, co.CustomerAdminEMail)
	assert.Equal(t, com.Token, co.Token)
	assert.Equal(t, com.CloudReport, co.CloudReport)
	assert.Equal(t, com.CloudAPI, co.CloudAPI)
	assert.Equal(t, com.CloudUI, co.CloudUI)
	assert.Equal(t, com.CloudAuth, co.CloudAuth)
}

func TestLoadConfigFromData(t *testing.T) {

	// use case: all data is in base config
	{
		c := mockClusterConfig()
		co := mockConfigObj()

		configMap := &corev1.ConfigMap{}

		c.updateConfigData(configMap)

		c.configObj = &ConfigObj{}

		loadConfigFromData(c.configObj, configMap.Data)

		assert.Equal(t, c.GetAccountID(), co.AccountID)
		assert.Equal(t, c.GetClientID(), co.ClientID)
		assert.Equal(t, c.GetSecretKey(), co.SecretKey)
		assert.Equal(t, c.GetContextName(), co.ClusterName)
		assert.Equal(t, c.GetTenantEmail(), co.CustomerAdminEMail)
		assert.Equal(t, c.GetToken(), co.Token)
		assert.Equal(t, c.GetCloudReport(), co.CloudReport)
		assert.Equal(t, c.GetCloudAPI(), co.CloudAPI)
		assert.Equal(t, c.GetCloudUI(), co.CloudUI)
		assert.Equal(t, c.GetCloudAuth(), co.CloudAuth)
	}

	// use case: all data is in config.json
	{
		c := mockClusterConfig()

		co := mockConfigObj()
		configMap := &corev1.ConfigMap{
			Data: make(map[string]string),
		}

		configMap.Data["config.json"] = string(c.GetConfigObj().Config())
		c.configObj = &ConfigObj{}

		loadConfigFromData(c.configObj, configMap.Data)

		assert.Equal(t, c.GetAccountID(), co.AccountID)
		assert.Equal(t, c.GetClientID(), co.ClientID)
		assert.Equal(t, c.GetSecretKey(), co.SecretKey)
		assert.Equal(t, c.GetCloudReport(), co.CloudReport)
		assert.Equal(t, c.GetCloudAPI(), co.CloudAPI)
		assert.Equal(t, c.GetCloudUI(), co.CloudUI)
		assert.Equal(t, c.GetCloudAuth(), co.CloudAuth)
	}

	// use case: some data is in config.json
	{
		c := mockClusterConfig()
		configMap := &corev1.ConfigMap{
			Data: make(map[string]string),
		}

		// add to map
		configMap.Data["clientID"] = c.configObj.ClientID
		configMap.Data["secretKey"] = c.configObj.SecretKey
		configMap.Data["cloudReport"] = c.configObj.CloudReport

		// delete the content
		c.configObj.ClientID = ""
		c.configObj.SecretKey = ""
		c.configObj.CloudReport = ""

		configMap.Data["config.json"] = string(c.GetConfigObj().Config())
		loadConfigFromData(c.configObj, configMap.Data)

		assert.NotEmpty(t, c.GetAccountID())
		assert.NotEmpty(t, c.GetClientID())
		assert.NotEmpty(t, c.GetSecretKey())
		assert.NotEmpty(t, c.GetCloudReport())
	}

	// use case: some data is in config.json
	{
		c := mockClusterConfig()
		configMap := &corev1.ConfigMap{
			Data: make(map[string]string),
		}

		c.configObj.AccountID = "tttt"

		// add to map
		configMap.Data["accountID"] = mockConfigObj().AccountID
		configMap.Data["clientID"] = c.configObj.ClientID
		configMap.Data["secretKey"] = c.configObj.SecretKey

		// delete the content
		c.configObj.ClientID = ""
		c.configObj.SecretKey = ""

		configMap.Data["config.json"] = string(c.GetConfigObj().Config())
		loadConfigFromData(c.configObj, configMap.Data)

		assert.Equal(t, mockConfigObj().AccountID, c.GetAccountID())
		assert.NotEmpty(t, c.GetClientID())
		assert.NotEmpty(t, c.GetSecretKey())
	}

}

func TestAdoptClusterName(t *testing.T) {
	tests := []struct {
		name        string
		clusterName string
		want        string
	}{
		{
			name:        "replace 1",
			clusterName: "my-name__is--ks",
			want:        "my-name__is-ks",
		},
		{
			name:        "replace 2",
			clusterName: "my-name1",
			want:        "my-name1",
		},
		{
			name:        "replace 3",
			clusterName: "my:name",
			want:        "my-name",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AdoptClusterName(tt.clusterName); got != tt.want {
				t.Errorf("AdoptClusterName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUpdateCloudURLs(t *testing.T) {
	co := mockConfigObj()
	mockCloudAPI := "1-2-3-4.com"
	os.Setenv("KS_CLOUD_API_URL", mockCloudAPI)

	assert.NotEqual(t, co.CloudAPI, mockCloudAPI)
	updateCloudURLs(co)
	assert.Equal(t, co.CloudAPI, mockCloudAPI)
}
