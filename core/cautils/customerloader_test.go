package cautils

import (
	"encoding/json"
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

	// test ClusterConfig methods
	assert.Equal(t, co.AccountID, c.GetAccountID())
	assert.Equal(t, co.ClientID, c.GetClientID())
	assert.Equal(t, co.SecretKey, c.GetSecretKey())
	assert.Equal(t, co.ClusterName, c.GetContextName())
	assert.Equal(t, co.CustomerAdminEMail, c.GetTenantEmail())
	assert.Equal(t, co.Token, c.GetToken())
}

func TestUpdateConfigData(t *testing.T) {
	c := mockClusterConfig()

	configMap := &corev1.ConfigMap{}

	c.updateConfigData(configMap)

	assert.Equal(t, c.GetAccountID(), configMap.Data["accountID"])
	assert.Equal(t, c.GetClientID(), configMap.Data["clientID"])
	assert.Equal(t, c.GetSecretKey(), configMap.Data["secretKey"])
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

		// delete the content
		c.configObj.ClientID = ""
		c.configObj.SecretKey = ""

		configMap.Data["config.json"] = string(c.GetConfigObj().Config())
		loadConfigFromData(c.configObj, configMap.Data)

		assert.NotEmpty(t, c.GetAccountID())
		assert.NotEmpty(t, c.GetClientID())
		assert.NotEmpty(t, c.GetSecretKey())
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
