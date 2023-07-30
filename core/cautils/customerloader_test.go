package cautils

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/kubescape/kubescape/v2/core/cautils/getter"
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
		CloudReportURL:     "report.armo.cloud",
		CloudAPIURL:        "api.armosec.io",
		CloudUIURL:         "cloud.armosec.io",
		CloudAuthURL:       "auth.armosec.io",
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
	assert.Equal(t, co.CloudReportURL, cop.CloudReportURL)
	assert.Equal(t, co.CloudAPIURL, cop.CloudAPIURL)
	assert.Equal(t, co.CloudUIURL, cop.CloudUIURL)
	assert.Equal(t, co.CloudAuthURL, cop.CloudAuthURL)
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
	assert.Equal(t, co.CloudReportURL, lc.GetCloudReportURL())
	assert.Equal(t, co.CloudAPIURL, lc.GetCloudAPIURL())
	assert.Equal(t, co.CloudUIURL, lc.GetCloudUIURL())
	assert.Equal(t, co.CloudAuthURL, lc.GetCloudAuthURL())

	// test ClusterConfig methods
	assert.Equal(t, co.AccountID, c.GetAccountID())
	assert.Equal(t, co.ClientID, c.GetClientID())
	assert.Equal(t, co.SecretKey, c.GetSecretKey())
	assert.Equal(t, co.ClusterName, c.GetContextName())
	assert.Equal(t, co.CustomerAdminEMail, c.GetTenantEmail())
	assert.Equal(t, co.Token, c.GetToken())
	assert.Equal(t, co.CloudReportURL, c.GetCloudReportURL())
	assert.Equal(t, co.CloudAPIURL, c.GetCloudAPIURL())
	assert.Equal(t, co.CloudUIURL, c.GetCloudUIURL())
	assert.Equal(t, co.CloudAuthURL, c.GetCloudAuthURL())
}

func TestUpdateConfigData(t *testing.T) {
	c := mockClusterConfig()

	configMap := &corev1.ConfigMap{}

	c.updateConfigData(configMap)

	assert.Equal(t, c.GetAccountID(), configMap.Data["accountID"])
	assert.Equal(t, c.GetClientID(), configMap.Data["clientID"])
	assert.Equal(t, c.GetSecretKey(), configMap.Data["secretKey"])
	assert.Equal(t, c.GetCloudReportURL(), configMap.Data["cloudReportURL"])
	assert.Equal(t, c.GetCloudAPIURL(), configMap.Data["cloudAPIURL"])
	assert.Equal(t, c.GetCloudUIURL(), configMap.Data["cloudUIURL"])
	assert.Equal(t, c.GetCloudAuthURL(), configMap.Data["cloudAuthURL"])
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
	assert.Equal(t, com.CloudReportURL, co.CloudReportURL)
	assert.Equal(t, com.CloudAPIURL, co.CloudAPIURL)
	assert.Equal(t, com.CloudUIURL, co.CloudUIURL)
	assert.Equal(t, com.CloudAuthURL, co.CloudAuthURL)
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
		assert.Equal(t, c.GetCloudReportURL(), co.CloudReportURL)
		assert.Equal(t, c.GetCloudAPIURL(), co.CloudAPIURL)
		assert.Equal(t, c.GetCloudUIURL(), co.CloudUIURL)
		assert.Equal(t, c.GetCloudAuthURL(), co.CloudAuthURL)
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
		assert.Equal(t, c.GetCloudReportURL(), co.CloudReportURL)
		assert.Equal(t, c.GetCloudAPIURL(), co.CloudAPIURL)
		assert.Equal(t, c.GetCloudUIURL(), co.CloudUIURL)
		assert.Equal(t, c.GetCloudAuthURL(), co.CloudAuthURL)
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
		configMap.Data["cloudReportURL"] = c.configObj.CloudReportURL

		// delete the content
		c.configObj.ClientID = ""
		c.configObj.SecretKey = ""
		c.configObj.CloudReportURL = ""

		configMap.Data["config.json"] = string(c.GetConfigObj().Config())
		loadConfigFromData(c.configObj, configMap.Data)

		assert.NotEmpty(t, c.GetAccountID())
		assert.NotEmpty(t, c.GetClientID())
		assert.NotEmpty(t, c.GetSecretKey())
		assert.NotEmpty(t, c.GetCloudReportURL())
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
	mockCloudAPIURL := "1-2-3-4.com"
	os.Setenv("KS_CLOUD_API_URL", mockCloudAPIURL)

	assert.NotEqual(t, co.CloudAPIURL, mockCloudAPIURL)
	updateCloudURLs(co)
	assert.Equal(t, co.CloudAPIURL, mockCloudAPIURL)
}

func Test_initializeCloudAPI(t *testing.T) {
	type args struct {
		c ITenantConfig
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "test",
			args: args{
				c: mockClusterConfig(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			initializeCloudAPI(tt.args.c)
			cloud := getter.GetKSCloudAPIConnector()
			assert.Equal(t, tt.args.c.GetCloudAPIURL(), cloud.GetCloudAPIURL())
			assert.Equal(t, tt.args.c.GetCloudAuthURL(), cloud.GetCloudAuthURL())
			assert.Equal(t, tt.args.c.GetCloudUIURL(), cloud.GetCloudUIURL())
			assert.Equal(t, tt.args.c.GetCloudReportURL(), cloud.GetCloudReportURL())
			assert.Equal(t, tt.args.c.GetAccountID(), cloud.GetAccountID())
			assert.Equal(t, tt.args.c.GetClientID(), cloud.GetClientID())
			assert.Equal(t, tt.args.c.GetSecretKey(), cloud.GetSecretKey())
		})
	}
}

func TestGetConfigMapNamespace(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want string
	}{
		{
			name: "no env",
			want: "kubescape",
		},
		{
			name: "default ns",
			env:  "kubescape",
			want: "kubescape",
		},
		{
			name: "custom ns",
			env:  "my-ns",
			want: "my-ns",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.env != "" {
				_ = os.Setenv("KS_DEFAULT_CONFIGMAP_NAMESPACE", tt.env)
			}
			assert.Equalf(t, tt.want, GetConfigMapNamespace(), "GetConfigMapNamespace()")
		})
	}
}

const (
	anyString       string = "anyString"
	shouldNotUpdate string = "shouldNotUpdate"
	shouldUpdate    string = "shouldUpdate"
)

func checkIsUpdateCorrectly(t *testing.T, beforeField string, afterField string) {
	switch beforeField {
	case anyString:
		assert.Equal(t, anyString, afterField)
	case "":
		assert.Equal(t, shouldUpdate, afterField)
	}
}

func TestUpdateEmptyFields(t *testing.T) {

	tests := []struct {
		inCo  *ConfigObj
		outCo *ConfigObj
	}{
		{
			outCo: &ConfigObj{
				AccountID:          "",
				ClientID:           "",
				SecretKey:          "",
				CustomerGUID:       "",
				Token:              "",
				CustomerAdminEMail: "",
				ClusterName:        "",
				CloudReportURL:     "",
				CloudAPIURL:        "",
				CloudUIURL:         "",
				CloudAuthURL:       "",
			},
			inCo: &ConfigObj{
				AccountID:          shouldUpdate,
				ClientID:           shouldUpdate,
				SecretKey:          shouldUpdate,
				CustomerGUID:       shouldUpdate,
				Token:              shouldUpdate,
				CustomerAdminEMail: shouldUpdate,
				ClusterName:        shouldUpdate,
				CloudReportURL:     shouldUpdate,
				CloudAPIURL:        shouldUpdate,
				CloudUIURL:         shouldUpdate,
				CloudAuthURL:       shouldUpdate,
			},
		},
		{
			outCo: &ConfigObj{
				AccountID:          anyString,
				ClientID:           anyString,
				SecretKey:          anyString,
				CustomerGUID:       anyString,
				Token:              anyString,
				CustomerAdminEMail: "",
				ClusterName:        "",
				CloudReportURL:     "",
				CloudAPIURL:        "",
				CloudUIURL:         "",
				CloudAuthURL:       "",
			},
			inCo: &ConfigObj{
				AccountID:          shouldNotUpdate,
				ClientID:           shouldNotUpdate,
				SecretKey:          shouldNotUpdate,
				CustomerGUID:       shouldNotUpdate,
				Token:              shouldNotUpdate,
				CustomerAdminEMail: shouldUpdate,
				ClusterName:        shouldUpdate,
				CloudReportURL:     shouldUpdate,
				CloudAPIURL:        shouldUpdate,
				CloudUIURL:         shouldUpdate,
				CloudAuthURL:       shouldUpdate,
			},
		},
		{
			outCo: &ConfigObj{
				AccountID:          "",
				ClientID:           "",
				SecretKey:          "",
				CustomerGUID:       "",
				Token:              "",
				CustomerAdminEMail: anyString,
				ClusterName:        anyString,
				CloudReportURL:     anyString,
				CloudAPIURL:        anyString,
				CloudUIURL:         anyString,
				CloudAuthURL:       anyString,
			},
			inCo: &ConfigObj{
				AccountID:          shouldUpdate,
				ClientID:           shouldUpdate,
				SecretKey:          shouldUpdate,
				CustomerGUID:       shouldUpdate,
				Token:              shouldUpdate,
				CustomerAdminEMail: shouldNotUpdate,
				ClusterName:        shouldNotUpdate,
				CloudReportURL:     shouldNotUpdate,
				CloudAPIURL:        shouldNotUpdate,
				CloudUIURL:         shouldNotUpdate,
				CloudAuthURL:       shouldNotUpdate,
			},
		},
		{
			outCo: &ConfigObj{
				AccountID:          anyString,
				ClientID:           "",
				SecretKey:          anyString,
				CustomerGUID:       "",
				Token:              anyString,
				CustomerAdminEMail: "",
				ClusterName:        anyString,
				CloudReportURL:     "",
				CloudAPIURL:        anyString,
				CloudUIURL:         "",
				CloudAuthURL:       anyString,
			},
			inCo: &ConfigObj{
				AccountID:          shouldNotUpdate,
				ClientID:           shouldUpdate,
				SecretKey:          shouldNotUpdate,
				CustomerGUID:       shouldUpdate,
				Token:              shouldNotUpdate,
				CustomerAdminEMail: shouldUpdate,
				ClusterName:        shouldNotUpdate,
				CloudReportURL:     shouldUpdate,
				CloudAPIURL:        shouldNotUpdate,
				CloudUIURL:         shouldUpdate,
				CloudAuthURL:       shouldNotUpdate,
			},
		},
	}

	for i := range tests {
		beforeChangesOutCO := tests[i].outCo
		tests[i].outCo.UpdateEmptyFields(tests[i].inCo)
		checkIsUpdateCorrectly(t, beforeChangesOutCO.AccountID, tests[i].outCo.AccountID)
		checkIsUpdateCorrectly(t, beforeChangesOutCO.ClientID, tests[i].outCo.ClientID)
		checkIsUpdateCorrectly(t, beforeChangesOutCO.CloudAPIURL, tests[i].outCo.CloudAPIURL)
		checkIsUpdateCorrectly(t, beforeChangesOutCO.CloudAuthURL, tests[i].outCo.CloudAuthURL)
		checkIsUpdateCorrectly(t, beforeChangesOutCO.CloudReportURL, tests[i].outCo.CloudReportURL)
		checkIsUpdateCorrectly(t, beforeChangesOutCO.CloudUIURL, tests[i].outCo.CloudUIURL)
		checkIsUpdateCorrectly(t, beforeChangesOutCO.ClusterName, tests[i].outCo.ClusterName)
		checkIsUpdateCorrectly(t, beforeChangesOutCO.CustomerAdminEMail, tests[i].outCo.CustomerAdminEMail)
		checkIsUpdateCorrectly(t, beforeChangesOutCO.CustomerGUID, tests[i].outCo.CustomerGUID)
		checkIsUpdateCorrectly(t, beforeChangesOutCO.SecretKey, tests[i].outCo.SecretKey)
		checkIsUpdateCorrectly(t, beforeChangesOutCO.Token, tests[i].outCo.Token)
	}
}
