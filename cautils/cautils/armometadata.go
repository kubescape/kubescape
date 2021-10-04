package cautils

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/golang/glog"
)

// labels added to the workload
const (
	ArmoPrefix          string = "armo"
	ArmoAttach          string = ArmoPrefix + ".attach"
	ArmoInitialSecret   string = ArmoPrefix + ".initial"
	ArmoSecretStatus    string = ArmoPrefix + ".secret"
	ArmoCompatibleLabel string = ArmoPrefix + ".compatible"

	ArmoSecretProtectStatus string = "protect"
	ArmoSecretClearStatus   string = "clear"
)

// annotations added to the workload
const (
	ArmoUpdate               string = ArmoPrefix + ".last-update"
	ArmoWlid                 string = ArmoPrefix + ".wlid"
	ArmoSid                  string = ArmoPrefix + ".sid"
	ArmoJobID                string = ArmoPrefix + ".job"
	ArmoJobIDPath            string = ArmoJobID + "/id"
	ArmoJobParentPath        string = ArmoJobID + "/parent"
	ArmoJobActionPath        string = ArmoJobID + "/action"
	ArmoCompatibleAnnotation string = ArmoAttach + "/compatible"
	ArmoReplaceheaders       string = ArmoAttach + "/replaceheaders"
)

const ( // DEPRECATED

	CAAttachLabel string = "cyberarmor"
	Patched       string = "Patched"
	Done          string = "Done"
	Encrypted     string = "Protected"

	CAInjectOld = "injectCyberArmor"

	CAPrefix          string = "cyberarmor"
	CAProtectedSecret string = CAPrefix + ".secret"
	CAInitialSecret   string = CAPrefix + ".initial"
	CAInject          string = CAPrefix + ".inject"
	CAIgnore          string = CAPrefix + ".ignore"
	CAReplaceHeaders  string = CAPrefix + ".removeSecurityHeaders"
)

const ( // DEPRECATED
	CAUpdate string = CAPrefix + ".last-update"
	CAStatus string = CAPrefix + ".status"
	CAWlid   string = CAPrefix + ".wlid"
)

type ClusterConfig struct {
	EventReceiverREST       string `json:"eventReceiverREST"`
	EventReceiverWS         string `json:"eventReceiverWS"`
	MaserNotificationServer string `json:"maserNotificationServer"`
	Postman                 string `json:"postman"`
	Dashboard               string `json:"dashboard"`
	Portal                  string `json:"portal"`
	CustomerGUID            string `json:"customerGUID"`
	ClusterGUID             string `json:"clusterGUID"`
	ClusterName             string `json:"clusterName"`
	OciImageURL             string `json:"ociImageURL"`
	NotificationWSURL       string `json:"notificationWSURL"`
	NotificationRestURL     string `json:"notificationRestURL"`
	VulnScanURL             string `json:"vulnScanURL"`
	OracleURL               string `json:"oracleURL"`
	ClairURL                string `json:"clairURL"`
}

// represents workload basic info
type SpiffeBasicInfo struct {
	//cluster/datacenter
	Level0     string `json:"level0"`
	Level0Type string `json:"level0Type"`

	//namespace/project
	Level1     string `json:"level0"`
	Level1Type string `json:"level0Type"`

	Kind string `json:"kind"`
	Name string `json:"name"`
}

type ImageInfo struct {
	Registry     string `json:"registry"`
	VersionImage string `json:"versionImage"`
}

func IsAttached(labels map[string]string) *bool {
	attach := false
	if labels == nil {
		return nil
	}
	if attached, ok := labels[ArmoAttach]; ok {
		if strings.ToLower(attached) == "true" {
			attach = true
			return &attach
		} else {
			return &attach
		}
	}

	// deprecated
	if _, ok := labels[CAAttachLabel]; ok {
		attach = true
		return &attach
	}

	// deprecated
	if inject, ok := labels[CAInject]; ok {
		if strings.ToLower(inject) == "true" {
			attach = true
			return &attach
		}
	}

	// deprecated
	if ignore, ok := labels[CAIgnore]; ok {
		if strings.ToLower(ignore) == "true" {
			return &attach
		}
	}

	return nil
}

func IsSecretProtected(labels map[string]string) *bool {
	protect := false
	if labels == nil {
		return nil
	}
	if protected, ok := labels[ArmoSecretStatus]; ok {
		if strings.ToLower(protected) == ArmoSecretProtectStatus {
			protect = true
			return &protect
		} else {
			return &protect
		}
	}
	return nil
}

func LoadConfig(configPath string, loadToEnv bool) (*ClusterConfig, error) {
	if configPath == "" {
		configPath = "/etc/config/clusterData.json"
	}

	dat, err := os.ReadFile(configPath)
	if err != nil || len(dat) == 0 {
		return nil, fmt.Errorf("Config empty or not found. path: %s", configPath)
	}
	componentConfig := &ClusterConfig{}
	if err := json.Unmarshal(dat, componentConfig); err != nil {
		return componentConfig, fmt.Errorf("Failed to read component config, path: %s, reason: %s", configPath, err.Error())
	}
	if loadToEnv {
		componentConfig.LoadConfigToEnv()
	}
	return componentConfig, nil
}

func (clusterConfig *ClusterConfig) LoadConfigToEnv() {

	SetEnv("CA_CLUSTER_NAME", clusterConfig.ClusterName)
	SetEnv("CA_CLUSTER_GUID", clusterConfig.ClusterGUID)
	SetEnv("CA_ORACLE_SERVER", clusterConfig.OracleURL)
	SetEnv("CA_CUSTOMER_GUID", clusterConfig.CustomerGUID)
	SetEnv("CA_DASHBOARD_BACKEND", clusterConfig.Dashboard)
	SetEnv("CA_NOTIFICATION_SERVER_REST", clusterConfig.NotificationWSURL)
	SetEnv("CA_NOTIFICATION_SERVER_WS", clusterConfig.NotificationWSURL)
	SetEnv("CA_NOTIFICATION_SERVER_REST", clusterConfig.NotificationRestURL)
	SetEnv("CA_OCIMAGE_URL", clusterConfig.OciImageURL)
	SetEnv("CA_K8S_REPORT_URL", clusterConfig.EventReceiverWS)
	SetEnv("CA_EVENT_RECEIVER_HTTP", clusterConfig.EventReceiverREST)
	SetEnv("CA_VULNSCAN", clusterConfig.VulnScanURL)
	SetEnv("CA_POSTMAN", clusterConfig.Postman)
	SetEnv("MASTER_NOTIFICATION_SERVER_HOST", clusterConfig.MaserNotificationServer)
	SetEnv("CLAIR_URL", clusterConfig.ClairURL)

}

func SetEnv(key, value string) {
	if e := os.Getenv(key); e == "" {
		if err := os.Setenv(key, value); err != nil {
			glog.Warning("%s: %s", key, err.Error())
		}
	}
}
