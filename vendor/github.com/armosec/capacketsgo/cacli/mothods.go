package cacli

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/armosec/capacketsgo/opapolicy"
	"github.com/armosec/capacketsgo/secrethandling"
	"github.com/golang/glog"
)

// Cacli commands
type Cacli struct {
	backendURL  string
	credentials CredStruct
}

// NewCacli -
func NewCacli(backendURL string, setCredInEnv bool) *Cacli {
	// Load credentials from mounted secret
	credentials, err := LoadCredentials()
	if err != nil {
		glog.Error(err)
		os.Exit(1)
	}
	cacliObj := &Cacli{
		backendURL:  backendURL,
		credentials: *credentials,
	}

	// login cacli
	if err := cacliObj.cacliLogin(3); err != nil {
		glog.Error(err)
		os.Exit(1)
	}

	if setCredInEnv {
		if err := cacliObj.setCredentialsInEnv(); err != nil {
			glog.Error(err)
			os.Exit(1)
		}
	}

	return cacliObj
}

// NewCacliWithoutLogin -
func NewCacliWithoutLogin() *Cacli {

	cacliObj := &Cacli{}
	// loggedin, err := cacliObj.IsLoggedIn()
	// if err != nil || !loggedin {
	// 	glog.Errorf("Please run `cacli login`\n")
	// 	os.Exit(1)
	// }
	return cacliObj
}

// ================================================================================================
// ================================ BASIC =========================================================
// ================================================================================================

// Login command
func (cacli *Cacli) Login() error {
	args := []string{}
	args = append(args, "login")
	args = append(args, "-u")
	args = append(args, cacli.credentials.User)
	if cacli.credentials.Customer != "" {
		args = append(args, "-c")
		args = append(args, cacli.credentials.Customer)
	}
	args = append(args, "--dashboard")
	args = append(args, cacli.backendURL)

	// must be last argument
	args = append(args, "-p")
	args = append(args, cacli.credentials.Password)

	glog.Infof("Running: cacli %v", args[:len(args)-1])

	_, err := runCacliCommandWithTimeout(args, false, time.Duration(2)*time.Minute)
	return err
}

// Status -
func (cacli *Cacli) Status() (*Status, error) {
	status := &Status{}
	args := []string{}
	args = append(args, "--status")
	statusReceive, err := runCacliCommand(args, true)
	if err == nil {
		err = json.Unmarshal(statusReceive, status)
	}
	return status, err
}

// Sign command
func (cacli *Cacli) Sign(wlid, user, password, ociImageURL string) error {
	args := []string{}
	display := true
	args = append(args, "--debug")
	args = append(args, "sign")
	args = append(args, "-wlid")
	args = append(args, wlid)

	if ociImageURL != "" {
		args = append(args, "--dockerless-service-url")
		args = append(args, ociImageURL)
	}

	if user != "" && password != "" {
		display = false
		args = append(args, "--docker-registry-user")
		args = append(args, user)
		args = append(args, "--docker-registry-password")
		args = append(args, password)
	}

	_, err := runCacliCommandWithTimeout(args, display, time.Duration(8)*time.Minute)
	return err
}

// ================================================================================================
// ================================== vulnscan ==========================================================
// ================================================================================================
func (cacli *Cacli) VulnerabilityScan(cluster, namespace, wlid string, attributes map[string]interface{}) error {

	args := []string{}
	args = append(args, "k8s")
	args = append(args, "scan")
	if wlid != "" {
		args = append(args, "-wlid")
		args = append(args, wlid)
	} else if attributes == nil {
		if cluster == "" {
			return fmt.Errorf("invalid vulnerability scan request- missing cluster")
		}
		args = append(args, "--cluster")
		args = append(args, cluster)
		if namespace != "" {
			args = append(args, "--namespace")
			args = append(args, namespace)
		}
	}

	b, err := cacli.runCacliCommandRepeat(args, true, time.Duration(5)*time.Minute)
	if err != nil {
		return err
	}
	glog.Infof("%v", string(b))
	return nil
}

// ================================================================================================
// ================================== WT ==========================================================
// ================================================================================================

// Create command
func (cacli *Cacli) WTCreate(wt *WorkloadTemplate, fileName string) (string, error) {
	if fileName == "" {
		var err error
		if fileName, err = ConvertObjectTOFile(*wt); err != nil {
			return "", err
		}
	}

	args := []string{}
	args = append(args, "wt")
	args = append(args, "create")
	args = append(args, "-i")
	args = append(args, fileName)
	wlid, err := cacli.runCacliCommandRepeat(args, true, time.Duration(2)*time.Minute)
	if err != nil {
		return "", err
	}
	DeleteObjTmpFile(fileName)
	wlidMap := make(map[string]string)
	json.Unmarshal(wlid, &wlidMap)
	return wlidMap["wlid"], err
}

// Apply command
func (cacli *Cacli) WTApply(wt *WorkloadTemplate, fileName string) (string, error) {
	if fileName == "" {
		if wt == nil {
			return "", fmt.Errorf("missing wt and fileName, you must provide one of them")
		}
		f, err := StoreObjTmpFile(wt)
		if err != nil {
			return "", err
		}
		fileName = f
	}
	args := []string{}
	args = append(args, "wt")
	args = append(args, "apply")
	args = append(args, "-i")
	args = append(args, fileName)
	wlid, err := cacli.runCacliCommandRepeat(args, true, time.Duration(2)*time.Minute)
	if err != nil {
		return "", err
	}
	DeleteObjTmpFile(fileName)
	wlidMap := make(map[string]string)
	json.Unmarshal(wlid, &wlidMap)
	return wlidMap["wlid"], err
}

// Update command
func (cacli *Cacli) WTUpdate(wt *WorkloadTemplate, fileName string) (string, error) {
	if fileName == "" {
		if wt == nil {
			return "", fmt.Errorf("missing wt and fileName, you must provide one of them")
		}
		f, err := StoreObjTmpFile(wt)
		if err != nil {
			return "", err
		}
		fileName = f
	}
	args := []string{}
	args = append(args, "wt")
	args = append(args, "update")
	args = append(args, "-i")
	args = append(args, fileName)
	wlid, err := cacli.runCacliCommandRepeat(args, true, time.Duration(2)*time.Minute)
	if err != nil {
		return "", err
	}
	DeleteObjTmpFile(fileName)
	wlidMap := make(map[string]string)
	json.Unmarshal(wlid, &wlidMap)
	return wlidMap["wlid"], err
}

// Triplet command
func (cacli *Cacli) WTTriplet(wlid string) (*GUIDTriplet, error) {
	triplet := GUIDTriplet{}
	args := []string{}
	args = append(args, "wt")
	args = append(args, "triplet")
	args = append(args, "-wlid")
	args = append(args, wlid)
	tripletReceive, err := cacli.runCacliCommandRepeat(args, true, time.Duration(2)*time.Minute)
	if err == nil {
		json.Unmarshal(tripletReceive, &triplet)
	}
	return &triplet, err
}

// Get command
// func (cacli *Cacli) Get(wlid string) error {
func (cacli *Cacli) WTGet(wlid string) (*WorkloadTemplate, error) {
	wt := WorkloadTemplate{}
	args := []string{}
	args = append(args, "wt")
	args = append(args, "get")
	args = append(args, "-wlid")
	args = append(args, wlid)
	wtReceive, err := cacli.runCacliCommandRepeat(args, true, time.Duration(2)*time.Minute)
	if err == nil {
		json.Unmarshal(wtReceive, &wt)
	}
	return &wt, err
}

// Get command
func (cacli *Cacli) WTDelete(wlid string) error {
	args := []string{}
	args = append(args, "wt")
	args = append(args, "delete")
	args = append(args, "-wlid")
	args = append(args, wlid)
	_, err := cacli.runCacliCommandRepeat(args, true, time.Duration(2)*time.Minute)
	return err
}

// Download command
func (cacli *Cacli) WTDownload(wlid, containerName, output string) error {
	args := []string{}
	args = append(args, "wt")
	args = append(args, "download")
	args = append(args, "-wlid")
	args = append(args, wlid)
	args = append(args, "-o")
	args = append(args, output)

	if containerName != "" {
		args = append(args, "-n")
		args = append(args, containerName)
	}
	_, err := cacli.runCacliCommandRepeat(args, true, time.Duration(6)*time.Minute)
	return err
}

// Sign command
func (cacli *Cacli) WTSign(wlid, user, password, ociImageURL string) error {
	args := []string{}
	display := true
	args = append(args, "--debug")
	args = append(args, "wt")
	args = append(args, "sign")
	args = append(args, "-wlid")
	args = append(args, wlid)

	if ociImageURL != "" {
		args = append(args, "--dockerless-service-url")
		args = append(args, ociImageURL)
	}

	if user != "" && password != "" {
		display = false
		args = append(args, "--docker-registry-user")
		args = append(args, user)
		args = append(args, "--docker-registry-password")
		args = append(args, password)
	}

	_, err := runCacliCommandWithTimeout(args, display, time.Duration(8)*time.Minute)
	return err
}

// ================================================================================================
// ================================= K8S ==========================================================
// ================================================================================================

// AttachNameSpace command attach workloads
func (cacli *Cacli) K8SAttach(cluster, ns, wlid string, injectLabel bool) error {
	args := []string{}
	args = append(args, "attach")
	args = append(args, SetArgs(cluster, ns, wlid, nil)...)
	if injectLabel {
		args = append(args, "--attach-future")
	}
	_, err := cacli.runCacliCommandRepeat(args, true, time.Duration(2)*time.Minute)
	return err
}

func (cacli *Cacli) RunPostureScan(framework, cluster string) error {
	args := []string{}
	// cacli k8s posture create --framework "MITRE" --cluster childrenofbodom

	args = append(args, "k8s")
	args = append(args, "posture")
	args = append(args, "create")
	args = append(args, "--cluster")
	args = append(args, cluster)
	args = append(args, "--framework")
	args = append(args, framework)
	res, err := cacli.runCacliCommandRepeat(args, false, time.Duration(3)*time.Minute)
	if err != nil {
		return err
	}
	glog.Infof("%v", string(res))
	return nil

}

// ================================================================================================
// ============================ OPA FRAMEWORK =====================================================
// ================================================================================================

// OPAFRAMEWORKGet cacli opa get
func (cacli *Cacli) OPAFRAMEWORKGet(name string, public bool) ([]opapolicy.Framework, error) {
	args := []string{}
	opaList := []opapolicy.Framework{}
	args = append(args, "opa")
	args = append(args, "framework")
	args = append(args, "get")
	if name != "" {
		args = append(args, "--name")
		args = append(args, name)
	}
	if public {
		args = append(args, "--public")
	}
	args = append(args, "--expand")

	opaReceive, err := cacli.runCacliCommandRepeat(args, true, time.Duration(2)*time.Minute)
	if err == nil {
		if name == "" {
			err = json.Unmarshal(opaReceive, &opaList)
		} else {
			opaSingle := opapolicy.Framework{}
			err = json.Unmarshal(opaReceive, &opaSingle)
			opaList = append(opaList, opaSingle)
		}
	}
	return opaList, err
}

// OPAFRAMEWORKList - cacli opa list
func (cacli *Cacli) OPAFRAMEWORKList(public bool) ([]string, error) {
	args := []string{}
	opaList := []string{}
	args = append(args, "opa")
	args = append(args, "framework")
	args = append(args, "list")
	if public {
		args = append(args, "--public")
	}
	opaReceive, err := cacli.runCacliCommandRepeat(args, true, time.Duration(2)*time.Minute)
	if err == nil {
		json.Unmarshal(opaReceive, &opaList)
	}
	return opaList, err
}

// OPAFRAMEWORKCreate - cacli opa create
func (cacli *Cacli) OPAFRAMEWORKCreate(framework *opapolicy.Framework, fileName string) (*opapolicy.Framework, error) {
	if fileName == "" {
		var err error
		if fileName, err = ConvertObjectTOFile(*framework); err != nil {
			return nil, err
		}
	}
	args := []string{}
	args = append(args, "opa")
	args = append(args, "framework")
	args = append(args, "create")
	args = append(args, "--input")
	args = append(args, fileName)
	_, err := cacli.runCacliCommandRepeat(args, true, time.Duration(2)*time.Minute)
	// if err == nil {
	// 	json.Unmarshal(opaReceive, &opaList)
	// }
	return nil, err
}

// OPAFRAMEWORKUpdate - cacli opa update
func (cacli *Cacli) OPAFRAMEWORKUpdate(framework *opapolicy.Framework, fileName string) (*opapolicy.Framework, error) {
	if fileName == "" {
		var err error
		if fileName, err = ConvertObjectTOFile(*framework); err != nil {
			return nil, err
		}
	}
	args := []string{}
	args = append(args, "opa")
	args = append(args, "framework")
	args = append(args, "update")
	args = append(args, "--input")
	args = append(args, fileName)
	_, err := cacli.runCacliCommandRepeat(args, true, time.Duration(2)*time.Minute)
	// if err == nil {
	// 	json.Unmarshal(opaReceive, &opaList)
	// }
	return nil, err
}

// OPAFRAMEWORKDelete cacli opa delete
func (cacli *Cacli) OPAFRAMEWORKDelete(name string) error {
	args := []string{}
	args = append(args, "opa")
	args = append(args, "framework")
	args = append(args, "delete")
	args = append(args, "--name")
	args = append(args, name)
	_, err := cacli.runCacliCommandRepeat(args, true, time.Duration(2)*time.Minute)
	return err
}

// ================================================================================================
// ============================ OPA CONTROL =======================================================
// ================================================================================================

// OPACONTROLGet cacli opa get
func (cacli *Cacli) OPACONTROLGet(name string) ([]opapolicy.Control, error) {
	args := []string{}
	opaList := []opapolicy.Control{}
	args = append(args, "opa")
	args = append(args, "control")
	args = append(args, "get")
	if name != "" {
		args = append(args, "--name")
		args = append(args, name)
	}
	args = append(args, "--expand")

	opaReceive, err := cacli.runCacliCommandRepeat(args, true, time.Duration(2)*time.Minute)
	if err == nil {
		if name == "" {
			err = json.Unmarshal(opaReceive, &opaList)
		} else {
			opaSingle := opapolicy.Control{}
			err = json.Unmarshal(opaReceive, &opaSingle)
			opaList = append(opaList, opaSingle)
		}
	}
	return opaList, err
}

// OPAFRAMEWORKList - cacli opa list
func (cacli *Cacli) OPACONTROLList() ([]string, error) {
	args := []string{}
	opaList := []string{}
	args = append(args, "opa")
	args = append(args, "control")
	args = append(args, "list")
	opaReceive, err := cacli.runCacliCommandRepeat(args, true, time.Duration(2)*time.Minute)
	if err == nil {
		json.Unmarshal(opaReceive, &opaList)
	}
	return opaList, err
}

// OPAFRAMEWORKCreate - cacli opa create
func (cacli *Cacli) OPACONTROLCreate(control *opapolicy.Control, fileName string) (*opapolicy.Control, error) {
	if fileName == "" {
		var err error
		if fileName, err = ConvertObjectTOFile(*control); err != nil {
			return nil, err
		}
	}
	args := []string{}
	args = append(args, "opa")
	args = append(args, "control")
	args = append(args, "create")
	args = append(args, "--input")
	args = append(args, fileName)
	_, err := cacli.runCacliCommandRepeat(args, true, time.Duration(2)*time.Minute)
	// if err == nil {
	// 	json.Unmarshal(opaReceive, &opaList)
	// }
	return nil, err
}

// OPAFRAMEWORKUpdate - cacli opa update
func (cacli *Cacli) OPACONTROLUpdate(control *opapolicy.Control, fileName string) (*opapolicy.Control, error) {
	if fileName == "" {
		var err error
		if fileName, err = ConvertObjectTOFile(*control); err != nil {
			return nil, err
		}
	}
	args := []string{}
	args = append(args, "opa")
	args = append(args, "control")
	args = append(args, "update")
	args = append(args, "--input")
	args = append(args, fileName)
	_, err := cacli.runCacliCommandRepeat(args, true, time.Duration(2)*time.Minute)
	// if err == nil {
	// 	json.Unmarshal(opaReceive, &opaList)
	// }
	return nil, err
}

// OPACONTROLDelete cacli opa delete
func (cacli *Cacli) OPACONTROLDelete(name string) error {
	args := []string{}
	args = append(args, "opa")
	args = append(args, "control")
	args = append(args, "delete")
	args = append(args, "--name")
	args = append(args, name)
	_, err := cacli.runCacliCommandRepeat(args, true, time.Duration(2)*time.Minute)
	return err
}

// ================================================================================================
// ============================== OPA RULE ========================================================
// ================================================================================================

// OPARULEGet cacli opa get
func (cacli *Cacli) OPARULEGet(name string) ([]opapolicy.PolicyRule, error) {
	args := []string{}
	opaList := []opapolicy.PolicyRule{}
	args = append(args, "opa")
	args = append(args, "rule")
	args = append(args, "get")
	if name != "" {
		args = append(args, "--name")
		args = append(args, name)
	}
	opaReceive, err := cacli.runCacliCommandRepeat(args, true, time.Duration(2)*time.Minute)
	if err == nil {
		if name == "" {
			err = json.Unmarshal(opaReceive, &opaList)
		} else {
			opaSingle := opapolicy.PolicyRule{}
			err = json.Unmarshal(opaReceive, &opaSingle)
			opaList = append(opaList, opaSingle)
		}
	}
	return opaList, err
}

// OPAFRAMEWORKList - cacli opa list
func (cacli *Cacli) OPARULEList() ([]string, error) {
	args := []string{}
	opaList := []string{}
	args = append(args, "opa")
	args = append(args, "rule")
	args = append(args, "list")
	opaReceive, err := cacli.runCacliCommandRepeat(args, true, time.Duration(2)*time.Minute)
	if err == nil {
		json.Unmarshal(opaReceive, &opaList)
	}
	return opaList, err
}

// OPAFRAMEWORKCreate - cacli opa create
func (cacli *Cacli) OPARULECreate(rule *opapolicy.PolicyRule, fileName string) (*opapolicy.PolicyRule, error) {
	if fileName == "" {
		var err error
		if fileName, err = ConvertObjectTOFile(*rule); err != nil {
			return nil, err
		}
	}
	args := []string{}
	args = append(args, "opa")
	args = append(args, "rule")
	args = append(args, "create")
	args = append(args, "--input")
	args = append(args, fileName)
	_, err := cacli.runCacliCommandRepeat(args, true, time.Duration(2)*time.Minute)
	// if err == nil {
	// 	json.Unmarshal(opaReceive, &opaList)
	// }
	return nil, err
}

// OPAFRAMEWORKUpdate - cacli opa update
func (cacli *Cacli) OPARULEUpdate(rule *opapolicy.PolicyRule, fileName string) (*opapolicy.PolicyRule, error) {
	if fileName == "" {
		var err error
		if fileName, err = ConvertObjectTOFile(*rule); err != nil {
			return nil, err
		}
	}
	args := []string{}
	args = append(args, "opa")
	args = append(args, "rule")
	args = append(args, "update")
	args = append(args, "--input")
	args = append(args, fileName)
	_, err := cacli.runCacliCommandRepeat(args, true, time.Duration(2)*time.Minute)
	// if err == nil {
	// 	json.Unmarshal(opaReceive, &opaList)
	// }
	return nil, err
}

// OPARULEDelete cacli opa delete
func (cacli *Cacli) OPARULEDelete(name string) error {
	args := []string{}
	args = append(args, "opa")
	args = append(args, "rule")
	args = append(args, "delete")
	args = append(args, "--name")
	args = append(args, name)
	_, err := cacli.runCacliCommandRepeat(args, true, time.Duration(2)*time.Minute)
	return err
}

// ================================================================================================
// ================================ SECP ==========================================================
// ================================================================================================

// SecretEncrypt -
func (cacli *Cacli) SECPEncrypt(message, inputFile, outputFile, keyID string, base64Enc bool) ([]byte, error) {
	args := []string{}
	args = append(args, "secret-policy")
	args = append(args, "encrypt")
	if message != "" {
		args = append(args, "--message")
		args = append(args, message)
	}
	if inputFile != "" {
		args = append(args, "--input")
		args = append(args, inputFile)
	}
	if keyID != "" {
		args = append(args, "-kid")
		args = append(args, keyID)
	}
	if outputFile != "" {
		args = append(args, "--output")
		args = append(args, outputFile)
	}
	if base64Enc {
		args = append(args, "--base64")
	}

	messageByte, err := runCacliCommand(args, false)
	return messageByte, err
}

// SecretDecrypt -
func (cacli *Cacli) SECPDecrypt(message, inputFile, outputFile string, base64Enc bool) ([]byte, error) {
	args := []string{}
	args = append(args, "secret-policy")
	args = append(args, "decrypt")
	if message != "" {
		args = append(args, "--message")
		args = append(args, message)
	}
	if inputFile != "" {
		args = append(args, "--input")
		args = append(args, inputFile)
	}
	if outputFile != "" {
		args = append(args, "--output")
		args = append(args, outputFile)
	}
	if base64Enc {
		args = append(args, "--base64")
	}

	messageByte, err := runCacliCommand(args, true)

	return messageByte, err
}

// GetSecretAccessPolicy -
func (cacli *Cacli) SECPGet(sid, name, cluster, namespace string) ([]secrethandling.SecretAccessPolicy, error) {
	secretAccessPolicy := []secrethandling.SecretAccessPolicy{}
	args := []string{}
	args = append(args, "secret-policy")
	args = append(args, "get")
	if sid != "" {
		args = append(args, "-sid")
		args = append(args, sid)
	} else if name != "" {
		args = append(args, "--name")
		args = append(args, name)
	} else {
		if cluster != "" {
			args = append(args, "--cluster")
			args = append(args, cluster)
			if namespace != "" {
				args = append(args, "--namespace")
				args = append(args, namespace)
			}
		}
	}
	sReceive, err := cacli.runCacliCommandRepeat(args, true, time.Duration(3)*time.Minute)
	if err == nil {
		if err = json.Unmarshal(sReceive, &secretAccessPolicy); err != nil {
			tmpSecretAccessPolicy := secrethandling.SecretAccessPolicy{}
			if err = json.Unmarshal(sReceive, &tmpSecretAccessPolicy); err == nil {
				secretAccessPolicy = []secrethandling.SecretAccessPolicy{tmpSecretAccessPolicy}
			}
		}
		err = nil // if received and empty list
	}
	return secretAccessPolicy, err
}

// ================================================================================================
// ================================ UTILS =========================================================
// ================================================================================================

func (cacli *Cacli) UTILSCleanup(wlid string, discoveryOnly bool) error {
	args := []string{}
	args = append(args, "utils")
	args = append(args, "cleanup")
	args = append(args, "--workload-id")
	args = append(args, wlid)
	if discoveryOnly {
		args = append(args, "--discovery")
	}
	_, err := cacli.runCacliCommandRepeat(args, true, time.Duration(3)*time.Minute)
	return err
}
