package cacli

import (
	"github.com/armosec/capacketsgo/opapolicy"
	"github.com/armosec/capacketsgo/secrethandling"
)

// Cacli commands
type CacliMock struct {
	backendURL  string
	credentials CredStruct
}

// NewCacli -
func NewCacliMock(backendURL string) *CacliMock {
	// Load credentials from mounted secret
	return &CacliMock{
		backendURL:  backendURL,
		credentials: CredStruct{},
	}
}

// ================================================================================================
// ================================ BASIC =========================================================
// ================================================================================================

// Login cacli login
func (cacli *CacliMock) Login() error {
	return nil
}

// Status cacli --status
func (caclim *CacliMock) Status() (*Status, error) {
	return &Status{}, nil
}

// Sign command
func (caclim *CacliMock) Sign(wlid, user, password, ociImageURL string) error {
	return nil
}

// ================================================================================================
// ================================== WT ==========================================================
// ================================================================================================

// Create command
func (caclim *CacliMock) WTCreate(wt *WorkloadTemplate, fileName string) (string, error) {
	return "", nil
}

// Apply command
func (caclim *CacliMock) WTApply(wt *WorkloadTemplate, fileName string) (string, error) {
	return "", nil

}

// Update command
func (caclim *CacliMock) WTUpdate(wt *WorkloadTemplate, fileName string) (string, error) {
	return "", nil

}

// Triplet command
func (caclim *CacliMock) WTTriplet(wlid string) (*GUIDTriplet, error) {
	return &GUIDTriplet{}, nil
}

// Get command
// func (caclim *CacliMock) Get(wlid string) error {
func (caclim *CacliMock) WTGet(wlid string) (*WorkloadTemplate, error) {
	return &WorkloadTemplate{}, nil
}

// Get command
func (caclim *CacliMock) WTDelete(wlid string) error {
	return nil
}

// Download command
func (caclim *CacliMock) WTDownload(wlid, containerName, output string) error {
	return nil
}

// Sign command
func (caclim *CacliMock) WTSign(wlid, user, password, ociImageURL string) error {
	return nil
}

// ================================================================================================
// ================================= K8S ==========================================================
// ================================================================================================

// AttachNameSpace command attach all workloads in namespace
func (caclim *CacliMock) K8SAttach(cluster, ns, wlid string, _ bool) error {
	return nil
}

// ================================================================================================
// ============================ OPA FRAMEWORK =====================================================
// ================================================================================================

// OPAFRAMEWORKGet cacli opa get
func (caclim *CacliMock) OPAFRAMEWORKGet(name string) ([]opapolicy.Framework, error) {
	return []opapolicy.Framework{}, nil
}

// OPAFRAMEWORKDelete cacli opa delete
func (caclim *CacliMock) OPAFRAMEWORKDelete(name string) error {
	return nil
}

// OPAFRAMEWORKList - cacli opa list
func (caclim *CacliMock) OPAFRAMEWORKList() ([]string, error) {
	return []string{}, nil
}

// OPAFRAMEWORKCreate - cacli opa create
func (caclim *CacliMock) OPAFRAMEWORKCreate(framework *opapolicy.Framework, fileName string) (*opapolicy.Framework, error) {
	return nil, nil
}

// OPAFRAMEWORKUpdate - cacli opa update
func (caclim *CacliMock) OPAFRAMEWORKUpdate(framework *opapolicy.Framework, fileName string) (*opapolicy.Framework, error) {
	return nil, nil
}

// ================================================================================================
// ============================ OPA CONTROL =======================================================
// ================================================================================================

// OPAFRAMEWORKGet cacli opa get
func (caclim *CacliMock) OPACONTROLGet(name string) ([]opapolicy.Control, error) {
	return []opapolicy.Control{}, nil
}

// OPAFRAMEWORKGet cacli opa get
func (caclim *CacliMock) OPACONTROLDelete(name string) error {
	return nil
}

// OPAFRAMEWORKList - cacli opa list
func (caclim *CacliMock) OPACONTROLList() ([]string, error) {
	return []string{}, nil
}

// OPAFRAMEWORKCreate - cacli opa create
func (caclim *CacliMock) OPACONTROLCreate(control *opapolicy.Control, fileName string) (*opapolicy.Control, error) {
	return nil, nil
}

// OPAFRAMEWORKUpdate - cacli opa update
func (caclim *CacliMock) OPACONTROLUpdate(control *opapolicy.Control, fileName string) (*opapolicy.Control, error) {
	return nil, nil
}

// ================================================================================================
// ============================== OPA RULE ========================================================
// ================================================================================================

// OPAFRAMEWORKGet cacli opa get
func (caclim *CacliMock) OPARULEGet(name string) ([]opapolicy.PolicyRule, error) {
	return []opapolicy.PolicyRule{}, nil
}

// OPAFRAMEWORKGet cacli opa get
func (caclim *CacliMock) OPARULEDelete(name string) error {
	return nil
}

// OPAFRAMEWORKList - cacli opa list
func (caclim *CacliMock) OPARULEList() ([]string, error) {
	return []string{}, nil
}

// OPAFRAMEWORKCreate - cacli opa create
func (caclim *CacliMock) OPARULECreate(rule *opapolicy.PolicyRule, fileName string) (*opapolicy.PolicyRule, error) {
	return nil, nil
}

// OPAFRAMEWORKUpdate - cacli opa update
func (caclim *CacliMock) OPARULEUpdate(rule *opapolicy.PolicyRule, fileName string) (*opapolicy.PolicyRule, error) {
	return nil, nil
}

// ================================================================================================
// ================================ SECP ==========================================================
// ================================================================================================

// SecretEncrypt -
func (caclim *CacliMock) SECPEncrypt(message, inputFile, outputFile, keyID string, base64Enc bool) ([]byte, error) {
	return []byte{}, nil
}

// SecretDecrypt -
func (caclim *CacliMock) SECPDecrypt(message, inputFile, outputFile string, base64Enc bool) ([]byte, error) {
	return []byte{}, nil

}

// GetSecretAccessPolicy -
func (caclim *CacliMock) SECPGet(sid, name, cluster, namespace string) ([]secrethandling.SecretAccessPolicy, error) {
	return []secrethandling.SecretAccessPolicy{}, nil
}

// ================================================================================================
// ================================ UTILS =========================================================
// ================================================================================================

func (caclim *CacliMock) UTILSCleanup(wlid string, _ bool) error {
	return nil
}
