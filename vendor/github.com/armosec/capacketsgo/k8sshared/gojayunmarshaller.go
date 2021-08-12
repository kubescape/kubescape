package k8sshared

import (
	"fmt"

	"github.com/francoispqt/gojay"
)

// CAClusterName string          `json:"caClusterName"`
// CANamespace   string          `json:"caNamespace"`
// Event         json.RawMessage `json:"k8sV1Event"`

// UnmarshalJSONObject - File inside a pkg
func (l *K8sAuditLog) UnmarshalJSONObject(dec *gojay.Decoder, key string) (err error) {

	switch key {
	case "caClusterName":
		err = dec.String(&(l.CAClusterName))

	case "caNamespace":
		err = dec.String(&(l.CANamespace))

	case "k8sV1Event":
		var tmp gojay.EmbeddedJSON

		if err = dec.AddEmbeddedJSON(&tmp); err != nil {
			return fmt.Errorf("failed to UnmarshalJSONObject k8sV1Event, error: %v", err)
		}
		l.Event = []byte(tmp)
		return nil
	}

	return err

}

func (logs *K8sAuditLogs) UnmarshalJSONArray(dec *gojay.Decoder) error {
	lae := K8sAuditLog{}
	if err := dec.Object(&lae); err != nil {
		return err
	}

	*logs = append(*logs, lae)
	return nil
}

// func (logs []K8sAuditLog) UnmarshalJSONArray(dec *gojay.Decoder) error {
// 	lae := K8sAuditLog{}
// 	if err := dec.Object(&lae); err != nil {
// 		return err
// 	}

// 	logs = append(logs, lae)
// 	return nil
// }

func (file *K8sAuditLog) NKeys() int {
	return 0
}
