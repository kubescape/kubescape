package auditconnector

import (
	"time"
)

// available sources for audit logs
const (
	AuditSourceControlPanel  = "ControlPanel"
	AuditSourceAggregator    = "Aggregator"
	AuditSourceEventReceiver = "EventReceiver"
	AuditSourceTest          = "Test"
)

// type Marshaler interface {
// 	MarshalJSON() ([]byte, error)
// }

// AuditTime wraps the golang time object
type AuditTime time.Time

// AuditReport represents single audit log entry
type AuditReport struct {
	Source       string    `json:"source"`
	TimeStamp    time.Time `json:"time"`
	Action       string    `json:"action"`
	Subject      string    `json:"subject"`
	Details      string    `json:"details"`
	User         string    `json:"user"`
	CustomerGUID string    `json:"-"`
}

// func (t AuditTime) MarshalJSON() ([]byte, error) {
// 	stamp := fmt.Sprintf("\"%s\"", time.Time(t).String())
// 	return []byte(stamp), nil
// }

const indexMapping = `
{
    "mappings": {
        "properties": {
            "source": {
                "type": "keyword",
                "ignore_above": 256
            },
            "time": {
                "type": "date",
                "ignore_malformed": true,
                "format": "strict_date_optional_time_nanos"
            },
            "action": {
                "type": "keyword",
                "ignore_above": 256
            },
            "subject": {
                "type": "text",
                "fields": {
                    "keyword": {
                        "type": "keyword",
                        "ignore_above": 8000
                    }
                }
            },
            "details": {
                "type": "text"
            },
            "user": {
                "type": "text",
                "fields": {
                    "keyword": {
                        "type": "keyword",
                        "ignore_above": 256
                    }
                }
            },
            "customerGUID": {
                "type": "keyword",
                "ignore_above": 64
            }
        }
    }
}
`
