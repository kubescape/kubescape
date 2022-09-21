package v1

import (
	"time"

	"github.com/kubescape/kubescape/v2/core/cautils/getter"
)

type V2ListRequest struct {
	// properties of the requested next page
	// Use ValidatePageProperties to set PageSize field
	PageSize *int `json:"pageSize,omitempty"`
	// One can leave it empty for 0, then call ValidatePageProperties
	PageNum *int `json:"pageNum,omitempty"`
	// The time window of the list to return. Default: since - beginning of the time, until - now.
	Since *time.Time `json:"since,omitempty"`
	Until *time.Time `json:"until,omitempty"`
	// Which elements of the list to return, each field can hold multiple values separated by comma
	// Example: ": {"severity": "High,Medium",		"type": "61539,30303"}
	// An empty map means "return the complete list"
	InnerFilters []map[string]string `json:"innerFilters,omitempty"`
	// How to order (sort) the list, field name + sort order (asc/desc), like https://www.w3schools.com/sql/sql_orderby.asp
	// Example: "timestamp:asc,severity:desc"
	OrderBy string `json:"orderBy,omitempty"`
	// Cursor to the next page of former request. Not supported yet
	// Cursor cannot be used with another parameters of this struct
	Cursor string `json:"cursor,omitempty"`
	// FieldsList allow us to return only subset of the source document fields
	// Don't expose FieldsList outside without well designed decision
	FieldsList              []string          `json:"includeFields,omitempty"`
	FieldsReverseKeywordMap map[string]string `json:"-,omitempty"`
}

type KSCivAdaptor struct {
	ksCloudAPI *getter.KSCloudAPI
}
