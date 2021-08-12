package apis

import (
	"time"

	"github.com/gofrs/uuid"
)

// AuthenticationCookie is what it is
type AuthenticationCookie struct {
	Oauth2Claims  `json:",inline"`
	CustomerGUID  uuid.UUID `json:"customerGuid"`
	Expires       time.Time `json:"expires"`
	Version       int       `json:"version"`
	Authorization string    `json:"authorization,omitempty"`
}

type LoginAux struct {
	Referer string
	Url     string
}

// CustomerLoginDetails is what it is
type CustomerLoginDetails struct {
	Email        string    `json:"email"`
	Password     string    `json:"password"`
	CustomerName string    `json:"customer,omitempty"`
	CustomerGUID uuid.UUID `json:"customerGuid,omitempty"`
}

// Oauth2Claims returns in claims section of Oauth2 verification process
type Oauth2Claims struct {
	Sub               string   `json:"sub"`
	Name              string   `json:"name"`
	PreferredUserName string   `json:"preferred_username"`
	CAGroups          []string `json:"ca_groups"`
	Email             string   `json:"email"`
}
