package apis

import (
	"bytes"
	"net/http"
	"time"

	"io/ioutil"

	oidc "github.com/coreos/go-oidc"
	uuid "github.com/satori/go.uuid"

	// "go.uber.org/zap"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/oauth2"
)

func GetOauth2TokenURL() string {
	return "https://idens.eudev3.cyberarmorsoft.com/auth/realms/CyberArmorSites"
}

func GetLoginStruct() (LoginAux, error) {

	return LoginAux{Referer: "https://cpanel.eudev3.cyberarmorsoft.com/login", Url: "https://cpanel.eudev3.cyberarmorsoft.com/login"}, nil
}

func LoginWithKeycloak(loginDetails CustomerLoginDetails) ([]uuid.UUID, *oidc.IDToken, error) {
	// var custGUID uuid.UUID
	// config.Oauth2TokenURL
	if GetOauth2TokenURL() == "" {
		return nil, nil, fmt.Errorf("missing oauth2 token URL")
	}
	urlaux, _ := GetLoginStruct()
	conf, err := getOauth2Config(urlaux)
	if err != nil {
		return nil, nil, err
	}
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, GetOauth2TokenURL())
	if err != nil {
		return nil, nil, err
	}

	// "Oauth2ClientID": "golang-client"
	oidcConfig := &oidc.Config{
		ClientID:          "golang-client",
		SkipClientIDCheck: true,
	}

	verifier := provider.Verifier(oidcConfig)
	ouToken, err := conf.PasswordCredentialsToken(ctx, loginDetails.Email, loginDetails.Password)
	if err != nil {
		return nil, nil, err
	}
	// "Authorization",
	authorization := fmt.Sprintf("%s %s", ouToken.Type(), ouToken.AccessToken)
	// oidc.IDTokenVerifier
	tkn, err := verifier.Verify(ctx, ouToken.AccessToken)
	if err != nil {
		return nil, tkn, err
	}
	tkn.Nonce = authorization
	if loginDetails.CustomerName == "" {
		customers, err := getCustomersNames(tkn)
		if err != nil {
			return nil, tkn, err
		}
		if len(customers) == 1 {
			loginDetails.CustomerName = customers[0]
		} else {
			return nil, tkn, fmt.Errorf("login with one of the following customers: %v", customers)
		}
	}
	custGUID, err := getCustomerGUID(tkn, &loginDetails)
	if err != nil {
		return nil, tkn, err
	}
	return []uuid.UUID{custGUID}, tkn, nil
}

func getOauth2Config(urlaux LoginAux) (*oauth2.Config, error) {
	reURLSlices := strings.Split(urlaux.Referer, "/")
	if len(reURLSlices) == 0 {
		reURLSlices = strings.Split(urlaux.Url, "/")
	}
	// zapLogger.With(zap.Strings("referer", reURLSlices)).Info("Searching oauth2Config for")
	if len(reURLSlices) < 3 {
		reURLSlices = []string{reURLSlices[0], reURLSlices[0], reURLSlices[0]}
	}
	lg, _ := GetLoginStruct()
	provider, _ := oidc.NewProvider(context.Background(), GetOauth2TokenURL())
	//provider.Endpoint {"AuthURL":"https://idens.eudev3.cyberarmorsoft.com/auth/realms/CyberArmorSites/protocol/openid-connect/auth","TokenURL":"https://idens.eudev3.cyberarmorsoft.com/auth/realms/CyberArmorSites/protocol/openid-connect/token","AuthStyle":0}
	conf := oauth2.Config{
		ClientID:     "golang-client",
		ClientSecret: "4e33bad2-3491-41a6-b486-93c492cfb4a2",
		RedirectURL:  lg.Referer,
		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),
		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}
	return &conf, nil
	// return nil, fmt.Errorf("canno't find oauth2Config for referer '%+v'.\nPlease set referer or origin headers", reURLSlices)
}

func getCustomersNames(oauth2Details *oidc.IDToken) ([]string, error) {
	var claimsJSON Oauth2Claims
	if err := oauth2Details.Claims(&claimsJSON); err != nil {
		return nil, err
	}

	customersList := make([]string, 0, len(claimsJSON.CAGroups))
	for _, v := range claimsJSON.CAGroups {
		var caCustomer Oauth2Customer
		if err := json.Unmarshal([]byte(v), &caCustomer); err == nil {
			customersList = append(customersList, caCustomer.CustomerName)
		}
	}
	return customersList, nil
}

func getCustomerGUID(tkn *oidc.IDToken, loginDetails *CustomerLoginDetails) (uuid.UUID, error) {

	customers, err := getCustomersList(tkn)
	if err != nil {
		return uuid.UUID{}, err
	}

	// if customer name not provided - use default customer
	if loginDetails.CustomerName == "" && len(customers) > 0 {
		return uuid.FromString(customers[0].CustomerGUID)
	}

	for _, i := range customers {
		if i.CustomerName == loginDetails.CustomerName {
			return uuid.FromString(i.CustomerGUID)
		}
	}
	return uuid.UUID{}, fmt.Errorf("customer name not found in customer list")
}

func getCustomersList(oauth2Details *oidc.IDToken) ([]Oauth2Customer, error) {
	var claimsJSON Oauth2Claims
	if err := oauth2Details.Claims(&claimsJSON); err != nil {
		return nil, err
	}

	customersList := make([]Oauth2Customer, 0, len(claimsJSON.CAGroups))
	for _, v := range claimsJSON.CAGroups {
		var caCustomer Oauth2Customer
		if err := json.Unmarshal([]byte(v), &caCustomer); err == nil {
			customersList = append(customersList, caCustomer)
		}
	}
	return customersList, nil
}

// func MakeAuthCookies(custGUID uuid.UUID, ouToken *oidc.IDToken) (*http.Cookie, error) {
// 	var ccc http.Cookie
// 	var responseData AuthenticationCookie
// 	expireDate := time.Now().UTC().Add(time.Duration(config.CookieExpirationHours) * time.Hour)
// 	if ouToken != nil {
// 		expireDate = ouToken.Expiry
// 	}
// 	ccc.Expires = expireDate
// 	responseData.CustomerGUID = custGUID
// 	responseData.Expires = ccc.Expires
// 	responseData.Version = 0
// 	authorizationStr := ""
// 	if ouToken != nil {
// 		authorizationStr = ouToken.Nonce
// 		if err := ouToken.Claims(&responseData.Oauth2Claims); err != nil {
// 			errStr := fmt.Sprintf("failed to get claims from JWT")
// 			return nil, fmt.Errorf("%v", errStr)
// 		}
// 	}
// 	jsonBytes, err := json.Marshal(responseData)
// 	if err != nil {
// 		errStr := fmt.Sprintf("failed to get claims from JWT")
// 		return nil, fmt.Errorf("%v", errStr)
// 	}
// 	ccc.Name = "auth"
// 	ccc.Value = hex.EncodeToString(jsonBytes) + "." + cacheaccess.CalcHmac256(jsonBytes)
// 	// TODO: HttpOnly for security...
// 	ccc.HttpOnly = false
// 	ccc.Path = "/"
// 	ccc.Secure = true
// 	ccc.SameSite = http.SameSiteNoneMode
// 	http.SetCookie(w, &ccc)
// 	responseData.Authorization = authorizationStr
// 	jsonBytes, err = json.Marshal(responseData)
// 	if err != nil {
// 		w.WriteHeader(http.StatusInternalServerError)
// 		fmt.Fprintf(w, "error while marshaling response(2) %s", err)
// 		return
// 	}
// 	w.Write(jsonBytes)
// }

func Login(loginDetails CustomerLoginDetails) (*LoginObject, error) {

	return nil, nil
}

func GetBEInfo(cfgFile string) string {
	return "https://dashbe.eudev3.cyberarmorsoft.com"
}

func BELogin(loginDetails *CustomerLoginDetails, login string, cfg string) (*BELoginResponse, error) {
	client := &http.Client{}

	basebeURL := GetBEInfo(cfg)
	beURL := fmt.Sprintf("%v/%v", basebeURL, login)

	loginInfoBytes, err := json.Marshal(loginDetails)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", beURL, bytes.NewReader(loginInfoBytes))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Referer", strings.Replace(beURL, "dashbe", "cpanel", 1))
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	loginS := &BELoginResponse{}
	json.Unmarshal(body, &loginS)

	loginS.Cookies = resp.Cookies()
	return loginS, nil
}

func (r *LoginObject) IsExpired() bool {
	if r == nil {
		return true
	}
	t, err := time.Parse(time.RFC3339, r.Expires)
	if err != nil {
		return true
	}

	return t.UTC().Before(time.Now().UTC())
}
