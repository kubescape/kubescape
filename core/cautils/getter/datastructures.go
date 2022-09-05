package getter

type FeLoginData struct {
	Secret   string `json:"secret"`
	ClientId string `json:"clientId"`
}

type FeLoginResponse struct {
	Token        string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	Expires      string `json:"expires"`
	ExpiresIn    int32  `json:"expiresIn"`
}

type KSCloudSelectCustomer struct {
	SelectedCustomerGuid string `json:"selectedCustomer"`
}

type TenantResponse struct {
	TenantID  string `json:"tenantId"`
	Token     string `json:"token"`
	Expires   string `json:"expires"`
	AdminMail string `json:"adminMail,omitempty"`
}
