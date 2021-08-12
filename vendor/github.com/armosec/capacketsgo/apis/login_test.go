package apis

// func TestLogin2BE(t *testing.T) {

// 	loginDetails := CustomerLoginDetails{Email: "lalafi@cyberarmor.io", Password: "***", CustomerName: "CyberArmorTests"}
// 	res, err := BELogin(loginDetails, "login")
// 	if err != nil {
// 		t.Errorf("failed to get raw audit is different ")
// 	}
// 	k := res.ToLoginObject()

// 	fmt.Printf("%v\n", k)

// }

// func TestGetMicroserviceOverview(t *testing.T) {
// 	// client := &http.Client{}
// 	loginDetails := CustomerLoginDetails{Email: "lalafi@cyberarmor.io", Password: "***", CustomerName: "CyberArmorTests"}
// 	loginobj, err := BELogin(loginDetails, "login")
// 	if err != nil {
// 		t.Errorf("failed to get raw audit is different ")
// 	}
// 	k := loginobj.ToLoginObject()
// 	beURL := GetBEInfo("")

// 	res, err := BEHttpRequest(k, beURL,
// 		"GET",
// 		"v1/microservicesOverview",
// 		nil,
// 		BasicBEQuery,
// 		k)

// 	if err != nil {
// 		t.Errorf("failed to get raw audit is different ")
// 	}

// 	s := string(res)

// 	fmt.Printf("%v\n", s)

// }
