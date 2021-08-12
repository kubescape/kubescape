package apis

// import (
// 	"fmt"
// 	"net/http"
// 	"testing"
// )

// func TestAuditStructure(t *testing.T) {
// 	c := http.Client{}
// 	be, err := MakeBackendConnector(&c, "https://dashbe.eudev3.cyberarmorsoft.com", &CustomerLoginDetails{Email: "lalafi@cyberarmor.io", Password: "*", CustomerName: "CyberArmorTests"})
// 	if err != nil {
// 		t.Errorf("sad1")

// 	}

// 	b, err := be.HTTPSend("GET", "v1/microservicesOverview", nil, MapQuery, map[string]string{"wlid": "wlid://cluster-childrenofbodom/namespace-default/deployment-pos"})
// 	if err != nil {
// 		t.Errorf("sad2")

// 	}
// 	fmt.Printf("%v", string(b))

// 	t.Errorf("sad")

// }
