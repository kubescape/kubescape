package apis

// WebsocketScanCommand api
const (
	WebsocketScanCommandVersion string = "v1"
	WebsocketScanCommandPath    string = "scanImage"
)

// commands send via websocket
const (
	UPDATE            string = "update"
	ATTACH            string = "Attach"
	REMOVE            string = "remove"
	DETACH            string = "Detach"
	INCOMPATIBLE      string = "Incompatible"
	REPLACE_HEADERS   string = "ReplaceHeaders"
	IMAGE_UNREACHABLE string = "ImageUnreachable"
	SIGN              string = "sign"
	UNREGISTERED      string = "unregistered"
	INJECT            string = "inject"
	RESTART           string = "restart"
	ENCRYPT           string = "encryptSecret"
	DECRYPT           string = "decryptSecret"
	SCAN              string = "scan"
)
