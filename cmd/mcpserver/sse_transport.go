package mcpserver

import (
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/mark3labs/mcp-go/server"
)

// newSSEServer returns the SSE transport for s, listening on addr, with every
// request passed through rejectCrossOriginRequests first. The handler it
// returns is the one the transport serves, for tests to drive directly.
//
// The SSE server binds to loopback, but a loopback address is reachable from
// any web page the user has open: the browser makes the request from the
// user's machine. mcp-go's own guard checks only the Host header, which stops
// DNS rebinding but not a page that targets http://127.0.0.1:<port> directly.
// Such a page can read the event stream (mcp-go answers it with
// Access-Control-Allow-Origin: *) and post JSON-RPC messages as text/plain,
// which browsers send without a CORS preflight, so it could call every tool
// with the user's kubeconfig. The MCP specification requires servers to
// validate the Origin header for exactly this reason.
func newSSEServer(s *server.MCPServer, addr string) (*server.SSEServer, http.Handler) {
	httpServer := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 10 * time.Second,
	}
	sseServer := server.NewSSEServer(s, server.WithHTTPServer(httpServer))
	httpServer.Handler = rejectCrossOriginRequests(sseServer)
	return sseServer, httpServer.Handler
}

// rejectCrossOriginRequests answers 403 to any request whose Origin header
// names a site other than this machine. Browsers attach Origin to cross-origin
// requests, including EventSource connections and simple POSTs, so this is
// what keeps web pages out. MCP clients that are not browsers (desktop apps,
// CLIs) send no Origin and are not affected, and browser-based tools served
// from localhost, such as the MCP Inspector, keep working.
func rejectCrossOriginRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin, sent := r.Header["Origin"]; sent && !isLoopbackOrigin(origin[0]) {
			http.Error(w, "Forbidden: cross-origin requests are not allowed", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isLoopbackOrigin reports whether origin is an http(s) origin on localhost or
// a loopback IP address. "null", sent by sandboxed frames and file: pages, is
// not a loopback origin.
func isLoopbackOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
