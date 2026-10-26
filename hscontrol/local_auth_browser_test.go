//go:build local_auth_browser

package hscontrol

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestLocalAuthBrowserFixture serves a disposable TLS origin for real-browser
// checks. The proxy wrapper models a trusted, header-overwriting proxy; it
// cannot attest to the configuration of any deployed reverse proxy.
func TestLocalAuthBrowserFixture(t *testing.T) {
	if os.Getenv("HEADSCALE_T4_BROWSER_FIXTURE") != "1" {
		t.Skip("run only for the isolated browser check")
	}
	app := localAuthHTTPTestApp(t, true)
	app.cfg.ServerURL = "https://localhost:18765"
	done := make(chan struct{})
	var once sync.Once
	backend := app.HTTPHandler()
	proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/__fixture_done" {
			once.Do(func() { close(done) })
			w.WriteHeader(http.StatusNoContent)
			return
		}
		// Simulate the only trusted reverse proxy peer, never pass through
		// a client-supplied forwarded transport header.
		r.RemoteAddr = "10.0.0.5:1234"
		r.Header.Del("X-Forwarded-Proto")
		r.Header.Set("X-Forwarded-Proto", "https")
		backend.ServeHTTP(w, r)
	}))
	require.NoError(t, proxy.Listener.Close())
	listener, err := net.Listen("tcp", "127.0.0.1:18765")
	require.NoError(t, err)
	proxy.Listener = listener
	proxy.StartTLS()
	defer proxy.Close()
	fmt.Fprintln(os.Stdout, "isolated browser fixture ready")
	select {
	case <-done:
	case <-time.After(120 * time.Second):
		t.Fatal("browser fixture timed out")
	}
}
