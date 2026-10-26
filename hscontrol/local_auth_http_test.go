package hscontrol

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
)

func localAuthHTTPTestApp(t *testing.T, enabled bool) *Headscale {
	t.Helper()
	cfg := &types.Config{
		ServerURL:           "https://login.example.org",
		NoisePrivateKeyPath: t.TempDir() + "/noise.key",
		TrustedProxies:      []netip.Prefix{netip.MustParsePrefix("10.0.0.5/32")},
		LocalAuth:           types.LocalAuthConfig{Enabled: enabled},
		Database: types.DatabaseConfig{
			Type:   "sqlite3",
			Sqlite: types.SqliteConfig{Path: t.TempDir() + "/headscale.db"},
		},
		Policy: types.PolicyConfig{Mode: types.PolicyModeDB},
	}
	app, err := NewHeadscale(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, app.GetState().Close()) })
	return app
}

func localAuthGET(app *Headscale, remote string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "http://login.example.org/local-auth/enroll", nil)
	req.RemoteAddr = remote
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	app.HTTPHandler().ServeHTTP(rec, req)
	return rec
}

func TestLocalAuthEnrollPage(t *testing.T) {
	app := localAuthHTTPTestApp(t, true)
	rec := localAuthGET(app, "10.0.0.5:1234")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Header().Get("Content-Type"), "text/html")
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	require.Equal(t, "no-referrer", rec.Header().Get("Referrer-Policy"))
	csp := rec.Header().Get("Content-Security-Policy")
	require.Contains(t, csp, "default-src 'none'")
	require.Contains(t, csp, "script-src 'nonce-")
	require.Contains(t, csp, "connect-src 'self'")
	require.Contains(t, csp, "frame-ancestors 'none'")
	require.NotContains(t, rec.Body.String(), "src=\"")
	require.Contains(t, rec.Body.String(), "window.location.hash")
	require.Contains(t, rec.Body.String(), "history.replaceState")
	require.Less(t, strings.Index(rec.Body.String(), "history.replaceState"), strings.Index(rec.Body.String(), "<form"))
	require.Contains(t, rec.Body.String(), "name=\"csrf\"")
	require.Contains(t, rec.Body.String(), "type=\"password\"")

	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	require.Equal(t, "__Secure-hs-local-enroll-csrf", cookies[0].Name)
	require.True(t, cookies[0].Secure)
	require.True(t, cookies[0].HttpOnly)
	require.Equal(t, http.SameSiteStrictMode, cookies[0].SameSite)
	require.Equal(t, "/local-auth/enroll", cookies[0].Path)
	require.Equal(t, 600, cookies[0].MaxAge)
	nonceMarker := "script-src 'nonce-"
	nonceStart := strings.Index(csp, nonceMarker) + len(nonceMarker)
	nonceEnd := strings.Index(csp[nonceStart:], "'")
	require.Greater(t, nonceEnd, 0)
	require.Contains(t, rec.Body.String(), `<script nonce="`+csp[nonceStart:nonceStart+nonceEnd]+`">`)
	require.Contains(t, rec.Body.String(), `name="csrf" value="`+cookies[0].Value+`"`)
	require.NotContains(t, rec.Body.String(), "secret bearer")

	second := localAuthGET(app, "10.0.0.5:1234")
	require.Equal(t, http.StatusOK, second.Code)
	require.NotEqual(t, cookies[0].Value, second.Result().Cookies()[0].Value)
}

func TestLocalAuthEnrollPageDisabledOrUntrusted(t *testing.T) {
	disabled := localAuthHTTPTestApp(t, false)
	rec := localAuthGET(disabled, "10.0.0.5:1234")
	require.Equal(t, http.StatusNotFound, rec.Code)
	require.Empty(t, rec.Result().Cookies())

	enabled := localAuthHTTPTestApp(t, true)
	rec = localAuthGET(enabled, "203.0.113.8:1234")
	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Empty(t, rec.Result().Cookies())
	require.NotContains(t, rec.Body.String(), "password")
}

func TestLocalAuthEnrollPOSTNotMounted(t *testing.T) {
	app := localAuthHTTPTestApp(t, true)
	req := httptest.NewRequest(http.MethodPost, "http://login.example.org/local-auth/enroll", strings.NewReader("token=secret&password=example"))
	req.RemoteAddr = "10.0.0.5:1234"
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	app.HTTPHandler().ServeHTTP(rec, req)
	require.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	require.Empty(t, rec.Result().Cookies())
}
