package hscontrol

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

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
	require.Equal(t, "__Host-hs-local-enroll-csrf", cookies[0].Name)
	require.Equal(t, "/", cookies[0].Path)
	require.Empty(t, cookies[0].Domain)
	require.True(t, cookies[0].Secure)
	require.True(t, cookies[0].Secure)
	require.True(t, cookies[0].HttpOnly)
	require.Equal(t, http.SameSiteStrictMode, cookies[0].SameSite)
	require.Equal(t, "/", cookies[0].Path)
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

func enrollmentCSRF(t *testing.T, app *Headscale) (string, *http.Cookie) {
	t.Helper()
	page := localAuthGET(app, "10.0.0.5:1234")
	require.Equal(t, http.StatusOK, page.Code)
	match := regexp.MustCompile(`name="csrf" value="([A-Za-z0-9_-]+)"`).FindStringSubmatch(page.Body.String())
	require.Len(t, match, 2)
	cookies := page.Result().Cookies()
	require.Len(t, cookies, 1)
	return match[1], cookies[0]
}

func enrollmentPOST(app *Headscale, fields url.Values, cookie *http.Cookie, origin, remote string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "http://login.example.org/local-auth/enroll", strings.NewReader(fields.Encode()))
	req.RemoteAddr = remote
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Origin", origin)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	app.HTTPHandler().ServeHTTP(rec, req)
	return rec
}

func TestLocalAuthEnrollPOSTRedeemsExistingUser(t *testing.T) {
	app := localAuthHTTPTestApp(t, true)
	user := app.GetState().CreateUserForTest("alice")
	token, err := app.GetState().IssueLocalInvitation(types.UserID(user.ID), time.Hour)
	require.NoError(t, err)
	csrf, cookie := enrollmentCSRF(t, app)
	rec := enrollmentPOST(app, url.Values{"token": {token}, "password": {"correct horse battery staple"}, "csrf": {csrf}}, cookie,
		"https://login.example.org", "10.0.0.5:1234")
	require.Equal(t, http.StatusNoContent, rec.Code)
	require.Empty(t, rec.Body.String())
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	cleared := rec.Result().Cookies()
	require.Len(t, cleared, 1)
	require.Equal(t, localEnrollCSRFCookie, cleared[0].Name)
	require.Equal(t, -1, cleared[0].MaxAge)
	require.Equal(t, "/", cleared[0].Path)
	require.Empty(t, cleared[0].Domain)
	require.True(t, cleared[0].Secure)
	require.True(t, cleared[0].HttpOnly)
	require.NotContains(t, rec.Header().Get("Location"), token)

	csrf, cookie = enrollmentCSRF(t, app)
	replay := enrollmentPOST(app, url.Values{"token": {token}, "password": {"correct horse battery staple"}, "csrf": {csrf}}, cookie,
		"https://login.example.org", "10.0.0.5:1234")
	require.Equal(t, http.StatusBadRequest, replay.Code)
	require.Equal(t, "Unable to enroll.\n", replay.Body.String())
	require.NotContains(t, replay.Body.String(), token)
}

func TestLocalAuthEnrollPOSTRejectsCSRFAndOrigin(t *testing.T) {
	app := localAuthHTTPTestApp(t, true)
	user := app.GetState().CreateUserForTest("alice")
	token, err := app.GetState().IssueLocalInvitation(types.UserID(user.ID), time.Hour)
	require.NoError(t, err)
	csrf, cookie := enrollmentCSRF(t, app)
	fields := url.Values{"token": {token}, "password": {"correct horse battery staple"}, "csrf": {csrf}}
	for _, tc := range []struct {
		name, origin, csrf string
		cookie             *http.Cookie
	}{
		{"wrong origin", "https://attacker.example.org", csrf, cookie},
		{"missing origin", "", csrf, cookie},
		{"wrong csrf", "https://login.example.org", "wrong", cookie},
		{"missing cookie", "https://login.example.org", csrf, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fields.Set("csrf", tc.csrf)
			rec := enrollmentPOST(app, fields, tc.cookie, tc.origin, "10.0.0.5:1234")
			require.Equal(t, http.StatusForbidden, rec.Code)
			require.Equal(t, "Unable to enroll.\n", rec.Body.String())
			require.NotContains(t, rec.Body.String(), token)
		})
	}
	fields.Set("csrf", csrf)
	rec := enrollmentPOST(app, fields, cookie, "https://login.example.org", "10.0.0.5:1234")
	require.Equal(t, http.StatusNoContent, rec.Code) // rejected requests did not consume invitation
}

func TestLocalAuthEnrollPOSTLimitsAndGenericErrors(t *testing.T) {
	app := localAuthHTTPTestApp(t, true)
	user := app.GetState().CreateUserForTest("alice")
	token, err := app.GetState().IssueLocalInvitation(types.UserID(user.ID), time.Hour)
	require.NoError(t, err)
	csrf, cookie := enrollmentCSRF(t, app)
	submit := func(tok, password, remote string) *httptest.ResponseRecorder {
		return enrollmentPOST(app, url.Values{"token": {tok}, "password": {password}, "csrf": {csrf}}, cookie,
			"https://login.example.org", remote)
	}
	invalidToken := submit("not a token", "correct horse battery staple", "10.0.0.5:1234")
	invalidPassword := submit(token, "short", "10.0.0.5:1234")
	require.Equal(t, http.StatusBadRequest, invalidToken.Code)
	require.Equal(t, invalidToken.Code, invalidPassword.Code)
	require.Equal(t, invalidToken.Body.String(), invalidPassword.Body.String())
	require.Equal(t, "Unable to enroll.\n", invalidToken.Body.String())
	require.Equal(t, "no-store", invalidToken.Header().Get("Cache-Control"))
	for range 4 {
		rec := submit(token, "short", "10.0.0.5:1234")
		require.Equal(t, http.StatusBadRequest, rec.Code)
	}
	rec := submit(token, "correct horse battery staple", "10.0.0.5:1234")
	require.Equal(t, http.StatusBadRequest, rec.Code) // shared subject cap, not credential verification
	// A replacement invitation remains usable and does not depend on the blocked secret.
	replacement, err := app.GetState().IssueLocalInvitation(types.UserID(user.ID), time.Hour)
	require.NoError(t, err)
	rec = submit(replacement, "correct horse battery staple", "10.0.0.5:1234")
	require.Equal(t, http.StatusNoContent, rec.Code)
}

func TestLocalAuthEnrollPOSTBodyLimitAndStorageFailure(t *testing.T) {
	app := localAuthHTTPTestApp(t, true)
	user := app.GetState().CreateUserForTest("alice")
	token, err := app.GetState().IssueLocalInvitation(types.UserID(user.ID), time.Hour)
	require.NoError(t, err)
	csrf, cookie := enrollmentCSRF(t, app)
	oversized := enrollmentPOST(app, url.Values{"token": {token}, "password": {strings.Repeat("a", 9000)}, "csrf": {csrf}}, cookie,
		"https://login.example.org", "10.0.0.5:1234")
	require.Equal(t, http.StatusBadRequest, oversized.Code)
	require.Equal(t, "Unable to enroll.\n", oversized.Body.String())
	valid := enrollmentPOST(app, url.Values{"token": {token}, "password": {"correct horse battery staple"}, "csrf": {csrf}}, cookie,
		"https://login.example.org", "10.0.0.5:1234")
	require.Equal(t, http.StatusNoContent, valid.Code)

	other := localAuthHTTPTestApp(t, true)
	csrf, cookie = enrollmentCSRF(t, other)
	require.NoError(t, other.GetState().Close())
	unavailable := enrollmentPOST(other, url.Values{"token": {token}, "password": {"correct horse battery staple"}, "csrf": {csrf}}, cookie,
		"https://login.example.org", "10.0.0.5:1234")
	require.Equal(t, http.StatusServiceUnavailable, unavailable.Code)
	require.Equal(t, "Unable to enroll.\n", unavailable.Body.String())
}

func TestLocalAuthEnrollPOSTRenewsWithoutChangingUser(t *testing.T) {
	app := localAuthHTTPTestApp(t, true)
	user, _, err := app.GetState().CreateUser(types.User{Name: "alice", Email: "alice@example.org"})
	require.NoError(t, err)
	first, err := app.GetState().IssueLocalInvitation(types.UserID(user.ID), time.Hour)
	require.NoError(t, err)
	csrf, cookie := enrollmentCSRF(t, app)
	submit := func(token, password string) *httptest.ResponseRecorder {
		return enrollmentPOST(app, url.Values{"token": {token}, "password": {password}, "csrf": {csrf}}, cookie,
			"https://login.example.org", "10.0.0.5:1234")
	}
	require.Equal(t, http.StatusNoContent, submit(first, "first correct horse battery").Code)
	oldValid, err := app.GetState().VerifyLocalPassword("alice", "first correct horse battery")
	require.NoError(t, err)
	require.True(t, oldValid)
	second, err := app.GetState().IssueLocalInvitation(types.UserID(user.ID), time.Hour)
	require.NoError(t, err)
	csrf, cookie = enrollmentCSRF(t, app)
	require.Equal(t, http.StatusBadRequest, submit(second, "short").Code)
	oldValid, err = app.GetState().VerifyLocalPassword("alice", "first correct horse battery")
	require.NoError(t, err)
	require.True(t, oldValid)
	require.Equal(t, http.StatusNoContent, submit(second, "second correct horse battery").Code)
	oldValid, err = app.GetState().VerifyLocalPassword("alice", "first correct horse battery")
	require.NoError(t, err)
	require.False(t, oldValid)
	newValid, err := app.GetState().VerifyLocalPassword("alice", "second correct horse battery")
	require.NoError(t, err)
	require.True(t, newValid)
	stored, err := app.GetState().GetUserByID(types.UserID(user.ID))
	require.NoError(t, err)
	require.Equal(t, user.Name, stored.Name)
	require.Equal(t, user.Email, stored.Email)
}

func TestLocalAuthEnrollPOSTRejectsDuplicateAndQueryToken(t *testing.T) {
	app := localAuthHTTPTestApp(t, true)
	user := app.GetState().CreateUserForTest("alice")
	token, err := app.GetState().IssueLocalInvitation(types.UserID(user.ID), time.Hour)
	require.NoError(t, err)
	csrf, cookie := enrollmentCSRF(t, app)
	fields := url.Values{"token": {token, token}, "password": {"correct horse battery staple"}, "csrf": {csrf}}
	duplicate := enrollmentPOST(app, fields, cookie, "https://login.example.org", "10.0.0.5:1234")
	require.Equal(t, http.StatusBadRequest, duplicate.Code)
	require.Equal(t, "Unable to enroll.\n", duplicate.Body.String())
	fields.Set("token", token)
	req := httptest.NewRequest(http.MethodPost, "http://login.example.org/local-auth/enroll?token="+token, strings.NewReader(fields.Encode()))
	req.RemoteAddr = "10.0.0.5:1234"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Origin", "https://login.example.org")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	query := httptest.NewRecorder()
	app.HTTPHandler().ServeHTTP(query, req)
	require.Equal(t, http.StatusBadRequest, query.Code)
	require.NotContains(t, query.Body.String(), token)
	valid := enrollmentPOST(app, fields, cookie, "https://login.example.org", "10.0.0.5:1234")
	require.Equal(t, http.StatusNoContent, valid.Code) // rejected requests did not consume invitation
}

func TestLocalAuthEnrollPOSTRejectsDuplicateCSRFCookies(t *testing.T) {
	for _, tc := range []struct {
		name        string
		poisonFirst bool
	}{
		{"poison before host", true}, {"poison after host", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := localAuthHTTPTestApp(t, true)
			user := app.GetState().CreateUserForTest("alice")
			token, err := app.GetState().IssueLocalInvitation(types.UserID(user.ID), time.Hour)
			require.NoError(t, err)
			csrf, cookie := enrollmentCSRF(t, app)
			fields := url.Values{"token": {token}, "password": {"correct horse battery staple"}, "csrf": {csrf}}
			req := httptest.NewRequest(http.MethodPost, "http://login.example.org/local-auth/enroll", strings.NewReader(fields.Encode()))
			req.RemoteAddr = "10.0.0.5:1234"
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Set("Origin", "https://login.example.org")
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			poison := &http.Cookie{Name: cookie.Name, Value: "poison"}
			if tc.poisonFirst {
				req.AddCookie(poison)
				req.AddCookie(cookie)
			} else {
				req.AddCookie(cookie)
				req.AddCookie(poison)
			}
			rejected := httptest.NewRecorder()
			app.HTTPHandler().ServeHTTP(rejected, req)
			require.Equal(t, http.StatusForbidden, rejected.Code)
			require.Equal(t, "Unable to enroll.\n", rejected.Body.String())
			valid := enrollmentPOST(app, fields, cookie, "https://login.example.org", "10.0.0.5:1234")
			require.Equal(t, http.StatusNoContent, valid.Code) // duplicate never consumes invitation
		})
	}
}

func localAuthPendingDevice(app *Headscale) types.AuthID {
	authID := types.MustAuthID()
	app.GetState().SetAuthCacheEntry(authID, types.NewRegisterAuthRequest(&types.RegistrationData{Hostname: "laptop"}))
	return authID
}

func localAuthRegisterGET(app *Headscale, authID types.AuthID, remote string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "http://login.example.org/register/"+authID.String(), nil)
	req.RemoteAddr = remote
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	app.HTTPHandler().ServeHTTP(rec, req)
	return rec
}

func localAuthLoginPOST(app *Headscale, authID types.AuthID, fields url.Values, cookie *http.Cookie, origin string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "http://login.example.org/register/login/"+authID.String(), strings.NewReader(fields.Encode()))
	req.RemoteAddr = "10.0.0.5:1234"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Origin", origin)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	app.HTTPHandler().ServeHTTP(rec, req)
	return rec
}

func TestLocalAuthDeviceLoginGETGuardAndLegacy(t *testing.T) {
	enabled := localAuthHTTPTestApp(t, true)
	authID := localAuthPendingDevice(enabled)
	rec := localAuthRegisterGET(enabled, authID, "10.0.0.5:1234")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	require.Contains(t, rec.Header().Get("Content-Security-Policy"), "form-action 'self'")
	require.Contains(t, rec.Body.String(), `type="password"`)
	require.Contains(t, rec.Body.String(), `name="csrf"`)
	require.NotContains(t, rec.Body.String(), "headscale auth register")
	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	require.Equal(t, "__Host-hs-local-login-csrf", cookies[0].Name)
	require.Equal(t, "/", cookies[0].Path)
	require.Empty(t, cookies[0].Domain)
	require.True(t, cookies[0].Secure)
	require.True(t, cookies[0].HttpOnly)
	require.Equal(t, http.SameSiteStrictMode, cookies[0].SameSite)
	require.Contains(t, rec.Body.String(), `name="csrf" value="`+cookies[0].Value+`"`)
	untrusted := localAuthRegisterGET(enabled, authID, "203.0.113.8:1234")
	require.Equal(t, http.StatusForbidden, untrusted.Code)
	require.Empty(t, untrusted.Result().Cookies())
	missing := localAuthRegisterGET(enabled, types.MustAuthID(), "10.0.0.5:1234")
	require.Equal(t, http.StatusNotFound, missing.Code)
	disabled := localAuthHTTPTestApp(t, false)
	legacy := localAuthRegisterGET(disabled, authID, "10.0.0.5:1234")
	require.Equal(t, http.StatusOK, legacy.Code)
	require.Contains(t, legacy.Body.String(), "headscale auth register")
	require.Empty(t, legacy.Result().Cookies())
}

func TestLocalAuthDeviceLoginAcceptsCredentialButDoesNotApprove(t *testing.T) {
	app := localAuthHTTPTestApp(t, true)
	user := app.GetState().CreateUserForTest("alice")
	invitation, err := app.GetState().IssueLocalInvitation(types.UserID(user.ID), time.Hour)
	require.NoError(t, err)
	_, err = app.GetState().RedeemLocalInvitation(invitation, "correct horse battery staple")
	require.NoError(t, err)
	authID := localAuthPendingDevice(app)
	page := localAuthRegisterGET(app, authID, "10.0.0.5:1234")
	require.Equal(t, http.StatusOK, page.Code)
	require.Len(t, page.Result().Cookies(), 1)
	csrfCookie := page.Result().Cookies()[0]
	untrusted := httptest.NewRequest(http.MethodPost, "http://login.example.org/register/login/"+authID.String(),
		strings.NewReader(url.Values{"name": {"alice"}, "password": {"correct horse battery staple"}, "csrf": {csrfCookie.Value}}.Encode()))
	untrusted.RemoteAddr = "203.0.113.8:1234"
	untrusted.Header.Set("X-Forwarded-Proto", "https")
	untrusted.Header.Set("Origin", "https://login.example.org")
	untrusted.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	untrusted.AddCookie(csrfCookie)
	blocked := httptest.NewRecorder()
	app.HTTPHandler().ServeHTTP(blocked, untrusted)
	require.Equal(t, http.StatusForbidden, blocked.Code)
	require.Empty(t, blocked.Result().Cookies())
	rec := localAuthLoginPOST(app, authID, url.Values{"name": {"alice"}, "password": {"correct horse battery staple"}, "csrf": {csrfCookie.Value}}, csrfCookie, "https://login.example.org")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	require.NotContains(t, rec.Body.String(), "correct horse battery staple")
	require.NotContains(t, rec.Body.String(), "Device approved")
	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 2)
	require.Equal(t, "__Host-hs-local-login-csrf", cookies[0].Name)
	require.Equal(t, -1, cookies[0].MaxAge)
	require.Equal(t, "/", cookies[0].Path)
	require.Equal(t, "__Host-hs-local-approval", cookies[1].Name)
	require.Len(t, cookies[1].Value, 43)
	require.True(t, cookies[1].Secure)
	require.True(t, cookies[1].HttpOnly)
	require.Equal(t, "/", cookies[1].Path)
	require.Empty(t, cookies[1].Domain)
	require.Equal(t, http.SameSiteStrictMode, cookies[1].SameSite)
	require.Equal(t, 600, cookies[1].MaxAge)
}

func TestLocalAuthDeviceLoginRejectsCSRFAndGenericCredentials(t *testing.T) {
	app := localAuthHTTPTestApp(t, true)
	user := app.GetState().CreateUserForTest("alice")
	invitation, err := app.GetState().IssueLocalInvitation(types.UserID(user.ID), time.Hour)
	require.NoError(t, err)
	_, err = app.GetState().RedeemLocalInvitation(invitation, "correct horse battery staple")
	require.NoError(t, err)
	authID := localAuthPendingDevice(app)
	page := localAuthRegisterGET(app, authID, "10.0.0.5:1234")
	require.Equal(t, http.StatusOK, page.Code)
	require.Len(t, page.Result().Cookies(), 1)
	csrfCookie := page.Result().Cookies()[0]
	fields := url.Values{"name": {"alice"}, "password": {"correct horse battery staple"}, "csrf": {csrfCookie.Value}}
	wrongOrigin := localAuthLoginPOST(app, authID, fields, csrfCookie, "https://other.example.org")
	require.Equal(t, http.StatusForbidden, wrongOrigin.Code)
	fields.Set("csrf", "wrong")
	wrongCSRF := localAuthLoginPOST(app, authID, fields, csrfCookie, "https://login.example.org")
	require.Equal(t, http.StatusForbidden, wrongCSRF.Code)
	fields.Set("csrf", csrfCookie.Value)
	fields.Set("password", "wrong password")
	wrong := localAuthLoginPOST(app, authID, fields, csrfCookie, "https://login.example.org")
	fields.Set("name", "unknown")
	fields.Set("password", "correct horse battery staple")
	unknown := localAuthLoginPOST(app, authID, fields, csrfCookie, "https://login.example.org")
	require.Equal(t, http.StatusUnauthorized, wrong.Code)
	require.Equal(t, wrong.Code, unknown.Code)
	require.Equal(t, "Unable to sign in.\n", wrong.Body.String())
	require.Equal(t, wrong.Body.String(), unknown.Body.String())
	require.Empty(t, wrong.Result().Cookies())
	require.Empty(t, unknown.Result().Cookies())
	fields.Set("name", "alice")
	valid := localAuthLoginPOST(app, authID, fields, csrfCookie, "https://login.example.org")
	require.Equal(t, http.StatusOK, valid.Code)
}

func TestLocalAuthDeviceLoginRejectsBadInputAndSharedLimit(t *testing.T) {
	app := localAuthHTTPTestApp(t, true)
	user := app.GetState().CreateUserForTest("alice")
	invitation, err := app.GetState().IssueLocalInvitation(types.UserID(user.ID), time.Hour)
	require.NoError(t, err)
	_, err = app.GetState().RedeemLocalInvitation(invitation, "correct horse battery staple")
	require.NoError(t, err)
	authID := localAuthPendingDevice(app)
	page := localAuthRegisterGET(app, authID, "10.0.0.5:1234")
	require.Equal(t, http.StatusOK, page.Code)
	require.Len(t, page.Result().Cookies(), 1)
	cookie := page.Result().Cookies()[0]
	fields := url.Values{"name": {"alice"}, "password": {"correct horse battery staple"}, "csrf": {cookie.Value}}
	duplicate := &http.Cookie{Name: cookie.Name, Value: "poison"}
	req := httptest.NewRequest(http.MethodPost, "http://login.example.org/register/login/"+authID.String(), strings.NewReader(fields.Encode()))
	req.RemoteAddr = "10.0.0.5:1234"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Origin", "https://login.example.org")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	req.AddCookie(duplicate)
	rec := httptest.NewRecorder()
	app.HTTPHandler().ServeHTTP(rec, req)
	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Empty(t, rec.Result().Cookies())
	fields.Add("name", "alice")
	rec = localAuthLoginPOST(app, authID, fields, cookie, "https://login.example.org")
	require.Equal(t, http.StatusBadRequest, rec.Code)
	fields.Set("name", "alice")
	fields.Set("password", strings.Repeat("a", 9000))
	rec = localAuthLoginPOST(app, authID, fields, cookie, "https://login.example.org")
	require.Equal(t, http.StatusBadRequest, rec.Code)
	fields.Set("password", "wrong password")
	for range 5 {
		rec = localAuthLoginPOST(app, authID, fields, cookie, "https://login.example.org")
		require.Equal(t, http.StatusUnauthorized, rec.Code)
		require.Equal(t, "Unable to sign in.\n", rec.Body.String())
		require.Empty(t, rec.Result().Cookies())
	}
	fields.Set("password", "correct horse battery staple")
	rec = localAuthLoginPOST(app, localAuthPendingDevice(app), fields, cookie, "https://login.example.org")
	require.Equal(t, http.StatusUnauthorized, rec.Code) // shared login-name limit, even across auth IDs
	require.Equal(t, "Unable to sign in.\n", rec.Body.String())
}
