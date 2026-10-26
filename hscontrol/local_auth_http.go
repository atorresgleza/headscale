package hscontrol

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"html/template"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
)

const localEnrollCSRFCookie = "__Host-hs-local-enroll-csrf"

var localEnrollPage = template.Must(template.New("local-enroll").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Set your Headscale password</title>
<script nonce="{{.Nonce}}">
// Capture the bearer fragment and remove it from browser history immediately.
let invitation = window.location.hash.slice(1);
window.history.replaceState(null, "", window.location.pathname);
if (invitation.length > 128) invitation = "";
window.addEventListener("DOMContentLoaded", () => {
  const form = document.querySelector("form");
  const status = document.getElementById("result");
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!invitation) { status.textContent = "Unable to enroll."; return; }
    const body = new URLSearchParams(new FormData(form));
    body.set("token", invitation);
    try {
      const response = await fetch("/local-auth/enroll", {
        method: "POST", credentials: "same-origin", redirect: "error",
        cache: "no-store", body: body
      });
      status.textContent = response.ok ? "Password set." : "Unable to enroll.";
      if (response.ok) invitation = "";
    } catch (_) { status.textContent = "Unable to enroll."; }
  });
});
</script></head><body>
<h1>Set your Headscale password</h1>
<form method="post" action="/local-auth/enroll">
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="new-password" required minlength="15" maxlength="1024">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<button type="submit">Set password</button>
</form><p id="result" role="status"></p>
</body></html>`))

// localAuthEnrollPage is mounted only when opt-in local authentication is
// enabled. The transport guard must run before any public credential handler.
func (h *Headscale) localAuthEnrollPage(w http.ResponseWriter, r *http.Request) {
	csrf, err := localEnrollRandom()
	if err != nil {
		http.Error(w, "Unable to load enrollment.", http.StatusInternalServerError)
		return
	}
	nonce, err := localEnrollRandom()
	if err != nil {
		http.Error(w, "Unable to load enrollment.", http.StatusInternalServerError)
		return
	}
	var page bytes.Buffer
	if err := localEnrollPage.Execute(&page, struct{ CSRF, Nonce string }{csrf, nonce}); err != nil {
		http.Error(w, "Unable to load enrollment.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", fmt.Sprintf(
		"default-src 'none'; script-src 'nonce-%s'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'", nonce,
	))
	http.SetCookie(w, &http.Cookie{
		Name: localEnrollCSRFCookie, Value: csrf, Path: "/",
		MaxAge: 600, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(page.Bytes()) // headers are committed; a short write cannot be recovered here
}

func localEnrollRandom() (string, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(secret), nil
}

// localAuthEnrollPOST never accepts a bearer token in the URL. Its body is
// capped before parsing; only a trusted peer and matching HTTPS Origin reach
// the shared limiter and the atomic one-time invitation redemption.
func (h *Headscale) localAuthEnrollPOST(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	fail := func(code int) { http.Error(w, "Unable to enroll.", code) }
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Fragment != "" {
		fail(http.StatusBadRequest)
		return
	}
	origin := r.Header.Values("Origin")
	if len(origin) != 1 || origin[0] != strings.TrimSuffix(h.cfg.ServerURL, "/") {
		fail(http.StatusForbidden)
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		fail(http.StatusBadRequest)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8*1024)
	if err := r.ParseForm(); err != nil {
		fail(http.StatusBadRequest)
		return
	}
	csrf := r.PostForm["csrf"]
	token := r.PostForm["token"]
	password := r.PostForm["password"]
	if len(csrf) != 1 || len(token) != 1 || len(password) != 1 {
		fail(http.StatusBadRequest)
		return
	}
	cookies := r.CookiesNamed(localEnrollCSRFCookie)
	if len(cookies) != 1 || len(cookies[0].Value) != 43 || len(csrf[0]) != 43 ||
		subtle.ConstantTimeCompare([]byte(cookies[0].Value), []byte(csrf[0])) != 1 {
		fail(http.StatusForbidden)
		return
	}
	clientIP, ok := parsePeerAddr(r.RemoteAddr)
	if !ok {
		fail(http.StatusServiceUnavailable)
		return
	}
	subject := token[0]
	if subject == "" || len(subject) > 1024 {
		subject = "invalid-invitation"
	}
	allowed, err := h.state.AllowLocalAuthAttempt(db.LocalAuthAttemptEnrollment, clientIP, subject, time.Now())
	if err != nil {
		fail(http.StatusServiceUnavailable)
		return
	}
	if !allowed {
		fail(http.StatusBadRequest)
		return
	}
	if _, err := h.state.RedeemLocalInvitation(token[0], password[0]); err != nil {
		fail(http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: localEnrollCSRFCookie, Value: "", Path: "/",
		MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

const (
	localLoginCSRFCookie = "__Host-hs-local-login-csrf"
	localApprovalCookie  = "__Host-hs-local-approval"
)

type localApproval struct {
	AuthID  types.AuthID
	UserID  types.UserID
	Request *types.AuthRequest
	CSRF    string
}

var localDeviceReviewPage = template.Must(template.New("local-review").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Review device</title></head><body>
<h1>Review device registration</h1>
<p>Device name: {{.Hostname}}</p>
<p>Machine key: {{.MachineKey}}</p><p>Node key: {{.NodeKey}}</p>
<p>Requested tags: {{.Tags}}</p>
<form method="post" action="/register/confirm/{{.AuthID}}">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<button type="submit">Approve this device</button></form></body></html>`))

var localLoginPage = template.Must(template.New("local-login").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Device sign-in</title></head><body>
<h1>Sign in to review device registration</h1>
<form method="post" action="/register/login/{{.AuthID}}">
<label>User name <input name="name" required autocomplete="username"></label>
<label>Password <input name="password" type="password" required autocomplete="current-password"></label>
<input type="hidden" name="csrf" value="{{.CSRF}}">
<button type="submit">Sign in</button></form></body></html>`))

// localAuthDeviceLoginPage replaces only the opt-in legacy CLI instructions.
// It reads the original pending request without consuming or approving it.
func (h *Headscale) localAuthDeviceLoginPage(w http.ResponseWriter, r *http.Request) {
	authID, err := authIDFromRequest(r)
	if err != nil {
		http.Error(w, "Unable to sign in.", http.StatusBadRequest)
		return
	}
	entry, ok := h.state.GetAuthCacheEntry(authID)
	if !ok || !entry.IsRegistration() {
		http.Error(w, "Unable to sign in.", http.StatusNotFound)
		return
	}
	csrf, err := localEnrollRandom()
	if err != nil {
		http.Error(w, "Unable to sign in.", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	http.SetCookie(w, &http.Cookie{
		Name: localLoginCSRFCookie, Value: csrf, Path: "/", MaxAge: 600,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	if err := localLoginPage.Execute(w, struct{ AuthID, CSRF string }{authID.String(), csrf}); err != nil {
		// Static template with validated auth ID and base64url CSRF value.
		return
	}
}

// localAuthDeviceLoginPOST verifies credentials without registering a device.
// T3c will consume this bounded confirmation state on a separate explicit POST.
func (h *Headscale) localAuthDeviceLoginPOST(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	fail := func(code int) { http.Error(w, "Unable to sign in.", code) }
	authID, err := authIDFromRequest(r)
	if err != nil {
		fail(http.StatusBadRequest)
		return
	}
	entry, ok := h.state.GetAuthCacheEntry(authID)
	if !ok || !entry.IsRegistration() {
		fail(http.StatusNotFound)
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		fail(http.StatusBadRequest)
		return
	}
	origin := r.Header.Values("Origin")
	if len(origin) != 1 || origin[0] != strings.TrimSuffix(h.cfg.ServerURL, "/") {
		fail(http.StatusForbidden)
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		fail(http.StatusBadRequest)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8*1024)
	if err := r.ParseForm(); err != nil {
		fail(http.StatusBadRequest)
		return
	}
	csrf, name, password := r.PostForm["csrf"], r.PostForm["name"], r.PostForm["password"]
	if len(csrf) != 1 || len(name) != 1 || len(password) != 1 {
		fail(http.StatusBadRequest)
		return
	}
	cookies := r.CookiesNamed(localLoginCSRFCookie)
	if len(cookies) != 1 || len(cookies[0].Value) != 43 || len(csrf[0]) != 43 ||
		subtle.ConstantTimeCompare([]byte(cookies[0].Value), []byte(csrf[0])) != 1 {
		fail(http.StatusForbidden)
		return
	}
	clientIP, ok := parsePeerAddr(r.RemoteAddr)
	if !ok {
		fail(http.StatusServiceUnavailable)
		return
	}
	subject := name[0]
	if subject == "" || len(subject) > 1024 {
		subject = "invalid-name"
	}
	allowed, err := h.state.AllowLocalAuthAttempt(db.LocalAuthAttemptLogin, clientIP, subject, time.Now())
	if err != nil {
		fail(http.StatusServiceUnavailable)
		return
	}
	if !allowed {
		fail(http.StatusUnauthorized)
		return
	}
	userID, valid, err := h.state.AuthenticateLocalUser(name[0], password[0])
	if err != nil {
		fail(http.StatusServiceUnavailable)
		return
	}
	if !valid {
		fail(http.StatusUnauthorized)
		return
	}
	// A slow password hash may have outlived the pending registration.
	entry, ok = h.state.GetAuthCacheEntry(authID)
	if !ok || !entry.IsRegistration() {
		fail(http.StatusNotFound)
		return
	}
	session, err := localEnrollRandom()
	if err != nil {
		fail(http.StatusServiceUnavailable)
		return
	}
	confirmCSRF, err := localEnrollRandom()
	if err != nil {
		fail(http.StatusServiceUnavailable)
		return
	}
	data := entry.RegistrationData()
	tags := "None"
	if data.Hostinfo != nil && len(data.Hostinfo.RequestTags) != 0 {
		tags = strings.Join(data.Hostinfo.RequestTags, ", ")
	}
	var page bytes.Buffer
	if err := localDeviceReviewPage.Execute(&page, struct {
		AuthID, Hostname, MachineKey, NodeKey, Tags, CSRF string
	}{authID.String(), data.Hostname, data.MachineKey.String(), data.NodeKey.String(), tags, confirmCSRF}); err != nil {
		fail(http.StatusServiceUnavailable)
		return
	}
	h.localApprovals.Add(session, localApproval{
		AuthID: authID, UserID: userID, Request: entry, CSRF: confirmCSRF,
	})
	http.SetCookie(w, &http.Cookie{
		Name: localLoginCSRFCookie, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name: localApprovalCookie, Value: session, Path: "/", MaxAge: 600,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(page.Bytes()) // The template escapes all client-supplied identity fields.
}
