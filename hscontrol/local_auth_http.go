package hscontrol

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
)

const localEnrollCSRFCookie = "__Secure-hs-local-enroll-csrf"

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
		Name: localEnrollCSRFCookie, Value: csrf, Path: "/local-auth/enroll",
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
