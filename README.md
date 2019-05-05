# oidc

```go
p := openidClient.NewProvider(
    "idp url",
    "client name",
    "client secret"
)
    
func LoginHandler(w http.ResponseWriter, r *http.Request) {
    url := p.GenerateLoginURL("state")
    http.Redirect(w, r, url, 302)
}
    
func CallbackHandler(w http.ResponseWriter, r *http.Request) {
    session := p.Exchange("code")
    session. AccessToken
    session.IDToken
    session.RefreshToken
    ...
}
```
