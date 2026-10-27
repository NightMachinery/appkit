# appkit

Small Go packages for a personal web app that sits behind Tailscale Serve or Cloudflare
Access, where only its owner may use it.

- **`identity`** decides who is asking. Behind Tailscale Serve, the `Tailscale-User-Login`
  header must be the login that owns the machine. Behind Cloudflare Access, the
  `Cf-Access-Jwt-Assertion` token is verified: its RS256 signature against the team's
  keys, its issuer, audience, expiry and type, and the owner's email. The keys are
  cached on disk and refreshed hourly, and on an unknown key ID. There is no way to turn
  the check off.
- **`listen`** opens the app's address: a Unix socket only its user can open (0700
  directory, 0600 socket, a stale socket replaced, a served one left alone), or TCP on
  loopback only, so the app cannot be reached around the proxy that vouches for the
  caller.
- **`appconfig`** reads the part of the app's JSON config that every app shares (device,
  title, path, origin, listen address, colour, identity, pid file), strictly: an unknown
  field is an error.

```go
type Config struct {
	appconfig.Base
	Every string `json:"every"` // the app's own settings
}

var c Config
if err := appconfig.Load(path, &c); err != nil { ... }
if err := c.Check(home); err != nil { ... }
v, err := identity.New(c.Identity, filepath.Join(stateDir, "access-certs.json"))
go identity.KeepFresh(ctx, v, log.Printf)
l, err := listen.Listen(c.Listen)
// In each handler but the health check:
if _, err := v.Verify(r); err != nil { http.Error(w, "forbidden", 403); return }
```

`go test ./...` runs the tests, which need no network.
