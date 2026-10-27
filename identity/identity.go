// Package identity decides who is asking a web app that sits behind Tailscale Serve or
// Cloudflare Access. Every request but a health check must pass one of the two
// verifiers, chosen by the configuration; there is no way to turn identity off.
package identity

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Identity struct {
	Who string // the login or email
	Via string // "tailscale" or "cloudflare"
}

type Verifier interface {
	Verify(r *http.Request) (Identity, error)
}

// ErrNoIdentity means the request carried no identity at all: it did not come through
// Tailscale Serve or Cloudflare Access.
var ErrNoIdentity = errors.New("no identity on the request")

// --- Tailscale ---------------------------------------------------------------------

// Tailscale accepts a request whose Tailscale-User-Login header is the login that owns
// this machine. Tailscale Serve sets the header for tailnet users and strips any copy the
// client sent; tagged devices and Funnel get none.
type Tailscale struct {
	// Owner returns the login that owns this machine. Defaults to OwnerLogin.
	Owner func() (string, error)

	mu    sync.Mutex
	login string
	at    time.Time
}

func (t *Tailscale) owner() (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.login != "" && time.Since(t.at) < 10*time.Minute {
		return t.login, nil
	}
	lookup := t.Owner
	if lookup == nil {
		lookup = OwnerLogin
	}
	login, err := lookup()
	if err != nil {
		return "", fmt.Errorf("cannot tell who owns this machine: %w", err)
	}
	t.login, t.at = login, time.Now()
	return login, nil
}

func (t *Tailscale) Verify(r *http.Request) (Identity, error) {
	h := r.Header.Get("Tailscale-User-Login")
	if h == "" {
		return Identity{Via: "none"}, ErrNoIdentity
	}
	owner, err := t.owner()
	if err != nil {
		return Identity{Who: h, Via: "tailscale"}, err
	}
	if !strings.EqualFold(h, owner) {
		return Identity{Who: h, Via: "tailscale"}, fmt.Errorf("%s is not the owner of this machine", h)
	}
	return Identity{Who: h, Via: "tailscale"}, nil
}

// OwnerLogin reads the login of the user who owns this machine from `tailscale status`.
func OwnerLogin() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "tailscale", "status", "--json").Output()
	if err != nil {
		return "", fmt.Errorf("tailscale status: %w", err)
	}
	return ownerFromStatus(out)
}

func ownerFromStatus(b []byte) (string, error) {
	var st struct {
		BackendState string
		Self         struct {
			UserID int64
			Tags   []string
		}
		User map[string]struct{ LoginName string }
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return "", err
	}
	if st.BackendState != "Running" {
		return "", fmt.Errorf("tailscale is %q, not Running", st.BackendState)
	}
	if len(st.Self.Tags) > 0 {
		return "", errors.New("this machine is tagged, so Tailscale sends no user identity")
	}
	u, ok := st.User[strconv.FormatInt(st.Self.UserID, 10)]
	if !ok || u.LoginName == "" {
		return "", errors.New("tailscale status names no owner for this machine")
	}
	return u.LoginName, nil
}

// --- Cloudflare Access ---------------------------------------------------------------

// Cloudflare verifies the Access JWT in Cf-Access-Jwt-Assertion: RS256 signature against
// the team's keys, issuer, audience, expiry, and the owner's email. Trusting the header
// without this would let anything on the server's loopback claim to be anyone.
type Cloudflare struct {
	Team      string
	AUD       []string
	Emails    []string
	CachePath string // where the last good key set is kept across restarts
	// Fetch gets the certs document. Defaults to an HTTPS GET of the team's endpoint.
	Fetch func(ctx context.Context) ([]byte, error)
	Now   func() time.Time

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
	triedAt   time.Time
}

const leeway = 60 * time.Second

func (c *Cloudflare) issuer() string { return "https://" + c.Team + ".cloudflareaccess.com" }

func (c *Cloudflare) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Cloudflare) fetch(ctx context.Context) ([]byte, error) {
	if c.Fetch != nil {
		return c.Fetch(ctx)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", c.issuer()+"/cdn-cgi/access/certs", nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("certs: HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

func parseKeys(b []byte) (map[string]*rsa.PublicKey, error) {
	var doc struct {
		Keys []struct {
			Kid, Kty, Alg, N, E string
		} `json:"keys"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || (k.Alg != "" && k.Alg != "RS256") {
			continue
		}
		n, err1 := base64.RawURLEncoding.DecodeString(k.N)
		e, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err1 != nil || err2 != nil || len(e) == 0 || len(e) > 4 {
			continue
		}
		var exp int
		for _, x := range e {
			exp = exp<<8 | int(x)
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exp}
	}
	if len(keys) == 0 {
		return nil, errors.New("certs document holds no RSA keys")
	}
	return keys, nil
}

// Refresh fetches the key set now. Cloudflare rotates keys every six weeks and keeps the
// old one valid for seven days, so an hourly refresh plus a refresh on an unknown key id
// is enough. On failure the previous set, or the one cached on disk, stays in use.
func (c *Cloudflare) Refresh(ctx context.Context) error {
	c.mu.Lock()
	c.triedAt = c.now()
	c.mu.Unlock()
	b, err := c.fetch(ctx)
	if err == nil {
		var keys map[string]*rsa.PublicKey
		if keys, err = parseKeys(b); err == nil {
			c.mu.Lock()
			c.keys, c.fetchedAt = keys, c.now()
			c.mu.Unlock()
			if c.CachePath != "" {
				_ = os.MkdirAll(filepath.Dir(c.CachePath), 0o700)
				_ = os.WriteFile(c.CachePath, b, 0o600)
			}
			return nil
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.keys == nil && c.CachePath != "" {
		if cached, rerr := os.ReadFile(c.CachePath); rerr == nil {
			if keys, perr := parseKeys(cached); perr == nil {
				c.keys = keys
			}
		}
	}
	return err
}

func (c *Cloudflare) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	c.mu.Lock()
	k := c.keys[kid]
	stale := c.now().Sub(c.fetchedAt) > time.Hour
	canRetry := c.now().Sub(c.triedAt) > 30*time.Second
	c.mu.Unlock()
	if (k == nil || stale) && canRetry {
		_ = c.Refresh(ctx)
		c.mu.Lock()
		k = c.keys[kid]
		c.mu.Unlock()
	}
	if k == nil {
		return nil, fmt.Errorf("no key with id %q", kid)
	}
	return k, nil
}

type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*a = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

func (c *Cloudflare) Verify(r *http.Request) (Identity, error) {
	tok := r.Header.Get("Cf-Access-Jwt-Assertion")
	if tok == "" {
		return Identity{Via: "none"}, ErrNoIdentity
	}
	id := Identity{Via: "cloudflare"}
	email, err := c.check(r.Context(), tok)
	id.Who = email
	return id, err
}

func (c *Cloudflare) check(ctx context.Context, tok string) (string, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return "", errors.New("malformed token")
	}
	var hdr struct{ Alg, Kid string }
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(hb, &hdr) != nil {
		return "", errors.New("malformed token header")
	}
	if hdr.Alg != "RS256" {
		return "", fmt.Errorf("token algorithm %q is not RS256", hdr.Alg)
	}
	key, err := c.key(ctx, hdr.Kid)
	if err != nil {
		return "", err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", errors.New("malformed signature")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig); err != nil {
		return "", errors.New("bad signature")
	}
	var cl struct {
		Aud   audience `json:"aud"`
		Email string   `json:"email"`
		Exp   int64    `json:"exp"`
		Nbf   int64    `json:"nbf"`
		Iss   string   `json:"iss"`
		Type  string   `json:"type"`
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(pb, &cl) != nil {
		return "", errors.New("malformed claims")
	}
	now := c.now()
	switch {
	case cl.Iss != c.issuer():
		return cl.Email, fmt.Errorf("issuer %q is not %q", cl.Iss, c.issuer())
	case !intersects(cl.Aud, c.AUD):
		return cl.Email, errors.New("token is for another Access application")
	case cl.Exp == 0 || now.After(time.Unix(cl.Exp, 0).Add(leeway)):
		return cl.Email, errors.New("token expired")
	case cl.Nbf != 0 && now.Add(leeway).Before(time.Unix(cl.Nbf, 0)):
		return cl.Email, errors.New("token not valid yet")
	case cl.Type != "app":
		return cl.Email, fmt.Errorf("token type %q is not an application login", cl.Type)
	case cl.Email == "" || !containsFold(c.Emails, cl.Email):
		return cl.Email, fmt.Errorf("%q is not the owner", cl.Email)
	}
	return cl.Email, nil
}

func intersects(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}
