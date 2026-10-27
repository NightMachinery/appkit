package identity

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var b64 = base64.RawURLEncoding

func jwks(kid string, pub *rsa.PublicKey) []byte {
	doc := map[string]any{"keys": []map[string]string{{
		"kid": kid, "kty": "RSA", "alg": "RS256",
		"n": b64.EncodeToString(pub.N.Bytes()),
		"e": b64.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}}
	b, _ := json.Marshal(doc)
	return b
}

func sign(t *testing.T, key *rsa.PrivateKey, hdr, claims map[string]any) string {
	h, _ := json.Marshal(hdr)
	c, _ := json.Marshal(claims)
	head := b64.EncodeToString(h) + "." + b64.EncodeToString(c)
	sum := sha256.Sum256([]byte(head))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return head + "." + b64.EncodeToString(sig)
}

func TestCloudflare(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Unix(1_800_000_000, 0)
	fetches := 0
	docs := map[string][]byte{"k1": jwks("k1", &key.PublicKey)}
	current := "k1"
	cf := &Cloudflare{
		Team: "team", AUD: []string{"aud-ctl"}, Emails: []string{"Owner@Example.org"},
		CachePath: filepath.Join(t.TempDir(), "certs.json"),
		Fetch:     func(context.Context) ([]byte, error) { fetches++; return docs[current], nil },
		Now:       func() time.Time { return now },
	}
	good := map[string]any{"aud": []string{"aud-ctl"}, "email": "owner@example.org",
		"exp": now.Unix() + 3600, "nbf": now.Unix() - 10, "iss": "https://team.cloudflareaccess.com", "type": "app"}
	with := func(k string, v any) map[string]any {
		m := map[string]any{}
		for a, b := range good {
			m[a] = b
		}
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
		return m
	}
	rs := map[string]any{"alg": "RS256", "kid": "k1"}
	verify := func(tok string) error {
		r := httptest.NewRequest("GET", "/", nil)
		if tok != "" {
			r.Header.Set("Cf-Access-Jwt-Assertion", tok)
		}
		_, err := cf.Verify(r)
		return err
	}

	if err := verify(sign(t, key, rs, good)); err != nil {
		t.Fatalf("valid token refused: %v", err)
	}
	if err := verify(""); !errors.Is(err, ErrNoIdentity) {
		t.Errorf("no token: %v", err)
	}
	refused := map[string]string{
		"wrong aud":     sign(t, key, rs, with("aud", "aud-other")),
		"wrong iss":     sign(t, key, rs, with("iss", "https://evil.cloudflareaccess.com")),
		"expired":       sign(t, key, rs, with("exp", now.Unix()-120)),
		"no exp":        sign(t, key, rs, with("exp", nil)),
		"future nbf":    sign(t, key, rs, with("nbf", now.Unix()+600)),
		"wrong email":   sign(t, key, rs, with("email", "someone@example.org")),
		"service token": sign(t, key, rs, with("email", nil)),
		"not app type":  sign(t, key, rs, with("type", "org")),
		"other key":     sign(t, other, rs, good),
		"alg none":      b64.EncodeToString([]byte(`{"alg":"none","kid":"k1"}`)) + "." + strings.Split(sign(t, key, rs, good), ".")[1] + ".",
		"tampered claim": func() string {
			p := strings.Split(sign(t, key, rs, good), ".")
			c, _ := json.Marshal(with("email", "x@y"))
			return p[0] + "." + b64.EncodeToString(c) + "." + p[2]
		}(),
	}
	// HS256 signed with the public key as the secret: the classic algorithm confusion.
	{
		h, _ := json.Marshal(map[string]any{"alg": "HS256", "kid": "k1"})
		c, _ := json.Marshal(good)
		head := b64.EncodeToString(h) + "." + b64.EncodeToString(c)
		mac := hmac.New(sha256.New, key.PublicKey.N.Bytes())
		mac.Write([]byte(head))
		refused["hs256 confusion"] = head + "." + b64.EncodeToString(mac.Sum(nil))
	}
	for name, tok := range refused {
		if err := verify(tok); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// Rotation: a token with an unknown kid triggers one refetch, rate-limited.
	docs["k2"] = jwks("k2", &other.PublicKey)
	current = "k2"
	now = now.Add(time.Minute)
	before := fetches
	if err := verify(sign(t, other, map[string]any{"alg": "RS256", "kid": "k2"}, with("exp", now.Unix()+3600))); err != nil {
		t.Fatalf("rotated key refused: %v", err)
	}
	if fetches != before+1 {
		t.Errorf("expected exactly one refetch, got %d", fetches-before)
	}
	for i := 0; i < 5; i++ {
		_ = verify(sign(t, other, map[string]any{"alg": "RS256", "kid": "k9"}, good))
	}
	if fetches != before+1 {
		t.Errorf("unknown kids must not hammer the certs endpoint: %d fetches", fetches-before)
	}

	// A restart while Cloudflare is unreachable uses the key set cached on disk.
	cold := &Cloudflare{Team: "team", AUD: []string{"aud-ctl"}, Emails: []string{"owner@example.org"},
		CachePath: cf.CachePath, Now: cf.Now,
		Fetch: func(context.Context) ([]byte, error) { return nil, errors.New("offline") }}
	_ = cold.Refresh(context.Background())
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cf-Access-Jwt-Assertion", sign(t, other, map[string]any{"alg": "RS256", "kid": "k2"}, with("exp", now.Unix()+3600)))
	if _, err := cold.Verify(r); err != nil {
		t.Errorf("cached keys not used: %v", err)
	}
}

func TestTailscale(t *testing.T) {
	ts := &Tailscale{Owner: func() (string, error) { return "owner@example.org", nil }}
	try := func(h string) error {
		r := httptest.NewRequest("GET", "/", nil)
		if h != "" {
			r.Header.Set("Tailscale-User-Login", h)
		}
		_, err := ts.Verify(r)
		return err
	}
	if err := try("owner@example.org"); err != nil {
		t.Errorf("owner refused: %v", err)
	}
	if err := try(""); !errors.Is(err, ErrNoIdentity) {
		t.Errorf("missing header: %v", err)
	}
	if err := try("someone@example.org"); err == nil {
		t.Error("another tailnet user accepted")
	}
	down := &Tailscale{Owner: func() (string, error) { return "", errors.New("not running") }}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Tailscale-User-Login", "owner@example.org")
	if _, err := down.Verify(r); err == nil {
		t.Error("accepted while the owner could not be determined")
	}
}

func TestOwnerFromStatus(t *testing.T) {
	ok := []byte(`{"BackendState":"Running","Self":{"UserID":42},"User":{"42":{"LoginName":"o@x"}}}`)
	if l, err := ownerFromStatus(ok); err != nil || l != "o@x" {
		t.Errorf("%q %v", l, err)
	}
	for _, bad := range []string{
		`{"BackendState":"Stopped","Self":{"UserID":42},"User":{"42":{"LoginName":"o@x"}}}`,
		`{"BackendState":"Running","Self":{"UserID":42,"Tags":["tag:x"]},"User":{"42":{"LoginName":"o@x"}}}`,
		`{"BackendState":"Running","Self":{"UserID":7},"User":{"42":{"LoginName":"o@x"}}}`,
	} {
		if _, err := ownerFromStatus([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}
