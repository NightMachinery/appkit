package identity

import (
	"path/filepath"
	"testing"
)

func TestConfig(t *testing.T) {
	cf := Config{Mode: "cloudflare", Team: "team", AUD: []string{"aud"}, Emails: []string{"o@example.org"}}
	for name, c := range map[string]Config{
		"no mode":        {},
		"unknown mode":   {Mode: "header"},
		"cf without aud": {Mode: "cloudflare", Team: "team", Emails: []string{"o@example.org"}},
		"cf without who": {Mode: "cloudflare", Team: "team", AUD: []string{"aud"}},
	} {
		if _, err := New(c, ""); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if v, err := New(Config{Mode: "tailscale"}, ""); err != nil {
		t.Fatal(err)
	} else if _, ok := v.(*Tailscale); !ok {
		t.Errorf("tailscale mode gave %T", v)
	}
	cache := filepath.Join(t.TempDir(), "state", "certs.json")
	v, err := New(cf, cache)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := v.(*Cloudflare)
	if !ok || c.Team != "team" || c.CachePath != cache || c.Emails[0] != "o@example.org" {
		t.Errorf("cloudflare mode gave %+v", v)
	}
}
