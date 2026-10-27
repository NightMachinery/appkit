package identity

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Config says how an app checks who is asking, as it appears in the app's config file.
type Config struct {
	// Mode is "tailscale" (the Tailscale-User-Login header must be the login that owns
	// this machine) or "cloudflare" (the Access JWT is verified). There is no third mode:
	// the app cannot run without checking who is asking.
	Mode string `json:"mode"`
	// Cloudflare only.
	Team   string   `json:"team"`   // <team>.cloudflareaccess.com
	AUD    []string `json:"aud"`    // the Access application's audience tag(s)
	Emails []string `json:"emails"` // the owner's addresses
}

// Check reports what is missing or wrong in c.
func (c Config) Check() error {
	switch c.Mode {
	case "tailscale":
		return nil
	case "cloudflare":
		if c.Team == "" || len(c.AUD) == 0 || len(c.Emails) == 0 {
			return errors.New("cloudflare identity needs team, aud and emails")
		}
		return nil
	}
	return errors.New(`identity.mode must be "tailscale" or "cloudflare"`)
}

// New builds the verifier c names. A Cloudflare verifier keeps its last good key set in
// cacheFile, so that a restart while Cloudflare is unreachable still lets the owner in;
// run KeepFresh beside it.
func New(c Config, cacheFile string) (Verifier, error) {
	if err := c.Check(); err != nil {
		return nil, err
	}
	if c.Mode == "tailscale" {
		return &Tailscale{}, nil
	}
	if cacheFile != "" {
		if err := os.MkdirAll(filepath.Dir(cacheFile), 0o700); err != nil {
			return nil, fmt.Errorf("key cache: %w", err)
		}
	}
	return &Cloudflare{Team: c.Team, AUD: c.AUD, Emails: c.Emails, CachePath: cacheFile}, nil
}

// KeepFresh refreshes a Cloudflare verifier's keys now and hourly until ctx ends,
// reporting failures through logf. Other verifiers need nothing, and it returns at once.
func KeepFresh(ctx context.Context, v Verifier, logf func(format string, args ...any)) {
	cf, ok := v.(*Cloudflare)
	if !ok {
		return
	}
	for {
		rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		if err := cf.Refresh(rctx); err != nil && ctx.Err() == nil {
			logf("access keys: %v", err)
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Hour):
		}
	}
}
