// Package appconfig reads the part of a web app's config file that every app shares: where
// it is, how it is reached, and who may ask. An app embeds Base in its own config struct,
// adds its own fields beside it, and calls Load, then Base.Check from its own checks.
//
// The file never holds a secret.
package appconfig

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/NightMachinery/appkit/identity"
	"github.com/NightMachinery/appkit/listen"
)

var color = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// Base is what every app's config holds.
type Base struct {
	Device string `json:"device"` // the machine this instance runs on
	Title  string `json:"title"`  // the app's name
	Path   string `json:"path"`   // the URL path the instance is served at, for display
	Origin string `json:"origin"` // scheme://host[:port] the browser uses
	Listen string `json:"listen"` // "unix:/path/to.sock" or "tcp:127.0.0.1:PORT"
	Color  string `json:"color"`  // #rrggbb, the app's theme on this device
	// RemoteKill says whether an app that acts may change things on this machine; an app
	// that acts on nothing here ignores it.
	RemoteKill bool            `json:"remote_kill"`
	Identity   identity.Config `json:"identity"`
	PIDFile    string          `json:"pid_file"` // written at start, for a deploy to signal; optional
}

// Load decodes the JSON file at path into v, refusing fields v does not have, so that a
// misspelt setting fails loudly instead of being ignored.
func Load(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// Check validates b and fills what has an obvious default, expanding a leading ~ in its
// paths against home.
func (b *Base) Check(home string) error {
	if b.Device == "" {
		return fmt.Errorf("device is required")
	}
	if b.Color != "" && !color.MatchString(b.Color) {
		return fmt.Errorf("color must be #rrggbb, not %q", b.Color)
	}
	if b.Path == "" {
		b.Path = "/"
	}
	u, err := url.Parse(b.Origin)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Path != "" {
		return fmt.Errorf("origin must be scheme://host, not %q", b.Origin)
	}
	if b.Listen, err = listen.Check(b.Listen, home); err != nil {
		return err
	}
	if err := b.Identity.Check(); err != nil {
		return err
	}
	if b.PIDFile != "" {
		b.PIDFile = listen.Expand(b.PIDFile, home)
	}
	return nil
}

// WritePID writes this process's ID to path, and returns a function that removes the
// file if it still names this process.
func WritePID(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	me := strconv.Itoa(os.Getpid())
	if err := os.WriteFile(path, []byte(me+"\n"), 0o600); err != nil {
		return nil, err
	}
	return func() {
		if b, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(b)) == me {
			os.Remove(path)
		}
	}, nil
}
