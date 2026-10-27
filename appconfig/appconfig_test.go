package appconfig

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// app is how an app uses the package: Base embedded, its own fields beside it.
type app struct {
	Base
	Every int `json:"every"`
}

func load(t *testing.T, body string) (*app, error) {
	p := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var a app
	if err := Load(p, &a); err != nil {
		return nil, err
	}
	return &a, a.Check("/h")
}

func TestLoad(t *testing.T) {
	a, err := load(t, `{"device":"d","origin":"https://x.example","listen":"unix:~/s/a.sock",
		"identity":{"mode":"tailscale"},"remote_kill":true,"pid_file":"~/p","every":3}`)
	if err != nil {
		t.Fatal(err)
	}
	if a.Listen != "unix:/h/s/a.sock" || a.PIDFile != "/h/p" || a.Path != "/" || !a.RemoteKill || a.Every != 3 {
		t.Errorf("%+v", a)
	}
}

func TestRefused(t *testing.T) {
	base := `"device":"d","origin":"https://x.example","identity":{"mode":"tailscale"}`
	for name, body := range map[string]string{
		"public listen":  `{` + base + `,"listen":"tcp:0.0.0.0:80"}`,
		"no identity":    `{"device":"d","origin":"https://x.example","listen":"unix:/s"}`,
		"cf without aud": `{"device":"d","origin":"https://x.example","listen":"unix:/s","identity":{"mode":"cloudflare","team":"t"}}`,
		"origin path":    `{"device":"d","origin":"https://x.example/ctl","listen":"unix:/s","identity":{"mode":"tailscale"}}`,
		"unknown field":  `{` + base + `,"listen":"unix:/s","remote_kil":true}`,
		"bad colour":     `{` + base + `,"listen":"unix:/s","color":"red"}`,
		"no device":      `{"origin":"https://x.example","listen":"unix:/s","identity":{"mode":"tailscale"}}`,
	} {
		if _, err := load(t, body); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestWritePID(t *testing.T) {
	p := filepath.Join(t.TempDir(), "run", "a.pid")
	remove, err := WritePID(p)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); strings.TrimSpace(string(b)) != strconv.Itoa(os.Getpid()) {
		t.Errorf("pid file holds %q", b)
	}
	remove()
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Error("not removed")
	}
	// A file another process has since claimed stays.
	if err := os.WriteFile(p, []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	remove()
	if _, err := os.Stat(p); err != nil {
		t.Error("removed another process's pid file")
	}
}
