package listen

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestCheck(t *testing.T) {
	for spec, want := range map[string]string{
		"unix:~/s/a.sock":    "unix:/h/s/a.sock",
		"unix:/run/a.sock":   "unix:/run/a.sock",
		"tcp:127.0.0.1:8810": "tcp:127.0.0.1:8810",
		"tcp:[::1]:8810":     "tcp:[::1]:8810",
	} {
		if got, err := Check(spec, "/h"); err != nil || got != want {
			t.Errorf("%s: %q, %v", spec, got, err)
		}
	}
	for _, bad := range []string{"tcp:0.0.0.0:80", "tcp::80", "127.0.0.1:80", "unix:rel.sock", ""} {
		if _, err := Check(bad, "/h"); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// shortDir is a private directory with a path short enough for a unix socket, which
// t.TempDir on macOS is not.
func shortDir(t *testing.T) string {
	d, err := os.MkdirTemp("/tmp", "lt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func TestUnixSocket(t *testing.T) {
	d := shortDir(t)
	path := filepath.Join(d, "s", "a.sock")
	l, err := Listen("unix:" + path)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("socket mode %v", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(filepath.Dir(path)); fi.Mode().Perm() != 0o700 {
		t.Errorf("directory mode %v", fi.Mode().Perm())
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	if _, err := Listen("unix:" + path); err == nil {
		t.Error("a second listener took a socket that is being served")
	}
	l.Close()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Errorf("closing left the socket behind: %v", err)
	}

	// A crash leaves the socket file; the next start replaces it.
	stale, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	stale.Close()
	l, err = Listen("unix:" + path)
	if err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}
	l.Close()
}

func TestRefusals(t *testing.T) {
	d := shortDir(t)
	if err := os.Chmod(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen("unix:" + filepath.Join(d, "a.sock")); err == nil {
		t.Error("a socket in a directory other accounts can open was accepted")
	}
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(d, "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen("unix:" + file); err == nil {
		t.Error("a regular file was replaced by a socket")
	}
}
