// Package listen opens the address a web app behind a local proxy is reached on:
// "unix:PATH", a socket only its own user can open, or "tcp:127.0.0.1:PORT" (or
// "tcp:[::1]:PORT"). Nothing else: the identity checks trust what arrives through the
// proxy, so the app must not be reachable around it.
package listen

import (
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Check returns spec with a leading ~ in a socket path expanded against home, or why
// spec is not an address this package opens.
func Check(spec, home string) (string, error) {
	switch {
	case strings.HasPrefix(spec, "unix:"):
		path := Expand(strings.TrimPrefix(spec, "unix:"), home)
		if !filepath.IsAbs(path) {
			return "", fmt.Errorf("listen: the socket path must be absolute, not %q", path)
		}
		return "unix:" + path, nil
	case strings.HasPrefix(spec, "tcp:127.0.0.1:"), strings.HasPrefix(spec, "tcp:[::1]:"):
		return spec, nil
	}
	return "", fmt.Errorf("listen must be unix:PATH or tcp:127.0.0.1:PORT (loopback only), not %q", spec)
}

// Expand replaces a leading ~ in p with home.
func Expand(p, home string) string {
	if p == "~" {
		return home
	}
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		return filepath.Join(home, rest)
	}
	return p
}

// Listen opens spec, which Check has passed. A socket's directory must be closed to
// other accounts (0700, created so when missing), and the socket itself is 0600. A stale
// socket left by a crash is replaced; one that something still answers on is not. Closing
// the listener removes the socket.
func Listen(spec string) (net.Listener, error) {
	if addr, ok := strings.CutPrefix(spec, "tcp:"); ok {
		return net.Listen("tcp", addr)
	}
	path := strings.TrimPrefix(spec, "unix:")
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	st, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is open to other accounts (mode %v); the socket's directory must be 0700", dir, st.Mode().Perm())
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode().Type() != fs.ModeSocket {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
			c.Close()
			return nil, fmt.Errorf("another process is serving on %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}
