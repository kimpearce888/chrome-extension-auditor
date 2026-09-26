package main

// Path security per §103: every filesystem path received or derived is
// validated. The native host never executes anything and only reads from
// locations it is allowed to read.

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// PathValidator restricts access to allowed roots.
type PathValidator struct {
	roots []string // absolute, cleaned
}

func NewPathValidator() *PathValidator { return &PathValidator{} }

func (pv *PathValidator) AddRoot(dir string) {
	dir = filepath.Clean(dir)
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	for _, r := range pv.roots {
		if strings.EqualFold(r, dir) {
			return
		}
	}
	pv.roots = append(pv.roots, dir)
}

// hasUNC detects \\server\share style paths (rejected, §103).
func hasUNC(p string) bool {
	return strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, `//`)
}

// Validate checks an inbound path and returns the cleaned absolute path or an
// error explaining the rejection.
func (pv *PathValidator) Validate(p string) (string, error) {
	if p == "" {
		return "", &ProtocolError{Code: "ACCESS_DENIED", Message: "empty path"}
	}
	if hasUNC(p) {
		return "", &ProtocolError{Code: "ACCESS_DENIED", Message: "UNC paths are not permitted"}
	}
	if strings.Contains(p, "..") {
		return "", &ProtocolError{Code: "ACCESS_DENIED", Message: "path traversal ('..') is not permitted"}
	}
	clean := filepath.Clean(p)
	if !filepath.IsAbs(clean) {
		return "", &ProtocolError{Code: "ACCESS_DENIED", Message: "relative paths are not permitted"}
	}
	// Drive check: on Windows allow only the same drive(s) as roots, if any
	// roots are known. On Linux roots are ordinary prefixes.
	if len(pv.roots) > 0 {
		allowed := false
		for _, r := range pv.roots {
			if pathWithin(clean, r) {
				allowed = true
				break
			}
		}
		if !allowed {
			return "", &ProtocolError{Code: "ACCESS_DENIED", Message: "path is outside the permitted scan locations"}
		}
	}
	// Symlink-escape check: ensure no component is a symlink pointing outside.
	if err := checkSymlinkEscape(clean, pv.roots); err != nil {
		return "", err
	}
	return clean, nil
}

// pathWithin reports whether p equals r or is inside it.
func pathWithin(p, r string) bool {
	if strings.EqualFold(p, r) {
		return true
	}
	return strings.HasPrefix(strings.ToLower(p), strings.ToLower(r)+string(os.PathSeparator))
}

// checkSymlinkEscape walks the path components and rejects symlinks that
// resolve outside the allowed roots (§103 "symbolic-link escapes").
func checkSymlinkEscape(p string, roots []string) error {
	if roots == nil {
		roots = []string{}
	}
	cur := filepath.VolumeName(p) + string(os.PathSeparator)
	if !filepath.IsAbs(p) {
		cur = ""
	} else if cur == string(os.PathSeparator) || cur == "" {
		cur = string(os.PathSeparator)
	}
	rest := strings.TrimPrefix(strings.TrimPrefix(p, cur), string(os.PathSeparator))
	parts := strings.Split(rest, string(os.PathSeparator))
	for _, part := range parts {
		if part == "" {
			continue
		}
		next := filepath.Join(cur, part)
		if fi, err := os.Lstat(next); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			resolved, err := filepath.EvalSymlinks(next)
			if err != nil {
				return &ProtocolError{Code: "ACCESS_DENIED", Message: "cannot resolve symlink: " + part}
			}
			ok := false
			for _, r := range roots {
				if pathWithin(resolved, r) {
					ok = true
					break
				}
			}
			if !ok && len(roots) > 0 {
				return &ProtocolError{Code: "ACCESS_DENIED", Message: "symlink escapes permitted locations"}
			}
			next = resolved
		}
		cur = next
	}
	return nil
}

// safeJoin joins dir+name for archive entries with traversal protection
// (also used by §104).
func safeJoin(dir, name string) (string, error) {
	name = strings.ReplaceAll(name, `\`, "/")
	// Reject absolute and drive-letter paths.
	if strings.HasPrefix(name, "/") || strings.Contains(name, ":") && len(name) > 1 && name[1] == ':' {
		return "", &ProtocolError{Code: "ACCESS_DENIED", Message: "absolute path in archive entry"}
	}
	clean := filepath.Clean(name)
	if strings.HasPrefix(clean, "..") || clean == ".." {
		return "", &ProtocolError{Code: "ACCESS_DENIED", Message: "path traversal in archive entry"}
	}
	return filepath.Join(dir, clean), nil
}

// fileURLHost is a small helper for source-viewer URIs (kept local).
func fileURLHost(u string) string {
	if parsed, err := url.Parse(u); err == nil && parsed.Host != "" {
		return parsed.Host
	}
	return ""
}

// ValidateDiscovered applies basic sanity checks to paths the scanner itself
// discovered by reading Chrome's preference files (not paths received from
// the extension UI). Chrome controls these values; they may legitimately point
// anywhere on disk (e.g. unpacked developer extensions), so root containment
// is not required — but traversal/UNC-style attacks still are.
func (pv *PathValidator) ValidateDiscovered(p string) (string, error) {
	if p == "" {
		return "", &ProtocolError{Code: "ACCESS_DENIED", Message: "empty path"}
	}
	if hasUNC(p) {
		return "", &ProtocolError{Code: "ACCESS_DENIED", Message: "UNC paths are not permitted"}
	}
	if strings.Contains(p, "..") {
		return "", &ProtocolError{Code: "ACCESS_DENIED", Message: "path traversal ('..') is not permitted"}
	}
	if !filepath.IsAbs(p) {
		return "", &ProtocolError{Code: "ACCESS_DENIED", Message: "relative paths are not permitted"}
	}
	return filepath.Clean(p), nil
}
