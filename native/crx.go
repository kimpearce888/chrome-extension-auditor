package main

// Safe archive extraction (§54, §104): CRX2/CRX3 and ZIP handling with
// zip-bomb, path-traversal, symlink, size and count protections. Extracted
// content is never executed.

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// SafeExtractArchive extracts a CRX/ZIP into a unique temp dir under the app
// temp root (§162) with all §104 protections.
func SafeExtractArchive(path string, limits Limits) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", &ProtocolError{Code: "SCAN_FAILED", Message: "archive unreadable"}
	}
	if int64(len(data)) > limits.MaxPackageBytes {
		return "", &ProtocolError{Code: "ARCHIVE_TOO_LARGE", Message: "archive exceeds size limit"}
	}
	zipBytes, err := stripCRXHeader(data)
	if err != nil {
		return "", err
	}
	tmpRoot := filepath.Join(os.TempDir(), "extension-auditor")
	if err := os.MkdirAll(tmpRoot, 0o700); err != nil {
		return "", &ProtocolError{Code: "SCAN_FAILED", Message: "cannot create temp dir"}
	}
	dir, err := os.MkdirTemp(tmpRoot, "extract-")
	if err != nil {
		return "", &ProtocolError{Code: "SCAN_FAILED", Message: "cannot create temp dir"}
	}
	if err := extractZipBytes(zipBytes, dir, limits, 0); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}

// stripCRXHeader removes CRX2/CRX3 headers, returning raw ZIP bytes.
func stripCRXHeader(data []byte) ([]byte, error) {
	if len(data) < 4 || string(data[:4]) != "Cr24" {
		if len(data) > 2 && data[0] == 'P' && data[1] == 'K' {
			return data, nil // plain ZIP
		}
		return nil, &ProtocolError{Code: "SCAN_FAILED", Message: "not a CRX or ZIP file"}
	}
	if len(data) < 12 {
		return nil, &ProtocolError{Code: "SCAN_FAILED", Message: "CRX header truncated"}
	}
	version := le32(data[4:8])
	switch version {
	case 2:
		// CRX2: sig len (4), sig, pubkey len (4), pubkey, zip
		if len(data) < 12 {
			return nil, &ProtocolError{Code: "SCAN_FAILED", Message: "CRX2 header truncated"}
		}
		sigLen := le32(data[8:12])
		pos := 12 + sigLen
		if int(pos)+4 > len(data) {
			return nil, &ProtocolError{Code: "SCAN_FAILED", Message: "CRX2 signature truncated"}
		}
		keyLen := le32(data[pos : pos+4])
		pos += 4 + keyLen
		if int(pos) > len(data) {
			return nil, &ProtocolError{Code: "SCAN_FAILED", Message: "CRX2 key truncated"}
		}
		return data[pos:], nil
	case 3:
		// CRX3: header length (4), header blob, zip
		headerLen := le32(data[8:12])
		pos := 12 + headerLen
		if int(pos) > len(data) {
			return nil, &ProtocolError{Code: "SCAN_FAILED", Message: "CRX3 header truncated"}
		}
		return data[pos:], nil
	default:
		return nil, &ProtocolError{Code: "SCAN_FAILED", Message: fmt.Sprintf("unsupported CRX version %d", version)}
	}
}

func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// extractZipBytes extracts with all protections, including nested archives.
func extractZipBytes(zipBytes []byte, dest string, limits Limits, depth int) error {
	if depth > limits.MaxNestedArchives {
		return &ProtocolError{Code: "SCAN_FAILED", Message: "archive nesting too deep"}
	}
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return &ProtocolError{Code: "SCAN_FAILED", Message: "malformed archive"}
	}
	if len(zr.File) > limits.MaxArchiveEntries {
		return &ProtocolError{Code: "ARCHIVE_TOO_LARGE", Message: "too many entries in archive"}
	}
	var totalUncompressed int64
	for _, f := range zr.File {
		if f.UncompressedSize64 > uint64(limits.MaxArchiveExtract) {
			return &ProtocolError{Code: "ARCHIVE_TOO_LARGE", Message: "entry exceeds extraction limit"}
		}
		totalUncompressed += int64(f.UncompressedSize64)
		if totalUncompressed > limits.MaxArchiveExtract {
			return &ProtocolError{Code: "ARCHIVE_TOO_LARGE", Message: "total extraction exceeds limit"}
		}
		// compression ratio check (zip bomb)
		if f.CompressedSize64 > 0 {
			ratio := float64(f.UncompressedSize64) / float64(f.CompressedSize64)
			if ratio > limits.MaxCompressionRatio && f.UncompressedSize64 > 1_000_000 {
				return &ProtocolError{Code: "ARCHIVE_TOO_LARGE", Message: "suspicious compression ratio (possible zip bomb)"}
			}
		}
		// path safety (§104)
		name := f.Name
		if strings.Contains(name, "..") || strings.HasPrefix(name, "/") || strings.Contains(name, ":\\") || strings.HasPrefix(name, "\\") {
			return &ProtocolError{Code: "ACCESS_DENIED", Message: "unsafe path in archive: " + name}
		}
		// symlink check
		if f.Mode()&os.ModeSymlink != 0 {
			return &ProtocolError{Code: "ACCESS_DENIED", Message: "symlink in archive rejected"}
		}
		target, err := safeJoin(dest, name)
		if err != nil {
			return err
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o700); err != nil {
				return &ProtocolError{Code: "SCAN_FAILED", Message: "mkdir failed"}
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return &ProtocolError{Code: "SCAN_FAILED", Message: "mkdir failed"}
		}
		rc, err := f.Open()
		if err != nil {
			return &ProtocolError{Code: "SCAN_FAILED", Message: "entry unreadable"}
		}
		// bounded copy
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			rc.Close()
			return &ProtocolError{Code: "SCAN_FAILED", Message: "cannot write extracted file"}
		}
		written, cerr := io.Copy(out, io.LimitReader(rc, limits.MaxArchiveExtract+1))
		rc.Close()
		out.Close()
		if cerr != nil {
			return &ProtocolError{Code: "SCAN_FAILED", Message: "extraction failed"}
		}
		if written > limits.MaxArchiveExtract {
			return &ProtocolError{Code: "ARCHIVE_TOO_LARGE", Message: "entry exceeded extraction limit"}
		}
		// nested archive: extract one level (bounded)
		lower := strings.ToLower(name)
		if depth < limits.MaxNestedArchives && (strings.HasSuffix(lower, ".zip") || strings.HasSuffix(lower, ".crx")) {
			nested, nerr := os.ReadFile(target)
			if nerr == nil && int64(len(nested)) < 64*1024*1024 {
				if zb, zerr := stripCRXHeader(nested); zerr == nil {
					nestedDir := target + ".extracted"
					if mkErr := os.MkdirAll(nestedDir, 0o700); mkErr == nil {
						if xerr := extractZipBytes(zb, nestedDir, limits, depth+1); xerr == nil {
							_ = os.Remove(target)
						} else {
							os.RemoveAll(nestedDir)
						}
					}
				}
			}
		}
	}
	return nil
}
