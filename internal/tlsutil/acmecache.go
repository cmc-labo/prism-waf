package tlsutil

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/crypto/acme/autocert"
)

// directoryURLFile records the CA a cache directory belongs to.
const directoryURLFile = "directory-url"

// accountKeyFiles are autocert's names for the ACME account key, current
// and legacy.
var accountKeyFiles = []string{"acme_account+key", "acme_account.key"}

// prepareACMECache creates the cache directory of the CA with the given
// directory URL below root and returns it.
//
// Certificates are cached per CA because a certificate in the cache is
// used no matter which CA issued it: switching from Let's Encrypt's
// staging environment to production would otherwise keep serving the
// untrusted staging certificates until their renewal.
//
// Older versions kept the cache directly in root. Such files are moved to
// the directory of the configured CA, except certificates from Let's
// Encrypt's staging environment, which are moved to its directory instead.
// When the staging environment is configured, other certificates and the
// account key are left in place until PrismWAF runs with their CA.
func prepareACMECache(root, directoryURL string, logger *slog.Logger) (string, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", fmt.Errorf("tlsutil: creating ACME cache directory: %w", err)
	}
	if fi, err := os.Stat(root); err == nil && fi.Mode().Perm()&0o077 != 0 {
		logger.Warn("ACME cache directory is accessible by other users; it contains private keys",
			"dir", root, "mode", fmt.Sprintf("%#o", fi.Mode().Perm()))
	}
	dir, err := caCacheDir(root, directoryURL)
	if err != nil {
		return "", err
	}
	if err := migrateACMECache(root, dir, directoryURL, logger); err != nil {
		return "", err
	}
	if directoryURL != LetsEncryptStaging {
		if err := moveStagingCerts(root, dir, logger); err != nil {
			return "", err
		}
	}
	return dir, nil
}

// caCacheDir creates and returns the cache directory of a CA, and checks
// that it can be written.
func caCacheDir(root, directoryURL string) (string, error) {
	dir := filepath.Join(root, cacheNamespace(directoryURL))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("tlsutil: creating ACME cache directory: %w", err)
	}
	marker := filepath.Join(dir, directoryURLFile)
	switch b, err := os.ReadFile(marker); {
	case err == nil:
		if got := strings.TrimSpace(string(b)); got != directoryURL {
			return "", fmt.Errorf("tlsutil: ACME cache directory %s belongs to %s, not %s; use another -acme-cache", dir, got, directoryURL)
		}
	case errors.Is(err, fs.ErrNotExist):
		if err := os.WriteFile(marker, []byte(directoryURL+"\n"), 0o600); err != nil {
			return "", fmt.Errorf("tlsutil: ACME cache directory is not writable: %w", err)
		}
	default:
		return "", fmt.Errorf("tlsutil: reading ACME cache directory: %w", err)
	}
	// Certificates are written much later, when they are issued; find out
	// now whether that will work.
	f, err := os.CreateTemp(dir, ".write-test-*")
	if err != nil {
		return "", fmt.Errorf("tlsutil: ACME cache directory is not writable: %w", err)
	}
	f.Close()
	os.Remove(f.Name())
	return dir, nil
}

var nonNameChars = regexp.MustCompile(`[^A-Za-z0-9.]+`)

// cacheNamespace returns the name of a CA's cache directory, derived from
// its directory URL, e.g. "acme-v02.api.letsencrypt.org-directory".
func cacheNamespace(directoryURL string) string {
	s := directoryURL
	if u, err := url.Parse(directoryURL); err == nil && u.Host != "" {
		s = u.Host + u.Path
	}
	s = strings.Trim(nonNameChars.ReplaceAllString(s, "-"), "-.")
	if s == "" {
		return "default"
	}
	return s
}

// migrateACMECache moves the cache files of older versions from root to
// dir.
func migrateACMECache(root, dir, directoryURL string, logger *slog.Logger) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return fmt.Errorf("tlsutil: reading ACME cache directory: %w", err)
	}
	var accountKeys []string
	leftBehind := false
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		name, src := e.Name(), filepath.Join(root, e.Name())
		switch {
		case strings.HasSuffix(name, "+token") || strings.HasSuffix(name, "+http-01"):
			// Challenge data of an interrupted request.
			os.Remove(src)
		case isAccountKeyFile(name):
			accountKeys = append(accountKeys, name)
		default:
			leaf := readCachedCert(src)
			if leaf == nil {
				continue // not a cache file
			}
			target := dir
			if isStagingCert(leaf) && directoryURL != LetsEncryptStaging {
				if target, err = caCacheDir(root, LetsEncryptStaging); err != nil {
					return err
				}
			} else if !isStagingCert(leaf) && directoryURL == LetsEncryptStaging {
				logger.Warn("ACME cache: leaving a certificate from an older version in place; start with the CA that issued it to migrate it",
					"file", src, "issuer", leaf.Issuer.String())
				leftBehind = true
				continue
			}
			moveCacheFile(src, filepath.Join(target, name), logger)
		}
	}
	// The account key belongs to the CA of the certificates.
	if !leftBehind {
		for _, name := range accountKeys {
			moveCacheFile(filepath.Join(root, name), filepath.Join(dir, name), logger)
		}
	}
	return nil
}

// moveStagingCerts moves certificates of Let's Encrypt's staging
// environment from the cache directory of another CA to the staging
// directory. They end up there when files are copied by hand.
func moveStagingCerts(root, dir string, logger *slog.Logger) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("tlsutil: reading ACME cache directory: %w", err)
	}
	var staging string
	for _, e := range entries {
		src := filepath.Join(dir, e.Name())
		if !e.Type().IsRegular() || isAccountKeyFile(e.Name()) {
			continue
		}
		if leaf := readCachedCert(src); leaf == nil || !isStagingCert(leaf) {
			continue
		}
		if staging == "" {
			if staging, err = caCacheDir(root, LetsEncryptStaging); err != nil {
				return err
			}
		}
		logger.Warn("ACME cache: moving a Let's Encrypt staging certificate out of the cache of another CA", "file", src)
		moveCacheFile(src, filepath.Join(staging, e.Name()), logger)
	}
	return nil
}

func moveCacheFile(src, dst string, logger *slog.Logger) {
	if _, err := os.Lstat(dst); err == nil {
		logger.Warn("ACME cache: not moving a file because the target exists; remove one of them", "file", src, "target", dst)
		return
	}
	if err := os.Rename(src, dst); err != nil {
		logger.Warn("ACME cache: cannot move file", "file", src, "target", dst, "error", err)
		return
	}
	logger.Info("ACME cache: moved file to the directory of its CA", "file", src, "target", dst)
}

func isAccountKeyFile(name string) bool {
	for _, n := range accountKeyFiles {
		if name == n {
			return true
		}
	}
	return false
}

// readCachedCert returns the leaf certificate of an autocert cache entry,
// or nil if the file is not one.
func readCachedCert(path string) *x509.Certificate {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return parseCachedCert(b)
}

// parseCachedCert parses autocert's format: the private key followed by
// the certificate chain, PEM-encoded.
func parseCachedCert(data []byte) *x509.Certificate {
	key, rest := pem.Decode(data)
	if key == nil || !strings.Contains(key.Type, "PRIVATE KEY") {
		return nil
	}
	b, _ := pem.Decode(rest)
	if b == nil || b.Type != "CERTIFICATE" {
		return nil
	}
	leaf, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil
	}
	return leaf
}

// isStagingCert reports whether a certificate was issued by Let's
// Encrypt's staging environment, whose issuers are named "(STAGING) …".
func isStagingCert(c *x509.Certificate) bool {
	return strings.Contains(c.Issuer.String(), "(STAGING)")
}

// acmeCache is autocert's directory cache with notifications of stored
// certificates and logging of write errors, which autocert ignores.
type acmeCache struct {
	autocert.DirCache
	onCert func(key string, leaf *x509.Certificate)
	logger *slog.Logger
}

func (c *acmeCache) Put(ctx context.Context, key string, data []byte) error {
	if err := c.DirCache.Put(ctx, key, data); err != nil {
		c.logger.Error("cannot write ACME cache; certificates will be requested again after a restart", "key", key, "error", err)
		return err
	}
	if strings.HasSuffix(key, "+token") || strings.HasSuffix(key, "+http-01") || isAccountKeyFile(key) {
		return nil
	}
	if leaf := parseCachedCert(data); leaf != nil {
		c.onCert(key, leaf)
	}
	return nil
}
