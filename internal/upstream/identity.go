package upstream

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/openziti/identity"
	"github.com/openziti/sdk-golang/ziti"
)

const (
	maxIdentityFileBytes = 4 << 20
	maxCredentialBytes   = 8 << 20
)

type capturedIdentity struct {
	config  ziti.Config
	binding Binding
}

func captureIdentity(profile, path string) (capturedIdentity, error) {
	if strings.TrimSpace(path) == "" {
		return capturedIdentity{}, fmt.Errorf("openziti identity %q has no identity file", profile)
	}
	data, err := readBoundedFile(path, maxIdentityFileBytes, true)
	if err != nil {
		return capturedIdentity{}, fmt.Errorf("cannot load openziti identity %q: %w", profile, err)
	}
	var parsed ziti.Config
	if err := json.Unmarshal(data, &parsed); err != nil {
		return capturedIdentity{}, fmt.Errorf("invalid openziti identity %q", profile)
	}
	if len(parsed.ZtAPIs) == 0 && strings.TrimSpace(parsed.ZtAPI) == "" {
		return capturedIdentity{}, fmt.Errorf("openziti identity %q has no controller", profile)
	}
	controllers := parsed.ZtAPIs
	if len(controllers) == 0 {
		controllers = []string{parsed.ZtAPI}
	}
	for _, controller := range controllers {
		u, err := url.Parse(controller)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return capturedIdentity{}, fmt.Errorf("invalid controller URL for openziti identity %q", profile)
		}
	}
	baseDir := filepath.Dir(path)
	embedded, err := embedIdentityConfig(parsed.ID, baseDir)
	if err != nil {
		return capturedIdentity{}, fmt.Errorf("invalid credentials for openziti identity %q: %w", profile, err)
	}
	parsed.ID = embedded
	disableSDKDiagnostics()
	loaded, err := identity.LoadIdentity(embedded)
	if err != nil {
		return capturedIdentity{}, fmt.Errorf("invalid credentials for openziti identity %q", profile)
	}
	chain := loaded.GetX509ActiveClientCertChain()
	now := time.Now()
	if len(chain) == 0 || now.Before(chain[0].NotBefore) || !now.Before(chain[0].NotAfter) {
		return capturedIdentity{}, fmt.Errorf("openziti identity %q has no currently valid client certificate", profile)
	}
	// Identity parsing does not verify this match. Check before deduplication:
	// generation fingerprints deliberately exclude private key material.
	key, keyOK := loaded.Cert().PrivateKey.(crypto.Signer)
	publicKey, publicKeyOK := chain[0].PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !keyOK || !publicKeyOK || !publicKey.Equal(key.Public()) {
		return capturedIdentity{}, fmt.Errorf("invalid credentials for openziti identity %q", profile)
	}
	fingerprint, err := generationFingerprint(parsed)
	if err != nil {
		return capturedIdentity{}, errors.New("unable to fingerprint openziti identity")
	}
	binding := Binding{Type: TypeOpenZiti, Identity: profile, IdentityGeneration: fingerprint}
	return capturedIdentity{config: parsed, binding: binding}, nil
}

func embedIdentityConfig(cfg identity.Config, baseDir string) (identity.Config, error) {
	capture := credentialCapture{remaining: maxCredentialBytes}
	var err error
	if cfg.Key, err = capture.embedRequired(cfg.Key, baseDir, true); err != nil {
		return identity.Config{}, err
	}
	if cfg.Cert, err = capture.embedRequired(cfg.Cert, baseDir, false); err != nil {
		return identity.Config{}, err
	}
	if cfg.ServerCert, err = capture.embedOptional(cfg.ServerCert, baseDir, false); err != nil {
		return identity.Config{}, err
	}
	if cfg.ServerKey, err = capture.embedOptional(cfg.ServerKey, baseDir, true); err != nil {
		return identity.Config{}, err
	}
	if cfg.CA, err = capture.embedOptional(cfg.CA, baseDir, false); err != nil {
		return identity.Config{}, err
	}
	for i := range cfg.AltServerCerts {
		if cfg.AltServerCerts[i].ServerCert, err = capture.embedRequired(cfg.AltServerCerts[i].ServerCert, baseDir, false); err != nil {
			return identity.Config{}, err
		}
		if cfg.AltServerCerts[i].ServerKey, err = capture.embedOptional(cfg.AltServerCerts[i].ServerKey, baseDir, true); err != nil {
			return identity.Config{}, err
		}
	}
	return cfg, nil
}

type credentialCapture struct {
	remaining int64
}

func (c *credentialCapture) embedRequired(value, baseDir string, private bool) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("credential is empty")
	}
	return c.embed(value, baseDir, private)
}

func (c *credentialCapture) embedOptional(value, baseDir string, private bool) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", nil
	}
	return c.embed(value, baseDir, private)
}

func (c *credentialCapture) embed(value, baseDir string, private bool) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("credential is empty")
	}
	if strings.HasPrefix(value, "pem:") {
		if int64(len(value)) > c.remaining {
			return "", errors.New("credential exceeds size limit")
		}
		c.remaining -= int64(len(value))
		return value, nil
	}
	if strings.HasPrefix(value, "-----BEGIN") {
		if int64(len(value)) > c.remaining {
			return "", errors.New("credential exceeds size limit")
		}
		c.remaining -= int64(len(value))
		return "pem:" + value, nil
	}
	if strings.Contains(value, ":") && !strings.HasPrefix(value, "file:") {
		return "", errors.New("unsupported credential storage")
	}
	path := value
	if strings.HasPrefix(value, "file:") {
		u, err := url.Parse(value)
		if err != nil || u.Host != "" || u.RawQuery != "" || u.Fragment != "" {
			return "", errors.New("invalid credential path")
		}
		path = u.Path
		if u.Opaque != "" {
			path = u.Opaque
		}
		if path == "" {
			return "", errors.New("empty credential path")
		}
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(baseDir, path)
	}
	if c.remaining <= 0 {
		return "", errors.New("credential exceeds size limit")
	}
	data, err := readBoundedFile(path, c.remaining, private)
	if err != nil {
		return "", err
	}
	c.remaining -= int64(len(data))
	return "pem:" + strings.TrimSpace(string(data)), nil
}

func readBoundedFile(path string, limit int64, private bool) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("credential path must be absolute")
	}
	// Walk directory descriptors so a concurrent rename cannot substitute a
	// symlink after a pathname check. O_NONBLOCK also rejects FIFOs without
	// waiting for a writer before the regular-file check.
	flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	file, err := os.OpenFile("/", flags|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/")
	for index, part := range parts {
		last := index == len(parts)-1
		openFlags := flags
		if !last {
			openFlags |= syscall.O_DIRECTORY
		}
		fd, err := syscall.Openat(int(file.Fd()), part, openFlags, 0)
		if err != nil {
			return nil, errors.New("credential path is unavailable or contains a symlink")
		}
		_ = file.Close()
		file = os.NewFile(uintptr(fd), part)
		info, err := file.Stat()
		if err != nil {
			return nil, err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (int64(stat.Uid) != int64(os.Geteuid()) && stat.Uid != 0) {
			return nil, errors.New("credential path is owned by another user")
		}
		if !last {
			sharedTemp := stat.Uid == 0 && info.Mode()&os.ModeSticky != 0
			if !info.IsDir() || (info.Mode().Perm()&0o022 != 0 && !sharedTemp) {
				return nil, errors.New("credential directory has unsafe permissions")
			}
			continue
		}
		if !info.Mode().IsRegular() {
			return nil, errors.New("credential is not a regular file")
		}
		forbidden := os.FileMode(0o133)
		if private {
			forbidden = 0o177
		}
		if info.Mode().Perm()&forbidden != 0 {
			return nil, errors.New("credential has unsafe permissions")
		}
		if info.Size() > limit {
			return nil, errors.New("credential exceeds size limit")
		}
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("credential exceeds size limit")
	}
	return data, nil
}

func generationFingerprint(cfg ziti.Config) (string, error) {
	type publicServerPair struct {
		ServerCert string `json:"server_cert,omitempty"`
	}
	type publicIdentity struct {
		Cert           string             `json:"cert"`
		ServerCert     string             `json:"server_cert,omitempty"`
		AltServerCerts []publicServerPair `json:"alt_server_certs,omitempty"`
		CA             string             `json:"ca,omitempty"`
	}
	canonical := struct {
		ZtAPI       string         `json:"ztAPI"`
		ZtAPIs      []string       `json:"ztAPIs,omitempty"`
		ConfigTypes []string       `json:"configTypes,omitempty"`
		ID          publicIdentity `json:"id"`
	}{
		ZtAPI:       cfg.ZtAPI,
		ZtAPIs:      append([]string(nil), cfg.ZtAPIs...),
		ConfigTypes: append([]string(nil), cfg.ConfigTypes...),
		ID: publicIdentity{
			Cert:       cfg.ID.Cert,
			ServerCert: cfg.ID.ServerCert,
			CA:         cfg.ID.CA,
		},
	}
	for _, pair := range cfg.ID.AltServerCerts {
		canonical.ID.AltServerCerts = append(canonical.ID.AltServerCerts, publicServerPair{ServerCert: pair.ServerCert})
	}
	data, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
