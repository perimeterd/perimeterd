package upstream

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-openapi/runtime/logger"
	"github.com/openziti/identity"
	"github.com/openziti/sdk-golang/ziti"
	"github.com/sirupsen/logrus"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/policy"
)

const (
	maxIdentityFileBytes  = 4 << 20
	maxCredentialBytes    = 8 << 20
	controllerHTTPTimeout = 30 * time.Second
	// Four static fetches and overlapping CrowdSec epochs can dial concurrently.
	// Admission happens before starting a worker: canceled SDK authentication
	// must not accumulate an unbounded queue of perimeterd goroutines.
	maxSDKDials = 8
)

var errManagerClosed = errors.New("upstream manager is closed")

// Manager owns immutable, shared identity generations. It never mutates the
// process-wide HTTP defaults or the SDK default context collection.
type Manager struct {
	mu          sync.Mutex
	generations map[Binding]*generation
	live        map[*generation]struct{}
	dials       chan struct{}
	closed      bool
}

// Session is a separately closable view of the generations captured by one
// admitted configuration. A session never rereads an identity file.
type Session struct {
	mu          sync.Mutex
	manager     *Manager
	generations map[string]*generation
	closed      bool
}

type generation struct {
	manager *Manager
	binding Binding
	config  ziti.Config
	ctx     context.Context
	cancel  context.CancelFunc

	refs      int // protected by manager.mu
	closeOnce sync.Once
	closed    chan struct{}

	sdkMu       sync.Mutex
	contextOnce sync.Once
	zitiContext ziti.Context
	contextErr  error
	dialSlot    chan struct{}

	transportMu sync.Mutex
	transports  map[*http.Transport]struct{}
}

type capturedIdentity struct {
	config  ziti.Config
	binding Binding
}

// NewManager creates an empty manager. Direct-only callers may keep one for
// their whole process without causing any filesystem or SDK activity.
func NewManager() *Manager {
	return &Manager{
		generations: make(map[Binding]*generation),
		live:        make(map[*generation]struct{}),
		dials:       make(chan struct{}, maxSDKDials),
	}
}

// Load captures only identities referenced by enabled policies and enabled
// CrowdSec. It validates and embeds all credential PEM material but does not
// authenticate or contact a controller.
func (m *Manager) Load(ctx context.Context, cfg config.Config) (*Session, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	profiles, err := referencedProfiles(cfg)
	if err != nil {
		return nil, err
	}
	// OpenAPI's environment-enabled wire dumps bypass logrus and include
	// authentication responses. Refuse them rather than mutate global env or
	// race the SDK's already-running controller client to replace its logger.
	if len(profiles) != 0 && logger.DebugEnabled() {
		return nil, errors.New("openziti requires DEBUG and SWAGGER_DEBUG unset, false, or 0 to prevent credential logging")
	}
	profileNames := make([]string, 0, len(profiles))
	for profile := range profiles {
		profileNames = append(profileNames, profile)
	}
	sort.Strings(profileNames)
	captured := make(map[string]capturedIdentity, len(profiles))
	for _, profile := range profileNames {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		identityCfg, ok := cfg.OpenZiti.Identities[profile]
		if !ok {
			return nil, fmt.Errorf("openziti identity %q is not defined", profile)
		}
		loaded, err := captureIdentity(profile, identityCfg.IdentityFile)
		if err != nil {
			return nil, err
		}
		captured[profile] = loaded
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	session := &Session{manager: m, generations: make(map[string]*generation, len(captured))}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, errManagerClosed
	}
	for profile, loaded := range captured {
		gen := m.generations[loaded.binding]
		if gen == nil {
			lifetime, cancel := context.WithCancel(context.Background())
			gen = &generation{
				manager:    m,
				binding:    loaded.binding,
				config:     loaded.config,
				ctx:        lifetime,
				cancel:     cancel,
				closed:     make(chan struct{}),
				dialSlot:   make(chan struct{}, 1),
				transports: make(map[*http.Transport]struct{}),
			}
			m.generations[loaded.binding] = gen
			m.live[gen] = struct{}{}
		}
		gen.refs++
		session.generations[profile] = gen
	}
	return session, nil
}

// Close cancels perimeterd requests and retires every SDK context, waiting up to
// ctx's deadline for context Close calls, not for uncancelable SDK authentication.
func (m *Manager) Close(ctx context.Context) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	m.closed = true
	gens := make([]*generation, 0, len(m.live))
	for gen := range m.live {
		gens = append(gens, gen)
	}
	m.mu.Unlock()
	for _, gen := range gens {
		gen.startClose()
	}
	for _, gen := range gens {
		select {
		case <-gen.closed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// Retain returns another handle to the same immutable generation bundle.
func (s *Session) Retain() *Session {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.manager.mu.Lock()
	defer s.manager.mu.Unlock()
	if s.manager.closed {
		return nil
	}
	for _, gen := range s.generations {
		gen.refs++
	}
	return &Session{manager: s.manager, generations: s.generations}
}

// Close releases this handle immediately; SDK shutdown is performed by the
// generation owner outside the session lock and never blocks this method.
func (s *Session) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	gens := s.generations
	s.generations = nil
	s.mu.Unlock()
	for _, gen := range gens {
		gen.release()
	}
}

func (g *generation) retain() bool {
	g.manager.mu.Lock()
	defer g.manager.mu.Unlock()
	if g.manager.closed || g.refs == 0 {
		return false
	}
	g.refs++
	return true
}

func (g *generation) release() {
	g.manager.mu.Lock()
	g.refs--
	retire := g.refs == 0
	if retire {
		delete(g.manager.generations, g.binding)
	}
	g.manager.mu.Unlock()
	if retire {
		g.startClose()
	}
}

func (g *generation) acquireOperation() bool { return g.retain() }

func (g *generation) startClose() {
	g.closeOnce.Do(func() {
		g.cancel()
		go g.shutdown()
	})
}

func (g *generation) shutdown() {
	g.transportMu.Lock()
	pools := g.transports
	g.transports = nil
	g.transportMu.Unlock()
	for transport := range pools {
		transport.CloseIdleConnections()
	}
	// Serialize construction versus close, not authentication versus close.
	g.sdkMu.Lock()
	if g.zitiContext != nil {
		g.zitiContext.Close()
	}
	g.sdkMu.Unlock()
	close(g.closed)
	g.manager.mu.Lock()
	delete(g.manager.live, g)
	g.manager.mu.Unlock()
}

// SDK v1.8.2 starts controller discovery during construction, so cached/offline
// loads must not construct a context. Its authentication/version workers can
// survive cancellation and Close. Keep our callers and worker admission bounded;
// never wait for those workers during retirement or claim they have drained.
func (g *generation) sdkContext() (ziti.Context, error) {
	g.sdkMu.Lock()
	defer g.sdkMu.Unlock()
	if err := g.ctx.Err(); err != nil {
		return nil, err
	}
	g.contextOnce.Do(func() {
		disableSDKDiagnostics()
		options := *ziti.DefaultOptions
		options.HttpTimeout = controllerHTTPTimeout
		options.AuthMaxElapsed = controllerHTTPTimeout
		captured := g.config
		zctx, err := ziti.NewContextWithOpts(&captured, &options)
		if err != nil {
			g.contextErr = errors.New("unable to initialize ziti context")
			return
		}
		g.zitiContext = zctx
	})
	return g.zitiContext, g.contextErr
}

func (g *generation) dial(ctx context.Context, service string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case g.dialSlot <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-g.ctx.Done():
		return nil, errManagerClosed
	}
	select {
	case g.manager.dials <- struct{}{}:
	case <-ctx.Done():
		<-g.dialSlot
		return nil, ctx.Err()
	case <-g.ctx.Done():
		<-g.dialSlot
		return nil, errManagerClosed
	}
	result := make(chan dialResult)
	go func() {
		defer func() {
			<-g.manager.dials
			<-g.dialSlot
		}()
		zctx, err := g.sdkContext()
		var conn net.Conn
		if err == nil {
			// The pinned SDK starts discovery in its constructor, while
			// authentication mutates the same TLS config. Its public capability
			// query joins discovery's sync.Once before the first authentication.
			// Keep this potentially uninterruptible wait inside admitted work,
			// outside sdkMu so cancellation and context closure remain bounded.
			zctx.(*ziti.ContextImpl).CtrlClt.API.ControllerSupportsOidc()
			if err = ctx.Err(); err == nil {
				err = g.ctx.Err()
			}
			if err == nil {
				conn, err = zctx.DialContext(ctx, service)
			}
		}
		if err != nil {
			if ctx.Err() != nil {
				err = ctx.Err()
			} else {
				err = errors.New("ziti service dial failed")
			}
		}
		// A canceled caller cannot receive a late connection. The unbuffered
		// handoff either transfers ownership or closes it here.
		select {
		case result <- dialResult{conn: conn, err: err}:
		case <-ctx.Done():
			if conn != nil {
				_ = conn.Close()
			}
		case <-g.ctx.Done():
			if conn != nil {
				_ = conn.Close()
			}
		}
	}()
	select {
	case outcome := <-result:
		return outcome.conn, outcome.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-g.ctx.Done():
		return nil, errManagerClosed
	}
}

type dialResult struct {
	conn net.Conn
	err  error
}

var sdkLogOnce sync.Once

// As with CrowdSec, SDK logrus diagnostics are not application observability:
// they may contain session credentials. Perimeterd's slog output is unaffected.
func disableSDKDiagnostics() {
	sdkLogOnce.Do(func() {
		logrus.StandardLogger().SetOutput(io.Discard)
		logrus.StandardLogger().SetLevel(logrus.PanicLevel)
	})
}

func referencedProfiles(cfg config.Config) (map[string]struct{}, error) {
	profiles := make(map[string]struct{})
	selectors, err := policy.RequiredSelectors(cfg)
	if err != nil {
		return nil, errors.New("unable to identify required policy sources")
	}
	for _, selector := range selectors {
		if selector.Kind != policy.IPList {
			continue
		}
		list, ok := cfg.IPLists[selector.Value]
		if !ok || list.Transport.Type != TypeOpenZiti {
			continue
		}
		profiles[list.Transport.Identity] = struct{}{}
	}
	if cfg.CrowdSec.Enabled && cfg.CrowdSec.Transport.Type == TypeOpenZiti {
		profiles[cfg.CrowdSec.Transport.Identity] = struct{}{}
	}
	return profiles, nil
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
