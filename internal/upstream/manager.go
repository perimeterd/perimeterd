package upstream

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/go-openapi/runtime/logger"
	"github.com/openziti/sdk-golang/ziti"
	"github.com/sirupsen/logrus"

	"github.com/perimeterd/perimeterd/internal/config"
)

const (
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

// NewManager creates an empty manager. Direct-only callers may keep one for
// their whole process without causing any filesystem or SDK activity.
func NewManager() *Manager {
	return &Manager{
		generations: make(map[Binding]*generation),
		live:        make(map[*generation]struct{}),
		dials:       make(chan struct{}, maxSDKDials),
	}
}

// Load captures exactly the supplied identities. It validates and embeds all
// credential PEM material but does not authenticate or contact a controller.
func (m *Manager) Load(ctx context.Context, profiles map[string]config.OpenZitiIdentityConfig) (*Session, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
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
		loaded, err := captureIdentity(profile, profiles[profile].IdentityFile)
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
