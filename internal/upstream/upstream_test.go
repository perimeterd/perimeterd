package upstream

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
)

func TestBindingValidationAndDeclarativeMatching(t *testing.T) {
	generation := strings.Repeat("a", 64)
	zitiBinding := Binding{Type: TypeOpenZiti, Identity: "private", IdentityGeneration: generation, Service: "source"}
	if err := zitiBinding.Validate(); err != nil {
		t.Fatal(err)
	}
	if !zitiBinding.MatchesConfig(config.TransportConfig{Type: TypeOpenZiti, Identity: "private", Service: "source"}) {
		t.Fatal("binding should match its declarative route")
	}
	if zitiBinding.MatchesConfig(config.TransportConfig{Type: TypeOpenZiti, Identity: "private", Service: "other"}) {
		t.Fatal("binding matched a different service")
	}
	if err := (Binding{Type: TypeDirect, Service: "source"}).Validate(); err == nil {
		t.Fatal("direct binding accepted a service")
	}
	if err := (Binding{Type: TypeOpenZiti, Identity: "private", IdentityGeneration: strings.ToUpper(generation), Service: "source"}).Validate(); err == nil {
		t.Fatal("uppercase generation was accepted")
	}
}

func TestLoadCapturesReferencedIdentityAndLeavesUnusedProfilesInert(t *testing.T) {
	dir := t.TempDir()
	identityPath := writeIdentityFile(t, dir)
	cfg := config.Config{
		OpenZiti: config.OpenZitiConfig{Identities: map[string]config.OpenZitiIdentityConfig{
			"private": {IdentityFile: identityPath},
			"unused":  {IdentityFile: filepath.Join(dir, "does-not-exist.json")},
		}},
		IPLists: map[string]config.IPListConfig{
			"private": {Transport: config.TransportConfig{Type: TypeOpenZiti, Identity: "private", Service: "source"}},
		},
		Policies: []config.Policy{{Mode: "enforce", Include: config.Selector{IPLists: []string{"private"}}}},
	}
	manager := NewManager()
	session, err := manager.Load(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := session.Binding(cfg.IPLists["private"].Transport)
	if err != nil {
		t.Fatal(err)
	}
	if err := binding.Validate(); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(identityPath) // #nosec G304 -- helper creates this credential under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	rotated := strings.Replace(string(original), "controller.invalid", "rotated.invalid", 1)
	if err := os.WriteFile(identityPath, []byte(rotated), 0o600); err != nil { // #nosec G703 -- identityPath is created under t.TempDir, not derived from credential content.
		t.Fatal(err)
	}
	rotatedSession, err := manager.Load(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	rotatedBinding, err := rotatedSession.Binding(cfg.IPLists["private"].Transport)
	if err != nil || rotatedBinding == binding {
		t.Fatalf("identity rotation did not create a new generation: %v", err)
	}
	rotatedSession.Close()
	if err := os.WriteFile(identityPath, []byte("not-an-identity"), 0o600); err != nil {
		t.Fatal(err)
	}
	bindingAgain, err := session.Binding(cfg.IPLists["private"].Transport)
	if err != nil || bindingAgain != binding {
		t.Fatalf("captured session reread or changed identity material: %v", err)
	}
	if got := session.Retain(); got == nil {
		t.Fatal("retain returned nil for live session")
	} else {
		got.Close()
	}
	session.Close()
	if err := manager.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestLoadRejectsMismatchedClientKeyBeforeGenerationReuse(t *testing.T) {
	path := writeIdentityFile(t, t.TempDir())
	route := config.TransportConfig{Type: TypeOpenZiti, Identity: "private", Service: "source"}
	cfg := config.Config{
		OpenZiti: config.OpenZitiConfig{Identities: map[string]config.OpenZitiIdentityConfig{
			"private": {IdentityFile: path},
		}},
		IPLists:  map[string]config.IPListConfig{"private": {Transport: route}},
		Policies: []config.Policy{{Mode: "enforce", Include: config.Selector{IPLists: []string{"private"}}}},
	}
	manager := NewManager()
	t.Cleanup(func() {
		if err := manager.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	session, err := manager.Load(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	binding, err := session.Binding(route)
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path) // #nosec G304 -- credential fixture under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	var rotated struct {
		ZtAPI string            `json:"ztAPI"`
		ID    map[string]string `json:"id"`
	}
	if err := json.Unmarshal(original, &rotated); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	rotated.ID["key"] = "pem:" + string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}))
	data, err := json.Marshal(rotated)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil { // #nosec G703 -- fixed credential fixture path, not credential-derived input.
		t.Fatal(err)
	}
	if accepted, err := manager.Load(context.Background(), cfg); err == nil {
		accepted.Close()
		t.Error("reload accepted a mismatched certificate/private key")
	}
	if retained, err := session.Binding(route); err != nil || retained != binding {
		t.Fatalf("rejected rotation changed the captured session: %v", err)
	}
	fresh := NewManager()
	t.Cleanup(func() {
		if err := fresh.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	if accepted, err := fresh.Load(context.Background(), cfg); err == nil {
		accepted.Close()
		t.Error("initial load accepted a mismatched certificate/private key")
	}
}

func TestBoundTransportHonorsCanceledRequestWithoutSDKStartup(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{
		OpenZiti: config.OpenZitiConfig{Identities: map[string]config.OpenZitiIdentityConfig{"private": {IdentityFile: writeIdentityFile(t, dir)}}},
		IPLists:  map[string]config.IPListConfig{"private": {Transport: config.TransportConfig{Type: TypeOpenZiti, Identity: "private", Service: "source"}}},
		Policies: []config.Policy{{Mode: "enforce", Include: config.Selector{IPLists: []string{"private"}}}},
	}
	manager := NewManager()
	session, err := manager.Load(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := session.Transport(cfg.IPLists["private"].Transport, "https://allowed.invalid/list")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://allowed.invalid/list", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = transport.RoundTrip(request)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled request returned unexpected error: %v", err)
	}
	session.Close()
	_ = manager.Close(context.Background())
}

func writeIdentityFile(t *testing.T, dir string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	identityJSON, err := json.Marshal(map[string]any{
		"ztAPI": "https://controller.invalid/edge/client/v1",
		"id": map[string]string{
			"cert": "pem:" + string(cert),
			"key":  "pem:" + string(privateKey),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "identity.json")
	if err := os.WriteFile(path, identityJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestControllerStallDoesNotBlockCallerOrManagerShutdown(t *testing.T) {
	entered := make(chan struct{})
	releaseVersion := make(chan struct{})
	var started, released sync.Once
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/version") {
			started.Do(func() { close(entered) })
			<-releaseVersion
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"version":"v2.0.4","capabilities":[]}}`))
			return
		}
		http.Error(w, "fixture rejects authentication", http.StatusUnauthorized)
	}))
	t.Cleanup(func() {
		released.Do(func() { close(releaseVersion) })
		server.Close()
	})
	path := writeIdentityFile(t, t.TempDir())
	data, err := os.ReadFile(path) // #nosec G304 -- helper creates this credential under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	document["ztAPI"] = server.URL + "/edge/client/v1"
	document["id"].(map[string]any)["ca"] = "pem:" + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	data, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	route := config.TransportConfig{Type: TypeOpenZiti, Identity: "private", Service: "source"}
	cfg := config.Config{
		OpenZiti: config.OpenZitiConfig{Identities: map[string]config.OpenZitiIdentityConfig{"private": {IdentityFile: path}}},
		IPLists:  map[string]config.IPListConfig{"private": {Transport: route}},
		Policies: []config.Policy{{Mode: "enforce", Include: config.Selector{IPLists: []string{"private"}}}},
	}
	manager := NewManager()
	session, err := manager.Load(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		session.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = manager.Close(ctx)
	})
	transport, err := session.Transport(route, "http://private.invalid/feed")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://private.invalid/feed", nil)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		response, err := transport.RoundTrip(request)
		if response != nil {
			_ = response.Body.Close()
		}
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("SDK never contacted the stalled controller")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled request returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SDK authentication blocked caller cancellation")
	}
	session.Close()
	shutdown, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	if err := manager.Close(shutdown); err != nil {
		t.Fatalf("SDK authentication blocked manager shutdown: %v", err)
	}
	// Let the unmodified SDK finish its otherwise uncancelable discovery and
	// fail authentication. Do not leave a permanent discovery loop in the suite.
	released.Do(func() { close(releaseVersion) })
	for len(manager.dials) != 0 {
		select {
		case <-time.After(time.Millisecond):
		case <-shutdown.Done():
			t.Fatal("fixture SDK authentication did not drain after controller release")
		}
	}
}

func TestSDKWireDebugIsRejectedOnlyForActiveProfiles(t *testing.T) {
	path := writeIdentityFile(t, t.TempDir())
	cfg := config.Config{
		OpenZiti: config.OpenZitiConfig{Identities: map[string]config.OpenZitiIdentityConfig{"private": {IdentityFile: path}}},
		IPLists: map[string]config.IPListConfig{
			"private": {Transport: config.TransportConfig{Type: TypeOpenZiti, Identity: "private", Service: "source"}},
		},
	}
	t.Setenv("SWAGGER_DEBUG", "1")
	manager := NewManager()
	session, err := manager.Load(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unused SDK profile changed direct-only behavior: %v", err)
	}
	session.Close()
	cfg.Policies = []config.Policy{{Mode: "blocklist", Include: config.Selector{IPLists: []string{"private"}}}}
	if session, err := manager.Load(context.Background(), cfg); err == nil {
		session.Close()
		t.Fatal("active SDK profile accepted secret-bearing wire diagnostics")
	}
	_ = manager.Close(context.Background())
}
