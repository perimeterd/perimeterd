//go:build linux && e2e

package e2e

import (
	"archive/tar"
	"bytes"
	"context"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	dockerTestBindirEnv = "DOCKER_TEST_BINDIR"
	dockerProbeEnv      = "PERIMETERD_DOCKER_PROBE"
	dockerProbeReady    = "PERIMETERD_DOCKER_PROBE_READY"
	dockerBridgeName    = "pmd-e2e-br0"
	dockerNetworkName   = "pmd-e2e-net"
	dockerContainerName = "pmd-e2e-echo"
	dockerImageName     = "pmd-e2e-probe:latest"
)

type dockerTools struct {
	docker      string
	dockerd     string
	containerd  string
	runc        string
	dockerProxy string
	env         []string
}

type dockerDaemonProcess struct {
	cmd    *exec.Cmd
	output *lockedBuffer
	done   chan struct{}
	mu     struct {
		sync.Mutex
		err error
	}
}

// dockerFixture owns a private Docker daemon and a peer namespace connected to
// the harness' e2h0 interface. The daemon is deliberately not configured to
// use any host Docker socket, configuration, state, or storage.
type dockerFixture struct {
	peer *peerNamespace

	dockerPath   string
	socketPath   string
	dataRoot     string
	execRoot     string
	pidFile      string
	configPath   string
	cgroupParent string

	networkName   string
	bridgeName    string
	containerName string
	imageName     string

	clientEnv []string
	daemon    *dockerDaemonProcess
}

// newDockerFixture starts a real Docker Engine, imports the current static
// test binary as a scratch image, creates a deterministic dual-stack bridge,
// and starts a packet-path TCP echo container with userland-proxy disabled.
func newDockerFixture(t *testing.T) *dockerFixture {
	t.Helper()
	requireIsolatedChild(t)

	peer := newPeerNamespace(t)
	root := t.TempDir()
	dataRoot := filepath.Join(root, "data")
	execRoot := filepath.Join(root, "exec")
	if err := os.MkdirAll(dataRoot, 0o700); err != nil {
		t.Fatalf("create Docker data root: %v", err)
	}
	if err := os.MkdirAll(execRoot, 0o700); err != nil {
		t.Fatalf("create Docker exec root: %v", err)
	}
	clientConfigDir := filepath.Join(root, "docker-config")
	if err := os.MkdirAll(clientConfigDir, 0o700); err != nil {
		t.Fatalf("create Docker client config directory: %v", err)
	}
	cgroupPath, err := os.MkdirTemp("/sys/fs/cgroup", "perimeterd-e2e-")
	if err != nil {
		t.Fatalf("Docker gate requires a writable cgroup hierarchy: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Remove(cgroupPath); err != nil {
			t.Errorf("remove private Docker cgroup: %v", err)
		}
	})

	tools := resolveDockerTools(t, root)
	probeBinary := currentTestBinary(t)
	socketPath := filepath.Join(root, "docker.sock")
	fixture := &dockerFixture{
		peer:          peer,
		dockerPath:    tools.docker,
		socketPath:    socketPath,
		dataRoot:      dataRoot,
		execRoot:      execRoot,
		pidFile:       filepath.Join(root, "dockerd.pid"),
		configPath:    filepath.Join(root, "daemon.json"),
		cgroupParent:  "/" + filepath.Base(cgroupPath),
		networkName:   dockerNetworkName,
		bridgeName:    dockerBridgeName,
		containerName: dockerContainerName,
		imageName:     dockerImageName,
	}
	fixture.clientEnv = tools.env
	fixture.clientEnv = setEnvironment(fixture.clientEnv, "DOCKER_HOST", "unix://"+socketPath)
	fixture.clientEnv = setEnvironment(fixture.clientEnv, "DOCKER_CONFIG", clientConfigDir)
	fixture.clientEnv = setEnvironment(fixture.clientEnv, "HOME", filepath.Join(root, "home"))
	fixture.clientEnv = setEnvironment(fixture.clientEnv, "XDG_CONFIG_HOME", filepath.Join(root, "xdg"))
	if err := os.MkdirAll(filepath.Join(root, "home"), 0o700); err != nil {
		t.Fatalf("create Docker home: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "xdg"), 0o700); err != nil {
		t.Fatalf("create Docker XDG config directory: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "runtime"), 0o700); err != nil {
		t.Fatalf("create private Docker runtime directory: %v", err)
	}

	writeDockerEngineConfig(t, fixture)
	requireStaticProbe(t, probeBinary)
	logDockerToolVersions(t, tools)
	fixture.daemon = startDockerEngine(t, fixture, tools)
	t.Cleanup(func() { fixture.stop(t) })
	fixture.waitDaemon(t)
	fixture.importProbeImage(t, probeBinary)
	fixture.createNetwork(t)
	fixture.startEchoContainer(t)
	return fixture
}

func currentTestBinary(t *testing.T) string {
	t.Helper()
	binary, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatalf("resolve current E2E test binary: %v", err)
	}
	if _, err := exec.LookPath(binary); err != nil {
		t.Fatalf("current E2E test binary is not executable: %v", err)
	}
	return binary
}

func resolveDockerTools(t *testing.T, root string) dockerTools {
	t.Helper()
	bindir := os.Getenv(dockerTestBindirEnv)
	if bindir != "" {
		var err error
		bindir, err = filepath.Abs(bindir)
		if err != nil {
			t.Fatalf("resolve Docker tool directory: %v", err)
		}
	}
	originalPath := os.Getenv("PATH")
	if originalPath == "" {
		t.Fatal("PATH is empty; cannot locate Docker tools")
	}

	lookup := func(name string, required bool) string {
		var path string
		if bindir != "" {
			path = filepath.Join(bindir, name)
		} else {
			var err error
			path, err = exec.LookPath(name)
			if err != nil {
				if required {
					t.Fatalf("required Docker tool %q is unavailable: %v", name, err)
				}
				return ""
			}
		}
		// #nosec G703 -- the operator selects trusted local Docker test binaries, never remote input.
		info, err := os.Stat(path)
		if err != nil {
			if required {
				t.Fatalf("required Docker tool %q is unavailable at %s: %v", name, path, err)
			}
			return ""
		}
		if info.Mode()&0o111 == 0 {
			t.Fatalf("Docker tool %q is not executable: %s", name, path)
		}
		return path
	}

	docker := lookup("docker", true)
	dockerd := lookup("dockerd", true)
	containerd := lookup("containerd", true)
	runc := lookup("runc", true)
	dockerProxy := lookup("docker-proxy", bindir != "")

	runtimeDir := filepath.Join(root, "docker-bin")
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		t.Fatalf("create Docker runtime PATH: %v", err)
	}
	link := func(name, target string) {
		if target == "" {
			return
		}
		if err := os.Symlink(target, filepath.Join(runtimeDir, name)); err != nil {
			t.Fatalf("link Docker tool %s: %v", name, err)
		}
	}
	link("docker", docker)
	link("dockerd", dockerd)
	link("containerd", containerd)
	link("runc", runc)
	link("docker-proxy", dockerProxy)

	// installIPTablesTools prepends its wrappers to PATH. Preserve those exact
	// wrappers ahead of Docker's static tool directory so dockerd creates rules
	// through the selected iptables family rather than the host default.
	for _, name := range []string{
		"iptables", "ip6tables", "iptables-save", "ip6tables-save",
		"iptables-restore", "ip6tables-restore", "ipset",
	} {
		path, err := exec.LookPath(name)
		if err == nil {
			link(name, path)
		}
	}
	env := sanitizedEnvironment(os.Environ())
	runtimePath := runtimeDir + string(os.PathListSeparator)
	toolDir := bindir
	if toolDir == "" {
		toolDir = filepath.Dir(dockerd)
	}
	runtimePath += toolDir + string(os.PathListSeparator) + originalPath
	env = setEnvironment(env, "PATH", runtimePath)
	env = setEnvironment(env, "HOME", filepath.Join(root, "home"))
	env = setEnvironment(env, "DOCKER_CONFIG", filepath.Join(root, "docker-config"))
	env = setEnvironment(env, "XDG_CONFIG_HOME", filepath.Join(root, "xdg"))
	env = setEnvironment(env, "XDG_RUNTIME_DIR", filepath.Join(root, "runtime"))
	return dockerTools{
		docker:      filepath.Join(runtimeDir, "docker"),
		dockerd:     filepath.Join(runtimeDir, "dockerd"),
		containerd:  filepath.Join(runtimeDir, "containerd"),
		runc:        filepath.Join(runtimeDir, "runc"),
		dockerProxy: filepath.Join(runtimeDir, "docker-proxy"),
		env:         env,
	}
}

func sanitizedEnvironment(base []string) []string {
	out := make([]string, 0, len(base))
	for _, value := range base {
		key, _, _ := strings.Cut(value, "=")
		switch {
		case strings.HasPrefix(key, "DOCKER_"):
			continue
		case key == "CONTAINER_HOST", key == "BUILDKIT_HOST":
			continue
		case strings.HasPrefix(key, "PODMAN_"):
			continue
		}
		out = append(out, value)
	}
	return out
}

func setEnvironment(env []string, key, value string) []string {
	out := env[:0]
	prefix := key + "="
	for _, item := range env {
		if !strings.HasPrefix(item, prefix) {
			out = append(out, item)
		}
	}
	return append(out, prefix+value)
}

func writeDockerEngineConfig(t *testing.T, fixture *dockerFixture) {
	t.Helper()
	config := map[string]any{
		"data-root":        fixture.dataRoot,
		"exec-root":        fixture.execRoot,
		"pidfile":          fixture.pidFile,
		"iptables":         true,
		"ip6tables":        true,
		"firewall-backend": "iptables",
		"storage-driver":   "vfs",
		"bridge":           "none",
		"userland-proxy":   false,
		"ip-forward":       true,
		"ip-masq":          true,
		"live-restore":     false,
		"log-level":        "info",
		"exec-opts":        []string{"native.cgroupdriver=cgroupfs"},
		"cgroup-parent":    fixture.cgroupParent,
		"features":         map[string]bool{"containerd-snapshotter": false},
		"default-address-pools": []map[string]any{{
			"base": "172.31.0.0/16", "size": 24,
		}},
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatalf("marshal Docker daemon config: %v", err)
	}
	if err := os.WriteFile(fixture.configPath, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("write Docker daemon config: %v", err)
	}
}

func logDockerToolVersions(t *testing.T, tools dockerTools) {
	t.Helper()
	for name, path := range map[string]string{
		"docker": tools.docker, "dockerd": tools.dockerd,
		"containerd": tools.containerd, "runc": tools.runc,
	} {
		output, err := runProgram(5*time.Second, tools.env, path, "--version")
		if err != nil {
			t.Fatalf("%s --version failed: %v\n%s", name, err, output)
		}
		lower := strings.ToLower(string(output))
		if (name == "docker" || name == "dockerd") &&
			(!strings.Contains(lower, "docker") || strings.Contains(lower, "podman")) {
			t.Fatalf("%s is not the Docker implementation: %s", name, strings.TrimSpace(string(output)))
		}
		t.Logf("%s: %s", name, strings.TrimSpace(string(output)))
	}
	if tools.dockerProxy != "" {
		output, err := runProgram(5*time.Second, tools.env, tools.dockerProxy, "--version")
		if err != nil {
			t.Logf("docker-proxy --version unavailable: %v (%s)", err, strings.TrimSpace(string(output)))
		} else {
			t.Logf("docker-proxy: %s", strings.TrimSpace(string(output)))
		}
	}
}

func requireStaticProbe(t *testing.T, binary string) {
	t.Helper()
	image, err := elf.Open(binary)
	if err != nil {
		t.Fatalf("inspect E2E probe ELF: %v", err)
	}
	defer func() { _ = image.Close() }()
	for _, program := range image.Progs {
		if program.Type == elf.PT_INTERP {
			t.Fatalf("E2E probe binary is dynamically linked (interpreter %q)", binary)
		}
	}
}

// Docker 29.8 loads docker-default at daemon startup. Network/PID namespaces do
// not isolate AppArmor policy, so hide securityfs before any Docker process can
// load host profiles. Docker, containerd, and runc detect AppArmor through
// /sys/kernel/security/apparmor. Keep this mount until the namespace exits.
func isolateDockerSecurityFS(t *testing.T) {
	t.Helper()
	requireIsolatedChild(t)
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		t.Fatalf("make Docker security mount private: %v", err)
	}
	if err := syscall.Mount("tmpfs", "/sys/kernel/security", "tmpfs",
		syscall.MS_RDONLY|syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC,
		"mode=0555,size=4k"); err != nil {
		t.Fatalf("hide host securityfs from Docker: %v", err)
	}
}

// This regression uses a private stand-in for securityfs, never real AppArmor
// policy. It exercises the isolation boundary even on hosts without AppArmor.
func TestE2EDockerSecurityIsolation(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		t.Logf("%s", runIsolated(t, "TestE2EDockerSecurityIsolation", "securityfs"))
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	// prepareMounts makes /run private tmpfs; the bind mount and its backing
	// disappear together at namespace exit, without unlinking a mounted inode.
	const backing = "/run/docker-securityfs"
	if err := os.MkdirAll(filepath.Join(backing, "apparmor"), 0o700); err != nil {
		t.Fatal(err)
	}
	const profile = "existing-host-profile (enforce)\n"
	const profiles = backing + "/apparmor/profiles"
	if err := os.WriteFile(profiles, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mount(backing, "/sys/kernel/security", "", syscall.MS_BIND, ""); err != nil {
		t.Fatalf("mount private securityfs stand-in: %v", err)
	}
	visible, err := os.ReadFile("/sys/kernel/security/apparmor/profiles")
	if err != nil || string(visible) != profile {
		t.Fatalf("securityfs stand-in is not visible: %q, %v", visible, err)
	}

	isolateDockerSecurityFS(t)

	if _, err := os.Stat("/sys/kernel/security/apparmor"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("AppArmor policy interface remains accessible: %v", err)
	}
	if err := os.Mkdir("/sys/kernel/security/apparmor", 0o700); !errors.Is(err, syscall.EROFS) {
		t.Fatalf("masked securityfs is not read-only: %v", err)
	}
	unchanged, err := os.ReadFile(profiles)
	if err != nil || string(unchanged) != profile {
		t.Fatalf("underlying policy was changed: %q, %v", unchanged, err)
	}
}

func startDockerEngine(t *testing.T, fixture *dockerFixture, tools dockerTools) *dockerDaemonProcess {
	t.Helper()
	isolateDockerSecurityFS(t)
	output := new(lockedBuffer)
	args := []string{
		"--config-file=" + fixture.configPath,
		"--host=unix://" + fixture.socketPath,
	}
	// #nosec G204 -- the selected Docker binary runs only after namespace isolation with fixture-owned config/socket paths.
	cmd := exec.Command(tools.dockerd, args...)
	cmd.Env = tools.env
	cmd.Stdout = output
	cmd.Stderr = output
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start private Docker daemon: %v", err)
	}
	d := &dockerDaemonProcess{cmd: cmd, output: output, done: make(chan struct{})}
	go func() {
		err := cmd.Wait()
		d.mu.Lock()
		d.mu.err = err
		d.mu.Unlock()
		close(d.done)
	}()
	return d
}

func (f *dockerFixture) waitDaemon(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var last []byte
	var lastErr error
	for time.Now().Before(deadline) {
		last, lastErr = f.tryCommand(3*time.Second, "version")
		if lastErr == nil {
			lower := strings.ToLower(string(last))
			if strings.Contains(lower, "podman") || !strings.Contains(lower, "server:") || !strings.Contains(lower, "docker") {
				t.Fatalf("Docker CLI is not connected to a Docker Engine:\n%s\ndaemon log:\n%s", last, f.daemon.output.String())
			}
			info, err := f.tryCommand(5*time.Second, "info", "--format", "{{json .}}")
			if err == nil {
				var status struct {
					Driver          string
					SecurityOptions []string
				}
				if err := json.Unmarshal(info, &status); err != nil {
					t.Fatalf("decode private Docker info: %v\n%s", err, info)
				}
				if status.Driver != "vfs" {
					t.Fatalf("private Docker daemon did not select vfs storage:\n%s\ndaemon log:\n%s", info, f.daemon.output.String())
				}
				for _, option := range status.SecurityOptions {
					if option == "name=apparmor" || strings.HasPrefix(option, "name=apparmor,") {
						t.Fatal("private Docker daemon can still access host AppArmor")
					}
				}
				t.Logf("Docker Engine: %s", strings.TrimSpace(string(last)))
				return
			}
			lastErr = err
		}
		select {
		case <-f.daemon.done:
			t.Fatalf("private Docker daemon exited during startup: %v\n%s", f.daemon.waitErr(), f.daemon.output.String())
		default:
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("private Docker daemon did not become ready: %v\n%s\ndaemon log:\n%s", lastErr, last, f.daemon.output.String())
}

func (f *dockerFixture) importProbeImage(t *testing.T, binary string) {
	t.Helper()
	tarPath := filepath.Join(filepath.Dir(f.configPath), "probe.tar")
	writeProbeTar(t, tarPath, binary)
	f.command(t, "import", "--change", `ENTRYPOINT ["/probe"]`, tarPath, f.imageName)
}

func writeProbeTar(t *testing.T, tarPath, binary string) {
	t.Helper()
	// #nosec G304 -- binary is this running, statically linked test executable.
	source, err := os.Open(binary)
	if err != nil {
		t.Fatalf("open E2E probe binary: %v", err)
	}
	defer func() { _ = source.Close() }()
	info, err := source.Stat()
	if err != nil {
		t.Fatalf("stat E2E probe binary: %v", err)
	}
	// #nosec G304 -- tarPath is inside the fixture's private t.TempDir.
	archive, err := os.Create(tarPath)
	if err != nil {
		t.Fatalf("create probe image tar: %v", err)
	}
	writer := tar.NewWriter(archive)
	header := &tar.Header{Name: "probe", Mode: 0o755, Size: info.Size(), Typeflag: tar.TypeReg}
	if err := writer.WriteHeader(header); err != nil {
		_ = archive.Close()
		t.Fatalf("write probe image header: %v", err)
	}
	if _, err := io.Copy(writer, source); err != nil {
		_ = archive.Close()
		t.Fatalf("write probe image binary: %v", err)
	}
	if err := writer.Close(); err != nil {
		_ = archive.Close()
		t.Fatalf("close probe image tar: %v", err)
	}
	if err := archive.Close(); err != nil {
		t.Fatalf("close probe image archive: %v", err)
	}
}

func (f *dockerFixture) createNetwork(t *testing.T) {
	t.Helper()
	// Private/ULA sources always bypass perimeterd denials through its built-in
	// allowlist. Use globally classified addresses only in this isolated network
	// so the egress assertion detects an incorrectly broadened ingress attachment.
	f.command(t, "network", "create",
		"--driver", "bridge",
		"--ipv6",
		"--subnet", "8.24.0.0/24",
		"--gateway", "8.24.0.1",
		"--subnet", "2600:24::/64",
		"--gateway", "2600:24::1",
		"--opt", "com.docker.network.bridge.name="+f.bridgeName,
		"--opt", "com.docker.network.bridge.enable_ip_masquerade=true",
		"--opt", "com.docker.network.enable_icc=true",
		f.networkName,
	)
	f.peer.run(t, "ip", "route", "add", "8.24.0.0/24", "via", fixtureIPv4Host)
	f.peer.run(t, "ip", "-6", "route", "add", "2600:24::/64", "via", fixtureIPv6Host)
}

func (f *dockerFixture) startEchoContainer(t *testing.T) {
	t.Helper()
	f.command(t, "run", "--detach", "--name", f.containerName,
		"--network", f.networkName,
		"--publish", fmt.Sprintf("%s:18080:8080/tcp", fixtureIPv4Host),
		"--publish", fmt.Sprintf("%s:18081:8080/tcp", fixtureIPv4Host),
		"--publish", fmt.Sprintf("[%s]:18080:8080/tcp", fixtureIPv6Host),
		"--publish", fmt.Sprintf("[%s]:18081:8080/tcp", fixtureIPv6Host),
		"--env", e2eEnabledEnv+"=1",
		"--env", e2eChildEnv+"=1",
		"--env", dockerProbeEnv+"=1",
		"--entrypoint", "/probe",
		f.imageName,
		"-test.run", "^TestE2EDockerProbe$",
	)

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		state, stateErr := f.tryCommand(3*time.Second, "inspect", "--format", "{{.State.Running}}", f.containerName)
		logs, logErr := f.tryCommand(3*time.Second, "logs", f.containerName)
		if stateErr == nil && strings.TrimSpace(string(state)) == "true" && logErr == nil && strings.Contains(string(logs), dockerProbeReady) {
			return
		}
		if stateErr == nil && strings.TrimSpace(string(state)) != "true" && strings.TrimSpace(string(state)) != "" {
			t.Fatalf("Docker echo container exited before readiness (state %s):\n%s\ndaemon log:\n%s", strings.TrimSpace(string(state)), logs, f.daemon.output.String())
		}
		select {
		case <-f.daemon.done:
			t.Fatalf("Docker daemon exited while starting echo container: %v\n%s", f.daemon.waitErr(), f.daemon.output.String())
		default:
		}
		time.Sleep(200 * time.Millisecond)
	}
	logs, _ := f.tryCommand(3*time.Second, "logs", f.containerName)
	t.Fatalf("Docker echo container did not become ready:\n%s\ndaemon log:\n%s", logs, f.daemon.output.String())
}

func (f *dockerFixture) command(t *testing.T, args ...string) []byte {
	t.Helper()
	output, err := f.tryCommand(60*time.Second, args...)
	if err != nil {
		t.Fatalf("docker %s failed: %v\n%s\ndaemon log:\n%s", strings.Join(args, " "), err, output, f.daemon.output.String())
	}
	return output
}

func (f *dockerFixture) tryCommand(timeout time.Duration, args ...string) ([]byte, error) {
	return runProgram(timeout, f.clientEnv, f.dockerPath, args...)
}

func (f *dockerFixture) peerProbe(t *testing.T, network, address, expectation string) {
	t.Helper()
	mode := "dial-tcp"
	if strings.HasPrefix(network, "udp") {
		mode = "dial-udp"
	}
	cmd := f.peer.helper(t, mode, network, address, expectation)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start Docker peer probe: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Docker peer probe %s %s (%s): %v\n%s", network, address, expectation, err, output.String())
		}
	case <-time.After(10 * time.Second):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-done
		t.Fatalf("Docker peer probe timed out for %s %s (%s)\n%s", network, address, expectation, output.String())
	}
}

func (f *dockerFixture) containerProbe(t *testing.T, network, address, expectation string) {
	t.Helper()
	mode := "dial-tcp"
	if strings.HasPrefix(network, "udp") {
		mode = "dial-udp"
	}
	output, err := f.tryCommand(20*time.Second,
		"exec", "--env", e2eEnabledEnv+"=1",
		"--env", e2eChildEnv+"=1",
		"--env", "PERIMETERD_E2E_PEER_MODE="+mode,
		"--env", "PERIMETERD_E2E_PEER_NETWORK="+network,
		"--env", "PERIMETERD_E2E_PEER_ADDRESS="+address,
		"--env", "PERIMETERD_E2E_PEER_EXPECT="+expectation,
		f.containerName, "/probe", "-test.run", "^TestE2EPeer$",
	)
	if err != nil {
		t.Fatalf("Docker container probe %s %s (%s): %v\n%s\ndaemon log:\n%s", network, address, expectation, err, output, f.daemon.output.String())
	}
}

func (f *dockerFixture) stop(t *testing.T) {
	t.Helper()
	if f.daemon == nil {
		return
	}
	select {
	case <-f.daemon.done:
		return
	default:
	}
	// Remove the container before stopping dockerd so no child remains after
	// the daemon exits. This command is intentionally best-effort during cleanup.
	_, _ = f.tryCommand(15*time.Second, "rm", "--force", f.containerName)
	if f.daemon.cmd.Process == nil {
		return
	}
	if err := f.daemon.cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		t.Logf("signal private Docker daemon: %v", err)
	}
	select {
	case <-f.daemon.done:
		return
	case <-time.After(20 * time.Second):
	}
	// This process group belongs only to the fixture. Kill it as a unit so a
	// stuck dockerd cannot leave its managed containerd process behind.
	_ = syscall.Kill(-f.daemon.cmd.Process.Pid, syscall.SIGKILL)
	select {
	case <-f.daemon.done:
	case <-time.After(5 * time.Second):
		t.Errorf("private Docker daemon did not terminate; output:\n%s", f.daemon.output.String())
	}
}

func (d *dockerDaemonProcess) waitErr() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.mu.err
}

func runProgram(timeout time.Duration, env []string, path string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// #nosec G204 -- bounded execution of the operator-selected Docker toolset with fixture-controlled arguments.
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return output, ctx.Err()
	}
	return output, err
}

// TestE2EDockerProbe is the scratch-image process used by dockerFixture. A
// single process opens both protocol families so published Docker ingress is
// tested by packets, not a userland proxy. It intentionally blocks until the
// container is stopped.
func TestE2EDockerProbe(t *testing.T) {
	if os.Getenv(dockerProbeEnv) != "1" {
		return
	}
	// #nosec G102 -- listens only inside the scratch container's isolated network namespace.
	v4, err := net.Listen("tcp4", ":8080")
	if err != nil {
		t.Fatalf("Docker probe IPv4 listen: %v", err)
	}
	// #nosec G102 -- IPv6 listener shares the scratch container's isolated network namespace.
	v6, err := net.Listen("tcp6", ":8080")
	if err != nil {
		_ = v4.Close()
		t.Fatalf("Docker probe IPv6 listen: %v", err)
	}
	go echoTCP(v4)
	go echoTCP(v6)
	fmt.Println(dockerProbeReady)
	select {}
}
