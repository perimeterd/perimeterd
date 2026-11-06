//go:build linux && e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	e2ePhasePrefix     = "PERIMETERD_E2E_PHASE "
	e2ePhaseDirEnv     = "PERIMETERD_E2E_PHASE_DIR"
	e2ePhaseLineLimit  = 4096
	e2eDiagnosticLimit = 64 * 1024
)

type e2ePhaseRecord struct {
	Backend              string    `json:"backend,omitempty"`
	Scenario             string    `json:"scenario,omitempty"`
	Profile              string    `json:"profile,omitempty"`
	Phase                string    `json:"phase,omitempty"`
	Event                string    `json:"event,omitempty"`
	Outcome              string    `json:"outcome,omitempty"`
	Resource             string    `json:"resource,omitempty"`
	CapacityScope        string    `json:"capacity_scope,omitempty"`
	RequiredBytes        int64     `json:"required_bytes,omitempty"`
	LimitBytes           int64     `json:"limit_bytes,omitempty"`
	StaticMemberships    int       `json:"static_memberships,omitempty"`
	SourceDecisions      int       `json:"source_decisions,omitempty"`
	ProjectedMemberships int       `json:"projected_memberships,omitempty"`
	StaticGeneration     string    `json:"static_generation,omitempty"`
	DynamicGeneration    string    `json:"dynamic_generation,omitempty"`
	StaticGenerations    int       `json:"static_generations,omitempty"`
	DynamicGenerations   int       `json:"dynamic_generations,omitempty"`
	CaptureCommands      int       `json:"capture_commands,omitempty"`
	CaptureBytes         int64     `json:"capture_bytes,omitempty"`
	DurationNS           int64     `json:"duration_ns,omitempty"`
	WallNS               int64     `json:"wall_ns,omitempty"`
	ChildUserNS          int64     `json:"child_user_ns,omitempty"`
	ChildSystemNS        int64     `json:"child_system_ns,omitempty"`
	ChildMaxRSSKiB       int64     `json:"child_max_rss_kib,omitempty"`
	DaemonMaxRSSKiB      int64     `json:"daemon_max_rss_kib,omitempty"`
	Timestamp            time.Time `json:"timestamp"`
}

// Labels are identifiers, never free-form messages or native command output.
func validE2EPhase(record e2ePhaseRecord) bool {
	for _, label := range []string{record.Backend, record.Scenario, record.Profile, record.Phase, record.Event, record.Outcome, record.StaticGeneration, record.DynamicGeneration, record.Resource, record.CapacityScope} {
		if len(label) > 128 {
			return false
		}
		for _, c := range label {
			letter := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
			digit := c >= '0' && c <= '9'
			if !letter && !digit && !strings.ContainsRune("_-./", c) {
				return false
			}
		}
	}
	for _, count := range []int{record.StaticMemberships, record.SourceDecisions, record.ProjectedMemberships, record.StaticGenerations, record.DynamicGenerations, record.CaptureCommands} {
		if count < 0 {
			return false
		}
	}
	for _, count := range []int64{record.CaptureBytes, record.DurationNS, record.WallNS, record.ChildUserNS, record.ChildSystemNS, record.ChildMaxRSSKiB, record.DaemonMaxRSSKiB, record.RequiredBytes, record.LimitBytes} {
		if count < 0 {
			return false
		}
	}
	return record.Event != "" && !record.Timestamp.IsZero()
}

func recordE2EPhase(t *testing.T, record e2ePhaseRecord) {
	t.Helper()
	if record.Timestamp.IsZero() {
		record.Timestamp = time.Now().UTC()
	}
	if record.Scenario == "" {
		record.Scenario = t.Name()
		if scenario := os.Getenv(e2eScenario); scenario != "" {
			record.Scenario += "/" + scenario
		}
	}
	if !validE2EPhase(record) {
		t.Error("invalid E2E phase record (only bounded identifier labels and nonnegative measurements are allowed)")
		return
	}
	if os.Getenv(e2eChildEnv) == "1" {
		data, _ := json.Marshal(record)
		// Unlike t.Log, this reaches the namespace runner before the test exits.
		if _, err := fmt.Fprintln(os.Stdout, e2ePhasePrefix+string(data)); err != nil {
			t.Errorf("emit phase progress: %v", err)
		}
		return
	}
	emitE2EPhase(record)
}

var e2ePhaseMu sync.Mutex

// Only this typed, validated record is streamed or written to artifacts. Raw
// nested Go control lines, native payloads and diagnostics never enter artifacts.
func emitE2EPhase(record e2ePhaseRecord) {
	e2ePhaseMu.Lock()
	defer e2ePhaseMu.Unlock()
	data, _ := json.Marshal(record)
	_, _ = fmt.Fprintln(os.Stdout, e2ePhasePrefix+string(data))
	dir := os.Getenv(e2ePhaseDirEnv)
	if dir == "" {
		return
	}
	if err := persistE2EPhase(dir, data); err != nil {
		// Artifact failure must not overwrite the primary namespace result, and
		// paths/errors may contain private workspace details.
		fmt.Fprintln(os.Stderr, "PERIMETERD_E2E_PROGRESS phase artifact write failed")
	}
}

func persistE2EPhase(dir string, data []byte) error {
	// #nosec G301 G703 -- operator-selected metadata-only output directory, never derived from native/source payloads; CI's uploader needs traversal after sudo.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// sudo may inherit a restrictive umask; CI's unprivileged uploader must
	// still be able to traverse this phase-only artifact directory.
	// #nosec G302 G703 -- operator-selected directory contains only validated phase metadata and must remain readable after sudo.
	if err := os.Chmod(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, fmt.Sprintf("phases-%d.jsonl", os.Getpid()))
	// #nosec G302 G304 G703 -- fixed PID filename beneath the operator-selected metadata directory; NOFOLLOW rejects file symlinks.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return err
	}
	if err := file.Chmod(0o644); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(append(data, '\n')); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

// e2eChildOutput serializes both streams. The spool preserves every semantic
// byte independently of the bounded diagnostic tail and bounded line parser.
// Separate line assemblers prevent stderr fragments from becoming stdout records.
type e2eChildOutput struct {
	mu       sync.Mutex
	spool    *os.File
	tail     []byte
	lines    [2][]byte
	dropping [2]bool
	progress func(e2ePhaseRecord)
}

type e2eChildStream struct {
	output *e2eChildOutput
	stream int
}

func (stream e2eChildStream) Write(data []byte) (int, error) {
	output := stream.output
	output.mu.Lock()
	defer output.mu.Unlock()
	n, err := output.spool.Write(data)
	if err != nil {
		return n, err
	}
	if len(data) >= e2eDiagnosticLimit {
		output.tail = append(output.tail[:0], data[len(data)-e2eDiagnosticLimit:]...)
	} else {
		excess := len(output.tail) + len(data) - e2eDiagnosticLimit
		if excess > 0 {
			copy(output.tail, output.tail[excess:])
			output.tail = output.tail[:len(output.tail)-excess]
		}
		output.tail = append(output.tail, data...)
	}
	for _, c := range data {
		if c == '\n' {
			if !output.dropping[stream.stream] {
				output.parseLine(output.lines[stream.stream])
			}
			output.lines[stream.stream] = output.lines[stream.stream][:0]
			output.dropping[stream.stream] = false
		} else if !output.dropping[stream.stream] {
			if len(output.lines[stream.stream]) == e2ePhaseLineLimit {
				output.lines[stream.stream] = output.lines[stream.stream][:0]
				output.dropping[stream.stream] = true
			} else {
				output.lines[stream.stream] = append(output.lines[stream.stream], c)
			}
		}
	}
	return n, nil
}

func (output *e2eChildOutput) parseLine(line []byte) {
	if !bytes.HasPrefix(line, []byte(e2ePhasePrefix)) {
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(line[len(e2ePhasePrefix):]))
	decoder.DisallowUnknownFields()
	var record e2ePhaseRecord
	if decoder.Decode(&record) != nil || !validE2EPhase(record) {
		return
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return
	}
	if output.progress != nil {
		output.progress(record)
	}
}

func (output *e2eChildOutput) evidence() ([]byte, error) {
	if _, err := output.spool.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	return io.ReadAll(output.spool)
}
