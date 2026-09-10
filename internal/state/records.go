// Package state owns the durable revision, journal, and lifecycle records used by the runtime.
package state

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/firewall"
	"github.com/perimeterd/perimeterd/internal/policy"
)

const (
	recordVersion  = 1
	idLength       = 32
	maxRecordBytes = 16 << 20
	stateDirMode   = 0o700
	recordFileMode = 0o600
)

// Revision is an immutable, validated desired firewall revision.
type Revision struct {
	Version    int              `json:"version"`
	ID         string           `json:"id"`
	Epoch      uint64           `json:"epoch"`
	ConfigPath string           `json:"config_path"`
	Config     config.Config    `json:"config"`
	Target     *firewall.Target `json:"target"`
}

// Journal describes an in-flight apply or explicit cleanup operation.
type Journal struct {
	Version   int      `json:"version"`
	ID        string   `json:"id"`
	Operation string   `json:"operation"`
	Phase     string   `json:"phase"`
	Previous  string   `json:"previous"`
	Candidate string   `json:"candidate"`
	Revisions []string `json:"revisions"`
}

// View is a consistent snapshot of all durable records referenced by active or journal state.
type View struct {
	Owner     string
	Active    *Revision
	Journal   *Journal
	Revisions map[string]*Revision
}

type envelope struct {
	Version  int             `json:"version"`
	Checksum string          `json:"checksum"`
	Payload  json.RawMessage `json:"payload"`
}

type ownerRecord struct {
	Owner string `json:"owner"`
}

type activeRecord struct {
	ID string `json:"id"`
}

// Store manages durable ownership, revision, active, and journal records.
type Store struct {
	dir        string
	revisions  string
	owner      string
	checkpoint func(string) error
}

// Open opens or initializes a durable state directory. The caller must hold the lifecycle lock.
func Open(dir string, checkpoint func(string) error) (*Store, error) {
	if dir == "" {
		return nil, errors.New("state: empty directory")
	}
	if err := ensureDirectory(dir, stateDirMode); err != nil {
		return nil, fmt.Errorf("state directory: %w", err)
	}
	revisions := filepath.Join(dir, "revisions")
	if err := ensureDirectory(revisions, stateDirMode); err != nil {
		return nil, fmt.Errorf("state revisions directory: %w", err)
	}

	s := &Store{dir: dir, revisions: revisions, checkpoint: checkpoint}
	ownerPath := filepath.Join(dir, "owner.json")
	ownerBytes, err := readOptional(ownerPath)
	if err != nil {
		return nil, fmt.Errorf("state owner: %w", err)
	}
	if ownerBytes == nil {
		if err := ensureNoPreexistingRecords(dir, revisions); err != nil {
			return nil, err
		}
		owner := makeID()
		if owner == "" {
			return nil, errors.New("state: generate owner identity")
		}
		if err := s.publish("owner", ownerPath, ownerRecord{Owner: owner}); err != nil {
			return nil, fmt.Errorf("state owner: %w", err)
		}
		s.owner = owner
	} else {
		var record ownerRecord
		if err := decodeRecord(ownerBytes, &record); err != nil {
			return nil, fmt.Errorf("state owner: %w", err)
		}
		if err := validateID(record.Owner, "owner"); err != nil {
			return nil, err
		}
		s.owner = record.Owner
	}
	if _, err := s.read(); err != nil {
		return nil, fmt.Errorf("state metadata: %w", err)
	}
	return s, nil
}

// Owner returns this state directory's stable ownership identity.
func (s *Store) Owner() string { return s.owner }

// Read returns a fresh, validated view of the durable records.
func (s *Store) Read() (View, error) {
	return s.read()
}

func (s *Store) read() (View, error) {
	ownerBytes, err := readRequired(filepath.Join(s.dir, "owner.json"))
	if err != nil {
		return View{}, fmt.Errorf("owner record: %w", err)
	}
	var owner ownerRecord
	if err := decodeRecord(ownerBytes, &owner); err != nil {
		return View{}, fmt.Errorf("owner record: %w", err)
	}
	if err := validateID(owner.Owner, "owner"); err != nil {
		return View{}, err
	}
	if owner.Owner != s.owner {
		return View{}, errors.New("state: owner identity changed")
	}
	view := View{Owner: s.owner, Revisions: make(map[string]*Revision)}
	activeBytes, err := readOptional(filepath.Join(s.dir, "active.json"))
	if err != nil {
		return View{}, fmt.Errorf("active record: %w", err)
	}
	if activeBytes != nil {
		var active activeRecord
		if err := decodeRecord(activeBytes, &active); err != nil {
			return View{}, fmt.Errorf("active record: %w", err)
		}
		if err := validateID(active.ID, "active revision"); err != nil {
			return View{}, err
		}
		revision, err := s.readRevision(active.ID)
		if err != nil {
			return View{}, fmt.Errorf("active revision %s: %w", active.ID, err)
		}
		view.Active = revision
		view.Revisions[active.ID] = revision
	}

	journalBytes, err := readOptional(filepath.Join(s.dir, "journal.json"))
	if err != nil {
		return View{}, fmt.Errorf("journal: %w", err)
	}
	if journalBytes != nil {
		var journal Journal
		if err := decodeRecord(journalBytes, &journal); err != nil {
			return View{}, fmt.Errorf("journal: %w", err)
		}
		if err := validateJournal(&journal); err != nil {
			return View{}, err
		}
		view.Journal = &journal
		ids := append([]string(nil), journal.Revisions...)
		if journal.Previous != "" {
			ids = append(ids, journal.Previous)
		}
		if journal.Candidate != "" {
			ids = append(ids, journal.Candidate)
		}
		for _, id := range ids {
			if _, ok := view.Revisions[id]; ok {
				continue
			}
			revision, err := s.readRevision(id)
			if err != nil {
				return View{}, fmt.Errorf("journal revision %s: %w", id, err)
			}
			view.Revisions[id] = revision
		}
		if journal.Operation == "apply" && journal.Previous != "" && view.Active == nil {
			return View{}, errors.New("state: apply journal has previous revision but active record is absent")
		}
		if journal.Operation == "apply" && view.Active != nil && view.Active.ID != journal.Previous && view.Active.ID != journal.Candidate {
			return View{}, errors.New("state: active record does not match apply journal")
		}
	}
	return view, nil
}

// Prepare durably records an immutable candidate and then its apply journal before kernel mutation.
func (s *Store) Prepare(previous, candidate *Revision) error {
	if candidate == nil {
		return errors.New("state: nil candidate revision")
	}
	if err := s.validateRevision(candidate); err != nil {
		return fmt.Errorf("candidate: %w", err)
	}
	if previous != nil {
		if err := s.validateRevision(previous); err != nil {
			return fmt.Errorf("previous: %w", err)
		}
		if err := s.ensureRevisionMatches(previous); err != nil {
			return err
		}
	}
	if current, err := s.read(); err != nil {
		return err
	} else if current.Journal != nil {
		return errors.New("state: transaction already pending")
	}
	if err := s.writeImmutableRevision(candidate); err != nil {
		return fmt.Errorf("candidate revision: %w", err)
	}
	journal := Journal{Version: recordVersion, ID: candidate.ID, Operation: "apply", Phase: "prepared", Candidate: candidate.ID}
	if previous != nil {
		journal.Previous = previous.ID
		journal.Revisions = append(journal.Revisions, previous.ID)
	}
	if candidate.ID != journal.Previous {
		journal.Revisions = append(journal.Revisions, candidate.ID)
	}
	if err := s.publish("journal", filepath.Join(s.dir, "journal.json"), journal); err != nil {
		return fmt.Errorf("prepare journal: %w", err)
	}
	return nil
}

// MarkPhase durably updates the diagnostic phase of the pending apply journal.
func (s *Store) MarkPhase(phase string) error {
	view, err := s.read()
	if err != nil {
		return err
	}
	if view.Journal == nil || view.Journal.Operation != "apply" {
		return errors.New("state: no pending apply journal")
	}
	if !validApplyPhase(phase) {
		return fmt.Errorf("state: invalid apply phase %q", phase)
	}
	journal := *view.Journal
	journal.Phase = phase
	return s.publish("journal", filepath.Join(s.dir, "journal.json"), journal)
}

// Commit durably publishes candidate as the authoritative active revision.
func (s *Store) Commit(candidate *Revision) error {
	if candidate == nil {
		return errors.New("state: nil commit candidate")
	}
	if err := s.validateRevision(candidate); err != nil {
		return fmt.Errorf("candidate: %w", err)
	}
	view, err := s.read()
	if err != nil {
		return err
	}
	if view.Journal == nil || view.Journal.Operation != "apply" || view.Journal.Candidate != candidate.ID {
		return errors.New("state: commit candidate does not match pending journal")
	}
	if err := s.ensureRevisionMatches(candidate); err != nil {
		return err
	}
	return s.publish("active", filepath.Join(s.dir, "active.json"), activeRecord{ID: candidate.ID})
}

// Stabilize validates observed records and fsyncs every named file and containing directory.
func (s *Store) Stabilize() error {
	view, err := s.read()
	if err != nil {
		return err
	}
	if err := s.checkpointCall("stabilize:before-file-sync"); err != nil {
		return err
	}
	paths := []string{filepath.Join(s.dir, "owner.json")}
	if view.Active != nil {
		paths = append(paths, filepath.Join(s.dir, "active.json"))
	}
	if view.Journal != nil {
		paths = append(paths, filepath.Join(s.dir, "journal.json"))
	}
	for id := range view.Revisions {
		paths = append(paths, s.revisionPath(id))
	}
	for _, path := range paths {
		if err := syncRegular(path); err != nil {
			return fmt.Errorf("stabilize %s: %w", filepath.Base(path), err)
		}
	}
	if err := s.checkpointCall("stabilize:before-dir-sync"); err != nil {
		return err
	}
	if err := syncDirectory(s.dir); err != nil {
		return fmt.Errorf("stabilize state directory: %w", err)
	}
	if err := syncDirectory(s.revisions); err != nil {
		return fmt.Errorf("stabilize revisions directory: %w", err)
	}
	return nil
}

// BeginCleanup durably replaces any pending intent with an explicit cleanup journal.
func (s *Store) BeginCleanup(view View, id string) error {
	if view.Owner != s.owner {
		return errors.New("state: cleanup view belongs to another owner")
	}
	if err := validateID(id, "cleanup transaction"); err != nil {
		return err
	}
	if err := validateView(&view); err != nil {
		return err
	}
	for id, revision := range view.Revisions {
		if err := s.validateRevision(revision); err != nil {
			return fmt.Errorf("state: cleanup revision %s: %w", id, err)
		}
	}
	if view.Active != nil {
		if _, ok := view.Revisions[view.Active.ID]; !ok {
			return errors.New("state: cleanup active revision is not referenced")
		}
	}
	if view.Journal != nil {
		for _, id := range append(append([]string{}, view.Journal.Revisions...), view.Journal.Previous, view.Journal.Candidate) {
			if id != "" {
				if _, ok := view.Revisions[id]; !ok {
					return fmt.Errorf("state: cleanup journal revision %s is not referenced", id)
				}
			}
		}
	}
	journal := Journal{Version: recordVersion, ID: id, Operation: "cleanup", Phase: "cleanup"}
	seen := make(map[string]struct{})
	add := func(value string) {
		if value != "" {
			if _, ok := seen[value]; !ok {
				seen[value] = struct{}{}
				journal.Revisions = append(journal.Revisions, value)
			}
		}
	}
	if view.Active != nil {
		add(view.Active.ID)
	}
	if view.Journal != nil {
		add(view.Journal.Previous)
		add(view.Journal.Candidate)
		for _, value := range view.Journal.Revisions {
			add(value)
		}
	}
	for value := range view.Revisions {
		add(value)
	}
	// Stable ordering makes the immutable intent deterministic and reviewable.
	sortStrings(journal.Revisions)
	return s.publish("journal", filepath.Join(s.dir, "journal.json"), journal)
}

// RemoveActive durably removes the active reference after owned kernel artifacts are gone.
func (s *Store) RemoveActive() error {
	path := filepath.Join(s.dir, "active.json")
	data, err := readOptional(path)
	if err != nil {
		return err
	}
	if data == nil {
		return nil
	}
	var active activeRecord
	if err := decodeRecord(data, &active); err != nil {
		return fmt.Errorf("active record: %w", err)
	}
	if err := validateID(active.ID, "active revision"); err != nil {
		return err
	}
	if _, err := s.readRevision(active.ID); err != nil {
		return fmt.Errorf("active revision %s: %w", active.ID, err)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove active record: %w", err)
	}
	if err := syncDirectory(s.dir); err != nil {
		return fmt.Errorf("remove active record sync: %w", err)
	}
	return nil
}

// Finish clears a completed journal and then retires only its recorded obsolete revisions.
func (s *Store) Finish() error {
	view, err := s.read()
	if err != nil {
		return err
	}
	if view.Journal == nil {
		return nil
	}
	journal := *view.Journal
	for _, id := range journal.Revisions {
		if _, ok := view.Revisions[id]; !ok {
			return fmt.Errorf("state: journal revision %s is unavailable", id)
		}
	}
	keep := ""
	if view.Active != nil {
		keep = view.Active.ID
	}
	for _, id := range journal.Revisions {
		path := s.revisionPath(id)
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("retire revision %s: %w", id, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("retire revision %s: unsafe file", id)
		}
	}
	if err := os.Remove(filepath.Join(s.dir, "journal.json")); err != nil {
		return fmt.Errorf("remove journal: %w", err)
	}
	if err := syncDirectory(s.dir); err != nil {
		return fmt.Errorf("remove journal sync: %w", err)
	}
	for _, id := range journal.Revisions {
		if id == keep {
			continue
		}
		path := s.revisionPath(id)
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("retire revision %s: %w", id, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("retire revision %s: unsafe file", id)
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("retire revision %s: %w", id, err)
		}
		if err := syncDirectory(s.revisions); err != nil {
			return fmt.Errorf("retire revision sync: %w", err)
		}
	}
	return nil
}

func (s *Store) validateRevision(revision *Revision) error {
	if revision == nil {
		return errors.New("state: nil revision")
	}
	if revision.Version != recordVersion {
		return fmt.Errorf("state: revision version %d is unsupported", revision.Version)
	}
	if err := validateID(revision.ID, "revision"); err != nil {
		return err
	}
	if revision.Config.Version != 1 {
		return fmt.Errorf("state: revision %s has unsupported configuration version %d", revision.ID, revision.Config.Version)
	}
	if err := firewall.ValidateConfig(revision.Config); err != nil {
		return fmt.Errorf("state: revision %s configuration: %w", revision.ID, err)
	}
	compiled, err := policy.Compile(revision.Config, policy.Snapshot{})
	if err != nil {
		return fmt.Errorf("state: revision %s compiled model: %w", revision.ID, err)
	}
	if revision.Target == nil {
		return nil
	}
	if err := firewall.ValidateTarget(revision.Target); err != nil {
		return fmt.Errorf("state: revision %s target: %w", revision.ID, err)
	}
	if revision.Target.Owner != s.owner {
		return fmt.Errorf("state: revision %s target owner mismatch", revision.ID)
	}
	if revision.Target.Table != revision.Config.Firewall.Nftables.Table || revision.Target.Priority != revision.Config.Firewall.Nftables.Priority {
		return fmt.Errorf("state: revision %s target/config mismatch", revision.ID)
	}
	if !reflect.DeepEqual(revision.Target.Families, compiled.Families()) {
		return fmt.Errorf("state: revision %s target/config model mismatch", revision.ID)
	}
	return nil
}

func (s *Store) ensureRevisionMatches(revision *Revision) error {
	if revision == nil {
		return errors.New("state: nil revision")
	}
	storedBytes, err := readRequired(s.revisionPath(revision.ID))
	if err != nil {
		return fmt.Errorf("state: revision %s: %w", revision.ID, err)
	}
	expected, err := encodeRecord(*revision)
	if err != nil {
		return err
	}
	if !bytes.Equal(storedBytes, expected) {
		return fmt.Errorf("state: immutable revision %s differs", revision.ID)
	}
	if _, err := s.readRevision(revision.ID); err != nil {
		return err
	}
	return nil
}

func (s *Store) writeImmutableRevision(revision *Revision) error {
	path := s.revisionPath(revision.ID)
	data, err := encodeRecord(*revision)
	if err != nil {
		return err
	}
	existing, err := readOptional(path)
	if err != nil {
		return err
	}
	if existing != nil {
		if _, err := s.readRevision(revision.ID); err != nil {
			return err
		}
		if !bytes.Equal(existing, data) {
			return fmt.Errorf("state: immutable revision %s already differs", revision.ID)
		}
		return syncRegular(path)
	}
	return s.publishBytes("revision", path, data)
}

func (s *Store) readRevision(id string) (*Revision, error) {
	if err := validateID(id, "revision"); err != nil {
		return nil, err
	}
	data, err := readRequired(s.revisionPath(id))
	if err != nil {
		return nil, err
	}
	var revision Revision
	if err := decodeRecord(data, &revision); err != nil {
		return nil, err
	}
	if revision.ID != id {
		return nil, errors.New("state: revision filename and identity differ")
	}
	if err := s.validateRevision(&revision); err != nil {
		return nil, err
	}
	return &revision, nil
}

func (s *Store) publish(record, path string, payload any) error {
	data, err := encodeRecord(payload)
	if err != nil {
		return err
	}
	return s.publishBytes(record, path, data)
}

func (s *Store) publishBytes(record, path string, data []byte) error {
	return atomicPublish(path, data, record, s.checkpoint)
}

func (s *Store) revisionPath(id string) string { return filepath.Join(s.revisions, id+".json") }

func (s *Store) checkpointCall(name string) error {
	if s.checkpoint == nil {
		return nil
	}
	return s.checkpoint(name)
}

func encodeRecord(payload any) ([]byte, error) {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode payload: %w", err)
	}
	digest := sha256.Sum256(payloadBytes)
	record := envelope{Version: recordVersion, Checksum: hex.EncodeToString(digest[:]), Payload: payloadBytes}
	data, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("encode record: %w", err)
	}
	if len(data) > maxRecordBytes {
		return nil, errors.New("state: encoded record is oversized")
	}
	return data, nil
}

func decodeRecord(data []byte, target any) error {
	if len(data) == 0 || len(data) > maxRecordBytes {
		return errors.New("state: record size is invalid")
	}
	if err := checkJSON(data); err != nil {
		return err
	}
	var record envelope
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return fmt.Errorf("state: malformed record: %w", err)
	}
	if err := ensureEOF(decoder); err != nil {
		return err
	}
	if record.Version != recordVersion {
		return fmt.Errorf("state: record version %d is unsupported", record.Version)
	}
	if len(record.Payload) == 0 || len(record.Payload) > maxRecordBytes {
		return errors.New("state: record payload size is invalid")
	}
	digest := sha256.Sum256(record.Payload)
	encoded, err := hex.DecodeString(record.Checksum)
	if err != nil || len(encoded) != sha256.Size || subtle.ConstantTimeCompare(encoded, digest[:]) != 1 {
		return errors.New("state: record checksum mismatch")
	}
	payloadDecoder := json.NewDecoder(bytes.NewReader(record.Payload))
	payloadDecoder.DisallowUnknownFields()
	if err := payloadDecoder.Decode(target); err != nil {
		return fmt.Errorf("state: malformed payload: %w", err)
	}
	return ensureEOF(payloadDecoder)
}

func checkJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := checkJSONValue(decoder); err != nil {
		return fmt.Errorf("state: malformed JSON: %w", err)
	}
	return ensureEOF(decoder)
}

func checkJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch delimiter := token.(type) {
	case json.Delim:
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok {
					return errors.New("object key is not a string")
				}
				if _, ok := seen[name]; ok {
					return fmt.Errorf("duplicate object key %q", name)
				}
				seen[name] = struct{}{}
				if err := checkJSONValue(decoder); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("unterminated object")
			}
		case '[':
			for decoder.More() {
				if err := checkJSONValue(decoder); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("unterminated array")
			}
		default:
			return errors.New("unexpected delimiter")
		}
	}
	return nil
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("state: trailing JSON data")
		}
		return fmt.Errorf("state: trailing JSON data: %w", err)
	}
	return nil
}

func readOptional(path string) (data []byte, retErr error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("unsafe record %q", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("record %q has unsafe permissions", path)
	}
	file, err := os.OpenFile(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0) // #nosec G304 -- path is a state record selected by the store; O_NOFOLLOW prevents symlink traversal.
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := file.Close(); retErr == nil && closeErr != nil {
			data = nil
			retErr = closeErr
		}
	}()
	limited := io.LimitReader(file, maxRecordBytes+1)
	data, err = io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(data) > maxRecordBytes {
		return nil, errors.New("state: record is oversized")
	}
	return data, nil
}

func readRequired(path string) ([]byte, error) {
	data, err := readOptional(path)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, os.ErrNotExist
	}
	return data, nil
}

func ensureDirectory(path string, mode os.FileMode) error {
	clean := filepath.Clean(path)
	var missing []string
	current := clean
	for {
		info, err := os.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return fmt.Errorf("%q is not a directory", current)
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		missing = append(missing, current)
		parent := filepath.Dir(current)
		if parent == current {
			return fmt.Errorf("cannot find parent directory for %q", current)
		}
		current = parent
	}
	for index := len(missing) - 1; index >= 0; index-- {
		directory := missing[index]
		if err := os.Mkdir(directory, mode.Perm()); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		info, err := os.Lstat(directory)
		if err != nil {
			return err
		}
		if err := validateManagedDirectory(directory, info, mode); err != nil {
			return err
		}
		if err := syncDirectory(filepath.Dir(directory)); err != nil {
			return fmt.Errorf("sync parent of %q: %w", directory, err)
		}
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return err
	}
	if err := validateManagedDirectory(clean, info, mode); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(clean)); err != nil {
		return fmt.Errorf("sync parent of %q: %w", clean, err)
	}
	return nil
}

func validateManagedDirectory(path string, info os.FileInfo, mode os.FileMode) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%q is not a directory", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return fmt.Errorf("directory %q is owned by another user", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("directory %q has unsafe permissions", path)
	}
	if info.Mode().Perm() != mode.Perm() {
		if err := os.Chmod(path, mode.Perm()); err != nil {
			return err
		}
	}
	return nil
}

func ensureNoPreexistingRecords(dir, revisions string) error {
	for _, name := range []string{"active.json", "journal.json"} {
		if info, err := os.Lstat(filepath.Join(dir, name)); err == nil && info != nil {
			return errors.New("state: records exist without owner identity")
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	entries, err := os.ReadDir(revisions)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".") {
			return errors.New("state: revisions exist without owner identity")
		}
	}
	return nil
}

func atomicPublish(path string, data []byte, record string, checkpoint func(string) error) error {
	dir := filepath.Dir(path)
	if err := ensureDirectory(dir, stateDirMode); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if record == "owner" {
			return errors.New("owner record already exists")
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("unsafe destination %q", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temp, err := os.CreateTemp(dir, ".state-tmp-")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(recordFileMode); err != nil {
		_ = temp.Close()
		return err
	}
	if err := writeFull(temp, data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := checkpointCall(checkpoint, record+":before-file-sync"); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := checkpointCall(checkpoint, record+":before-rename"); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	removeTemp = false
	if err := checkpointCall(checkpoint, record+":after-rename"); err != nil {
		return err
	}
	if err := syncDirectory(dir); err != nil {
		return err
	}
	return checkpointCall(checkpoint, record+":after-dir-sync")
}

func writeFull(file *os.File, data []byte) error {
	for len(data) > 0 {
		n, err := file.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func syncRegular(path string) (err error) {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("unsafe regular file")
	}
	file, err := os.OpenFile(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0) // #nosec G304 -- path is a state record selected by the store; O_NOFOLLOW prevents symlink traversal.
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := file.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()
	return file.Sync()
}

func syncDirectory(path string) (err error) {
	file, err := os.OpenFile(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0) // #nosec G304 -- path is a state directory selected by the store; O_NOFOLLOW prevents symlink traversal.
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := file.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()
	return file.Sync()
}

func checkpointCall(checkpoint func(string) error, name string) error {
	if checkpoint == nil {
		return nil
	}
	return checkpoint(name)
}

func makeID() string {
	var raw [idLength / 2]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(raw[:])
}

func validateID(value, label string) error {
	if len(value) != idLength {
		return fmt.Errorf("state: %s identity must be %d lowercase hex characters", label, idLength)
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return fmt.Errorf("state: %s identity is not lowercase hexadecimal", label)
		}
	}
	return nil
}

func validateJournal(journal *Journal) error {
	if journal.Version != recordVersion {
		return fmt.Errorf("state: journal version %d is unsupported", journal.Version)
	}
	if err := validateID(journal.ID, "journal"); err != nil {
		return err
	}
	if journal.Operation != "apply" && journal.Operation != "cleanup" {
		return fmt.Errorf("state: unsupported journal operation %q", journal.Operation)
	}
	if journal.Operation == "apply" {
		if !validApplyPhase(journal.Phase) {
			return fmt.Errorf("state: unsupported apply phase %q", journal.Phase)
		}
		if journal.Candidate == "" {
			return errors.New("state: apply journal has no candidate")
		}
	} else if journal.Phase != "cleanup" {
		return fmt.Errorf("state: unsupported cleanup phase %q", journal.Phase)
	}
	for _, id := range []string{journal.Previous, journal.Candidate} {
		if id != "" {
			if err := validateID(id, "journal revision"); err != nil {
				return err
			}
		}
	}
	seen := make(map[string]struct{}, len(journal.Revisions))
	for _, id := range journal.Revisions {
		if err := validateID(id, "journal revision"); err != nil {
			return err
		}
		if _, ok := seen[id]; ok {
			return fmt.Errorf("state: journal repeats revision %s", id)
		}
		seen[id] = struct{}{}
	}
	for _, id := range []string{journal.Previous, journal.Candidate} {
		if id != "" {
			if _, ok := seen[id]; !ok {
				return fmt.Errorf("state: journal omits revision %s", id)
			}
		}
	}
	return nil
}

func validApplyPhase(phase string) bool {
	return phase == "prepared" || phase == "switched" || phase == "committed" || phase == "cleanup"
}

func validateView(view *View) error {
	if view == nil {
		return errors.New("state: nil cleanup view")
	}
	if view.Active != nil && view.Active.ID == "" {
		return errors.New("state: cleanup view has invalid active revision")
	}
	if view.Journal != nil {
		if err := validateJournal(view.Journal); err != nil {
			return err
		}
	}
	for id, revision := range view.Revisions {
		if err := validateID(id, "cleanup revision"); err != nil {
			return err
		}
		if revision == nil || revision.ID != id {
			return fmt.Errorf("state: cleanup revision %s is invalid", id)
		}
	}
	return nil
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
