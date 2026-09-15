// Package state owns the durable revision, journal, and lifecycle records used by the runtime.
package state

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/perimeterd/perimeterd/internal/policy"
	"github.com/perimeterd/perimeterd/internal/source"
)

// Store manages durable ownership, revision, active, and journal records.
type Store struct {
	dir        string
	revisions  string
	owner      string
	checkpoint func(string) error
	prefixes   *source.Cache
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

	prefixes, err := source.NewCache(dir, checkpoint)
	if err != nil {
		return nil, fmt.Errorf("state prefixes: %w", err)
	}
	s := &Store{dir: dir, revisions: revisions, checkpoint: checkpoint, prefixes: prefixes}
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

// Prefixes returns the immutable source cache owned by this state store.
func (s *Store) Prefixes() *source.Cache { return s.prefixes }

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
		if journal.Operation == "apply" {
			if journal.Previous != "" {
				revision := view.Revisions[journal.Previous]
				if revision == nil || revision.Manifest != journal.PreviousManifest {
					return View{}, errors.New("state: apply journal previous manifest mismatch")
				}
			}
			if journal.Candidate != "" {
				revision := view.Revisions[journal.Candidate]
				if revision == nil || revision.Manifest != journal.CandidateManifest {
					return View{}, errors.New("state: apply journal candidate manifest mismatch")
				}
			}
		}
		if journal.Operation == "apply" && journal.Previous != "" && view.Active == nil {
			return View{}, errors.New("state: apply journal has previous revision but active record is absent")
		}
		for _, selection := range journal.FamilySelections {
			if !recordedFamilySelection(view, selection) {
				return View{}, errors.New("state: family selection names an unrecorded generation")
			}
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
	current, err := s.read()
	if err != nil {
		return err
	}
	if current.Journal != nil {
		return errors.New("state: transaction already pending")
	}
	if previous != nil && previous.Manifest != "" {
		if err := s.prefixes.Stabilize(previous.Manifest); err != nil {
			return fmt.Errorf("previous prefix manifest: %w", err)
		}
	}
	if candidate.Manifest != "" {
		if err := s.prefixes.Stabilize(candidate.Manifest); err != nil {
			return fmt.Errorf("candidate prefix manifest: %w", err)
		}
	}
	if err := s.writeImmutableRevision(candidate); err != nil {
		return fmt.Errorf("candidate revision: %w", err)
	}
	journal := Journal{Version: recordVersion, ID: candidate.ID, Operation: "apply", Phase: "prepared", Candidate: candidate.ID, CandidateManifest: candidate.Manifest}
	if previous != nil {
		journal.Previous = previous.ID
		journal.PreviousManifest = previous.Manifest
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

// RecordFamilySelection durably records actual kernel selection without changing
// commit authority. The writer calls it after each native family commit.
func (s *Store) RecordFamilySelection(family policy.Family, generation string) error {
	view, err := s.read()
	if err != nil {
		return err
	}
	if view.Journal == nil {
		return errors.New("state: family commit has no prepared journal")
	}
	selection := FamilySelection{Family: family, Generation: generation}
	if !recordedFamilySelection(view, selection) {
		return errors.New("state: family commit names an unrecorded generation")
	}
	journal := *view.Journal
	journal.FamilySelections = append([]FamilySelection(nil), journal.FamilySelections...)
	replaced := false
	for i := range journal.FamilySelections {
		if journal.FamilySelections[i].Family == family {
			journal.FamilySelections[i] = selection
			replaced = true
			break
		}
	}
	if !replaced {
		journal.FamilySelections = append(journal.FamilySelections, selection)
	}
	sort.Slice(journal.FamilySelections, func(i, j int) bool {
		return journal.FamilySelections[i].Family < journal.FamilySelections[j].Family
	})
	return s.publish("journal", filepath.Join(s.dir, "journal.json"), journal)
}

func recordedFamilySelection(view View, selection FamilySelection) bool {
	if selection.Family != policy.IPv4 && selection.Family != policy.IPv6 {
		return false
	}
	if selection.Generation == "" {
		return true
	}
	for _, id := range view.Journal.Revisions {
		target := view.Revisions[id].Target
		if target == nil || target.IPTables == nil || target.Generation != selection.Generation {
			continue
		}
		for _, family := range target.Families {
			if family.Family == selection.Family {
				return true
			}
		}
	}
	return false
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
	for _, revision := range view.Revisions {
		if revision.Manifest != "" {
			if err := s.prefixes.Stabilize(revision.Manifest); err != nil {
				return fmt.Errorf("stabilize prefix manifest %s: %w", revision.Manifest, err)
			}
		}
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
