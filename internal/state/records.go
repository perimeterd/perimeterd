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
	"reflect"

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
	Version         int              `json:"version"`
	ID              string           `json:"id"`
	Epoch           uint64           `json:"epoch"`
	RefreshSequence uint64           `json:"refresh_sequence,omitempty"`
	Manifest        string           `json:"manifest,omitempty"`
	ConfigPath      string           `json:"config_path"`
	Config          config.Config    `json:"config"`
	Target          *firewall.Target `json:"target"`
}

// Journal describes an in-flight apply or explicit cleanup operation.
type Journal struct {
	Version           int               `json:"version"`
	ID                string            `json:"id"`
	Operation         string            `json:"operation"`
	Phase             string            `json:"phase"`
	Previous          string            `json:"previous"`
	Candidate         string            `json:"candidate"`
	PreviousManifest  string            `json:"previous_manifest,omitempty"`
	CandidateManifest string            `json:"candidate_manifest,omitempty"`
	Revisions         []string          `json:"revisions"`
	FamilySelections  []FamilySelection `json:"family_selections,omitempty"`
}

// FamilySelection records the observed iptables selection after one atomic
// family commit. Empty Generation records an unhooked family.
type FamilySelection struct {
	Family     policy.Family `json:"family"`
	Generation string        `json:"generation"`
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
	required, err := policy.RequiredSelectors(revision.Config)
	if err != nil {
		return fmt.Errorf("state: revision %s selectors: %w", revision.ID, err)
	}
	var snapshot policy.Snapshot
	if revision.Manifest == "" {
		if len(required) != 0 {
			return fmt.Errorf("state: revision %s has no manifest for required selectors", revision.ID)
		}
	} else {
		if err := validateCacheManifestID(revision.Manifest); err != nil {
			return fmt.Errorf("state: revision %s manifest: %w", revision.ID, err)
		}
		if len(required) == 0 {
			return fmt.Errorf("state: revision %s has a manifest with no required selectors", revision.ID)
		}
		if s.prefixes == nil {
			return errors.New("state: source cache is unavailable")
		}
		cached, err := s.prefixes.Load(revision.Manifest)
		if err != nil {
			return fmt.Errorf("state: revision %s manifest: %w", revision.ID, err)
		}
		snapshot = cached.Policy()
		if !reflect.DeepEqual(cached.Policy().Selectors(), required) {
			return fmt.Errorf("state: revision %s manifest selector coverage mismatch", revision.ID)
		}
	}
	compiled, err := policy.Compile(revision.Config, snapshot)
	if err != nil {
		return fmt.Errorf("state: revision %s compiled model: %w", revision.ID, err)
	}
	if revision.Target == nil {
		if !compiled.Empty() {
			return fmt.Errorf("state: revision %s has no target for active policy", revision.ID)
		}
		return nil
	}
	if err := firewall.ValidateTarget(revision.Target); err != nil {
		return fmt.Errorf("state: revision %s target: %w", revision.ID, err)
	}
	if revision.Target.Owner != s.owner {
		return fmt.Errorf("state: revision %s target owner mismatch", revision.ID)
	}
	if revision.Target.Backend() != revision.Config.Firewall.Backend {
		return fmt.Errorf("state: revision %s target/backend mismatch", revision.ID)
	}
	if revision.Target.IPTables != nil {
		if !reflect.DeepEqual(revision.Target.IPTables.Attachments, revision.Config.Firewall.IPTables.Attachments) {
			return fmt.Errorf("state: revision %s attachment/config mismatch", revision.ID)
		}
	} else if revision.Target.Table != revision.Config.Firewall.Nftables.Table || revision.Target.Priority != revision.Config.Firewall.Nftables.Priority {
		return fmt.Errorf("state: revision %s target/config mismatch", revision.ID)
	}
	if !reflect.DeepEqual(revision.Target.Families, compiled.Families()) {
		return fmt.Errorf("state: revision %s target/config model mismatch", revision.ID)
	}
	return nil
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

func validateCacheManifestID(value string) error {
	if len(value) != sha256.Size*2 {
		return fmt.Errorf("manifest identity must be %d lowercase hex characters", sha256.Size*2)
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return errors.New("manifest identity is not lowercase hexadecimal")
		}
	}
	return nil
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
	for _, reference := range []struct{ revision, manifest string }{
		{journal.Previous, journal.PreviousManifest},
		{journal.Candidate, journal.CandidateManifest},
	} {
		if reference.manifest == "" {
			continue
		}
		if reference.revision == "" {
			return errors.New("state: journal manifest has no owning revision")
		}
		if err := validateCacheManifestID(reference.manifest); err != nil {
			return fmt.Errorf("state: journal manifest: %w", err)
		}
	}
	seenFamilies := make(map[policy.Family]struct{}, len(journal.FamilySelections))
	for _, selection := range journal.FamilySelections {
		if selection.Family != policy.IPv4 && selection.Family != policy.IPv6 {
			return errors.New("state: journal contains an invalid family selection")
		}
		if _, duplicate := seenFamilies[selection.Family]; duplicate {
			return errors.New("state: journal repeats a family selection")
		}
		seenFamilies[selection.Family] = struct{}{}
		if selection.Generation != "" {
			if err := validateID(selection.Generation, "selected generation"); err != nil {
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
