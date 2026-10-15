package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/perimeterd/perimeterd/internal/policy"
)

type nftCapacityKey struct{ kind, name, role string }

type nftCapacityObject struct {
	metadata []byte
	prefixes []netip.Prefix
	bytes    int64
	dynamic  bool
	// A dynamic set is replaced atomically, not accumulated per target.
	projectedBytes int64
	observedBytes  int64
}

type nftTableCapacity struct {
	owner      string
	objects    map[nftCapacityKey]*nftCapacityObject
	staticIDs  map[string]struct{}
	dynamicIDs map[string]struct{}
}

type nftCapacity struct {
	tables map[string]*nftTableCapacity
	inputs map[*Target]int64
}

// validateNFTCapacity counts the union of native identities, not target
// arguments. Only small command metadata is encoded. Prefixes are counted in
// bounded chunks without constructing element maps or a full JSON envelope.
func validateNFTCapacity(ctx context.Context, previous, candidate *Target, dynamic *DynamicState) (*nftCapacity, error) {
	capacity, err := collectNFTCapacity(ctx, previous, candidate)
	if err != nil {
		return nil, err
	}
	if dynamic != nil {
		if err := capacity.addProjection(ctx, candidate, dynamic.Prefixes); err != nil {
			return nil, err
		}
	}
	return capacity, capacity.check(maxNFTInput, maxNFTInventoryBudget)
}

func collectNFTCapacity(ctx context.Context, targets ...*Target) (*nftCapacity, error) {
	capacity := &nftCapacity{tables: make(map[string]*nftTableCapacity), inputs: make(map[*Target]int64)}
	for _, target := range targets {
		if target == nil {
			continue
		}
		if _, exists := capacity.inputs[target]; exists {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := validateNFTTarget(target); err != nil {
			return nil, err
		}
		if err := capacity.addTarget(ctx, target); err != nil {
			return nil, err
		}
	}
	return capacity, nil
}

func (c *nftCapacity) addTarget(ctx context.Context, target *Target) error {
	table := c.tables[target.Table]
	if table == nil {
		table = &nftTableCapacity{owner: target.Owner, objects: make(map[nftCapacityKey]*nftCapacityObject), staticIDs: make(map[string]struct{}), dynamicIDs: make(map[string]struct{})}
		c.tables[target.Table] = table
	} else if table.owner != target.Owner {
		return &ValidationError{Err: errors.New("nft backend: retained table owner conflict")}
	}
	table.staticIDs[target.Generation] = struct{}{}
	if target.DynamicGeneration != "" {
		table.dynamicIDs[target.DynamicGeneration] = struct{}{}
	}
	// The normal generator remains the authority for command structure and
	// rule variants; remove only membership before generating that metadata.
	metadata := *target
	metadata.Families = make([]policy.FamilyPlan, len(target.Families))
	prefixes := make(map[string][]netip.Prefix)
	dynamicSets := make(map[string]bool)
	for i, family := range target.Families {
		metadata.Families[i] = family
		metadata.Families[i].Sets = make([]policy.PrefixSet, len(family.Sets))
		for j, set := range family.Sets {
			metadata.Families[i].Sets[j] = set
			metadata.Families[i].Sets[j].Prefixes = nil
			name := setName(target, family.Family, set.ID)
			prefixes[name] = set.Prefixes
			dynamicSets[name] = set.Kind == policy.DynamicCrowdSecSet
		}
	}
	batch, err := commandBatch(&metadata, nil, nil)
	if err != nil {
		return err
	}
	// Envelope and one comma per command (one extra comma is conservative).
	input := int64(len(`{"nftables":[]}`))
	for _, command := range batch.Nftables {
		if err := ctx.Err(); err != nil {
			return err
		}
		key, mutable := nftCapacityIdentity(command, target.Owner)
		encoded, err := json.Marshal(command)
		if err != nil {
			return err
		}
		var values []netip.Prefix
		if key.kind == "set" {
			values = prefixes[key.name]
		}
		if existing := table.objects[key]; existing != nil && !mutable {
			if !bytes.Equal(existing.metadata, encoded) || !equalNFTPrefixes(ctx, existing.prefixes, values) {
				if err := ctx.Err(); err != nil {
					return err
				}
				return &ValidationError{Err: errors.New("nft backend: conflicting metadata for a retained native identity")}
			}
			input += existing.bytes
			continue
		}
		membershipBytes := int64(0)
		if key.kind == "set" && len(values) != 0 {
			membershipBytes, err = nftPrefixBytes(ctx, values)
			if err != nil {
				return err
			}
			// Empty metadata omits elem. Add its key, brackets and separators.
			membershipBytes += int64(len(`,"elem":[]`) + len(values) - 1)
		}
		size := int64(len(encoded)) + membershipBytes + 1
		input += size
		if existing := table.objects[key]; existing != nil {
			if size > existing.bytes {
				existing.bytes = size
			}
			continue
		}
		table.objects[key] = &nftCapacityObject{metadata: encoded, prefixes: values, bytes: size, dynamic: key.kind == "set" && dynamicSets[key.name]}
	}
	c.inputs[target] = input
	return nil
}

func nftCapacityIdentity(command nftCommand, owner string) (nftCapacityKey, bool) {
	operation := command.Add
	if operation == nil {
		operation = command.Create
	}
	for kind, value := range operation.(map[string]any) {
		fields := value.(map[string]any)
		name, _ := fields["name"].(string)
		role := ""
		if kind == "rule" {
			name = fields["chain"].(string)
			comment := fields["comment"].(string)
			_, role, _ = strings.Cut(comment, " role=")
		}
		// Stable hooks/entry dispatch are atomically rewritten. Their old and
		// new definitions cannot coexist; immutable generation rules must match.
		mutable := (kind == "chain" || kind == "rule") && strings.HasPrefix(name, "pd_"+owner+"_stable_")
		return nftCapacityKey{kind: kind, name: name, role: role}, mutable
	}
	panic("empty generated nft command")
}

func equalNFTPrefixes(ctx context.Context, a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if i%1024 == 0 && ctx.Err() != nil {
			return false
		}
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func nftPrefixSize(prefix netip.Prefix, buffer []byte) int64 {
	// Canonical addresses contain no JSON-escaped characters. This is the
	// exact size of prefixExpression's JSON, excluding no generated fields.
	size := int64(len(`{"prefix":{"addr":"","len":0}}`) - 1 + len(prefix.Addr().AppendTo(buffer[:0])))
	bits := prefix.Bits()
	switch {
	case bits >= 100:
		size += 3
	case bits >= 10:
		size += 2
	default:
		size++
	}
	return size
}

func nftPrefixBytes(ctx context.Context, prefixes []netip.Prefix) (int64, error) {
	var buffer [64]byte
	var size int64
	for i, prefix := range prefixes {
		if i%1024 == 0 {
			if err := ctx.Err(); err != nil {
				return 0, err
			}
		}
		size += nftPrefixSize(prefix, buffer[:])
	}
	return size, nil
}

func (c *nftCapacity) addProjection(ctx context.Context, target *Target, desired []policy.TimedPrefix) error {
	if err := validateDynamicState(target, &DynamicState{Prefixes: desired}); err != nil {
		return err
	}
	if target == nil {
		return nil
	}
	now := time.Now()
	var buffer [64]byte
	for _, family := range target.Families {
		var size int64
		for i, value := range desired {
			if i%1024 == 0 {
				if err := ctx.Err(); err != nil {
					return err
				}
			}
			if value.Prefix.Addr().Is4() != (family.Family == policy.IPv4) {
				continue
			}
			grant, _ := LeaseGrant(value.Deadline, now, time.Second)
			if grant <= 0 {
				continue
			}
			valueBytes := nftPrefixSize(value.Prefix, buffer[:])
			if value.Prefix.Bits() == value.Prefix.Addr().BitLen() {
				valueBytes = int64(len(value.Prefix.Addr().AppendTo(buffer[:0])) + 2)
			}
			// Five timeout digits conservatively cover the full 24-hour grant.
			size += int64(len(`{"elem":{"val":,"timeout":86400}},`)) + valueBytes
		}
		if size == 0 {
			continue
		}
		name := dynamicSetName(target, family.Family)
		entry := c.tables[target.Table].objects[nftCapacityKey{kind: "set", name: name}]
		if entry == nil {
			return &ValidationError{Err: errors.New("nft backend: projection has no retained dynamic identity")}
		}
		// Grouped add-element metadata and bookkeeping are bounded by 1 KiB.
		entry.projectedBytes = size + 1024
		c.inputs[target] += size + 1024
	}
	return nil
}

// observe includes live leases absent from durable target documents. For a
// shared container take the larger old/new content, not their sum: replacement
// is atomic. Distinct containers retain their separate charges.
func (c *nftCapacity) observe(ctx context.Context, tableName string, inventory *nftInventory) error {
	if inventory == nil || !inventory.present {
		return nil
	}
	table := c.tables[tableName]
	if table == nil {
		return &ValidationError{Err: errors.New("nft backend: inventory has no retained authority")}
	}
	for key, entry := range table.objects {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !entry.dynamic {
			continue
		}
		if observed, ok := inventory.sets[key.name]; ok {
			entry.observedBytes = int64(len(observed.Elem))
		}
	}
	if int64(inventory.sizeBytes) > maxNFTInventoryBudget {
		return table.capacityError("inventory", int64(inventory.sizeBytes), maxNFTInventoryBudget)
	}
	return c.check(maxNFTInput, maxNFTInventoryBudget)
}

func (t *nftTableCapacity) estimate() int64 {
	encoded := int64(len(`{"nftables":[]}`))
	commands := int64(len(t.objects))
	var elements int64
	for _, object := range t.objects {
		encoded += object.bytes
		if object.dynamic {
			// Projected command JSON needs representation headroom. Observed
			// elements are already native inventory JSON: charge them once.
			size := max(2*object.projectedBytes, object.observedBytes)
			if size != 0 {
				elements += size
				commands++
			}
		}
	}
	return 2*encoded + elements + 1024*commands + 4096
}

func (t *nftTableCapacity) capacityError(scope string, required, limit int64) *CapacityError {
	return &CapacityError{Scope: scope, RequiredBytes: required, LimitBytes: limit, StaticGenerations: len(t.staticIDs), DynamicGenerations: len(t.dynamicIDs)}
}

func (c *nftCapacity) check(inputLimit, inventoryLimit int64) error {
	for target, size := range c.inputs {
		if size > inputLimit {
			return c.tables[target.Table].capacityError("input", size, inputLimit)
		}
	}
	for _, table := range c.tables {
		if size := table.estimate(); size > inventoryLimit {
			return table.capacityError("inventory", size, inventoryLimit)
		}
	}
	return nil
}
