package firewall

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/perimeterd/perimeterd/internal/policy"
)

func TestCapacityCategoriesCannotRenderUntrustedValues(t *testing.T) {
	capacity := &CapacityError{Backend: "secret-backend", Resource: "secret-prefix", Scope: "secret-scope", RequiredBytes: 2, LimitBytes: 1}
	if strings.Contains(capacity.Error(), "secret") || capacity.SafeBackend() != "unknown" || capacity.SafeResource() != "unknown" || capacity.SafeScope() != "unknown" {
		t.Fatalf("capacity leaked untrusted categories: %s", capacity)
	}
	if capacity.RecoveryRetryable() {
		t.Fatal("deterministic capacity failure became retryable")
	}
}

func TestNativeOutputCapacityPreservesWrappedCause(t *testing.T) {
	for _, backend := range []string{"nftables", "iptables"} {
		t.Run(backend, func(t *testing.T) {
			overflow := &nativeOutputLimitError{required: 17, limit: 16}
			cause := fmt.Errorf("wrapped: %w", errors.Join(errors.New("native failure"), overflow))
			var err error
			if backend == "nftables" {
				native := &NFT{exec: func(context.Context, []string, []byte) ([]byte, error) { return nil, cause }}
				_, err = native.run(t.Context(), nil, nil)
			} else {
				native := &IPTables{exec: func(context.Context, string, []string, []byte) ([]byte, error) { return nil, cause }}
				_, err = native.run(t.Context(), "ipset", nil, nil)
			}
			var capacity *CapacityError
			if !errors.As(err, &capacity) || !errors.Is(err, overflow) || capacity.Backend != backend || capacity.Resource != "native-io" || capacity.Scope != "output" || capacity.RequiredBytes != 17 || capacity.LimitBytes != 16 {
				t.Fatalf("output failure lost classification or cause: %+v %v", capacity, err)
			}
		})
	}
}

func TestIPSetRestoreChunkBoundariesPreserveCommands(t *testing.T) {
	var calls []string
	native := &IPTables{exec: func(_ context.Context, _ string, _ []string, input []byte) ([]byte, error) {
		calls = append(calls, string(input))
		return nil, nil
	}}
	if err := native.restoreSetsBounded(t.Context(), "one\ntwo\nthree\n", 8); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []string{"one\ntwo\n", "three\n"}) {
		t.Fatalf("commands split or reordered: %q", calls)
	}
	calls = nil
	var capacity *CapacityError
	err := native.restoreSetsBounded(t.Context(), "12345678\n", 8)
	if !errors.As(err, &capacity) || capacity.Backend != "iptables" || capacity.Resource != "ipsets" || capacity.Scope != "input" || capacity.RequiredBytes != 9 || capacity.LimitBytes != 8 || len(calls) != 0 {
		t.Fatalf("oversized command reached execution or lost numbers: %+v %v %q", capacity, err, calls)
	}
}

func TestNFTDecoderExactOutputBoundary(t *testing.T) {
	data := []byte(`{"nftables":[]}`)
	if _, err := decodeNFTObjects(t.Context(), data, len(data)); err != nil {
		t.Fatal(err)
	}
	var capacity *CapacityError
	if _, err := decodeNFTObjects(t.Context(), data, len(data)-1); !errors.As(err, &capacity) || capacity.Backend != "nftables" || capacity.Scope != "output" || capacity.Resource != "nft-table" || capacity.RequiredBytes != int64(len(data)) || capacity.LimitBytes != int64(len(data)-1) {
		t.Fatalf("decoder lost exact output boundary: %+v %v", capacity, err)
	}
}

func TestIPTablesObservedChainBytesMatchCapturedRecords(t *testing.T) {
	declaration := ":owned - [0:0]\n"
	rule := "[123:456] -A owned -m comment --comment \"two\nlines\" -j RETURN\n"
	data := "*filter\n" + declaration + rule + ":foreign - [0:0]\nCOMMIT\n"
	inventory, err := parseIPTablesSave(policy.IPv4, []byte(data))
	if err != nil {
		t.Fatal(err)
	}
	key := iptChainKey{Family: policy.IPv4, Table: "filter", Chain: "owned"}
	if got, want := inventory.Chains[key].SerializedBytes, int64(len(declaration)+len(rule)); got != want {
		t.Fatalf("observed chain size = %d, want exact captured %d", got, want)
	}
}

func TestNativeSmallInputAndCaptureBoundaries(t *testing.T) {
	// An empty executable is intentional: over-limit input must reject before
	// attempting process creation.
	var capacity *CapacityError
	_, err := executeNative(t.Context(), "", nil, []byte("12345"), 4, 4)
	if !errors.As(err, &capacity) || capacity.Scope != "input" || capacity.Resource != "native-io" || capacity.RequiredBytes != 5 || capacity.LimitBytes != 4 {
		t.Fatalf("executor lost numeric input boundary: %+v %v", capacity, err)
	}
	buffer := boundedBuffer{limit: 4}
	if n, err := buffer.Write([]byte("1234")); err != nil || n != 4 {
		t.Fatalf("exact output boundary rejected: %d %v", n, err)
	}
	if _, err := buffer.Write([]byte("5")); !errors.As(err, &capacity) || capacity.Scope != "output" || capacity.RequiredBytes != 5 || capacity.LimitBytes != 4 {
		t.Fatalf("capture lost numeric output boundary: %+v %v", capacity, err)
	}
	if string(buffer.Bytes()) != "1234" {
		t.Fatalf("overflow changed bounded capture: %q", buffer.Bytes())
	}
}
