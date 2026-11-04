package firewall

// Native I/O bounds are shared; inventory admission remains independently
// scoped to each nft table, recorded ipsets, and each family's rule inventory.
const (
	maxNativeInputBytes     = 64 << 20
	maxInventoryBudgetBytes = 256 << 20
	maxNativeOutputBytes    = 384 << 20
)
