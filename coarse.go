package cidrange

// coarse is a direct-indexed summary of the leading bits of the address space,
// consulted before any bucket.
//
// It exists because the bucket structure is weakest exactly where a trie is
// strongest. A miss has to probe every bucket before it can be ruled out, and
// an address covered by a short prefix still pays a full hash lookup. A trie
// answers both from its root node. This is that root node, kept as a flat array
// rather than a tree: the part of the trie idea worth borrowing, without the
// per-level dependent loads that make a trie slow on deep matches.
//
// Each slot holds two bits summarising one prefix of the address space:
//
//	coarseEmpty   no block covers any address here          -> false, immediately
//	coarseFull    some block covers every address here      -> true, immediately
//	coarsePartial blocks exist here but none covers it all  -> consult the buckets
//
// Only coarsePartial reaches the buckets, so the structure below is left to do
// the work it is actually good at.
type coarse struct {
	// width is the number of leading address bits the table indexes, 8 or 16.
	width uint
	bits  []uint64
}

const (
	coarseEmpty   = 0
	coarsePartial = 1
	coarseFull    = 2
)

// coarseWidthFor picks the table width for a family holding n blocks.
//
// The table costs a fixed 2 bits per slot regardless of corpus size: 64 bytes
// at 8 bits, 16 KiB at 16 bits. The wider one discriminates far better — on the
// AWS ranges it leaves 0.7% of slots occupied against 12.9% — but 16 KiB is a
// silly overhead on a corpus of a few dozen blocks, which would otherwise
// occupy a few KiB in total.
func coarseWidthFor(n int) uint {
	if n < 512 {
		return 8
	}
	return 16
}

// newCoarse builds the table from the blocks of one tree.
func newCoarse(blocks []block, width uint) *coarse {
	c := &coarse{width: width, bits: make([]uint64, (1<<width)*2/64)}
	for _, b := range blocks {
		base := uint32(b.hi >> (64 - width))

		if uint(b.ones) >= width {
			// The block lies inside one slot and covers only part of it,
			// unless something else already covers the whole slot.
			c.raise(base, coarsePartial)
			continue
		}
		// A prefix shorter than the table's width spans a run of slots and
		// covers every one of them completely. Missing any of these is the one
		// way this table can produce a wrong answer, so the span is computed
		// from the prefix length rather than assumed.
		span := uint32(1)<<(width-uint(b.ones)) - 1
		for v := base; v <= base|span; v++ {
			c.raise(v, coarseFull)
		}
	}
	return c
}

// raise promotes slot idx to at least state. Full outranks partial: a slot that
// is wholly covered stays wholly covered however many narrower blocks also sit
// inside it.
func (c *coarse) raise(idx uint32, state uint64) {
	word, shift := idx>>5, (idx&31)*2
	if cur := (c.bits[word] >> shift) & 3; cur >= state {
		return
	}
	c.bits[word] = c.bits[word]&^(3<<shift) | state<<shift
}

// at returns the state of the slot holding the address whose leading bits are
// hi's most significant ones. Used when building and in tests.
func (c *coarse) at(hi uint64) uint64 {
	idx := uint32(hi >> (64 - c.width))
	return (c.bits[idx>>5] >> ((idx & 31) * 2)) & 3
}

// atIP is the lookup-path form. It reads the leading bytes straight from the
// address rather than packing it first, so a rejected miss never pays for the
// packing it would not have used. ip must already be in canonical form for its
// family, which is what Contains passes down.
func (c *coarse) atIP(ip []byte) uint64 {
	idx := uint32(ip[0])
	if c.width == 16 {
		idx = idx<<8 | uint32(ip[1])
	}
	return (c.bits[idx>>5] >> ((idx & 31) * 2)) & 3
}
