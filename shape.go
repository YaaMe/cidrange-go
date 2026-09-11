package cidrange

import (
	"fmt"
	"sort"
)

// u128 is an address as a single unsigned value, so IPv4 and IPv6 ranges can be
// merged by one piece of code. An IPv4 address occupies the top 32 bits, which
// is the same placement block uses, so adjacency is preserved: the block after
// a /24 starts exactly one past where the previous one ended.
type u128 struct{ hi, lo uint64 }

func (a u128) less(b u128) bool {
	return a.hi < b.hi || (a.hi == b.hi && a.lo < b.lo)
}

// next returns a+1, reporting false if that would wrap past the last address.
func (a u128) next() (u128, bool) {
	if a.lo != ^uint64(0) {
		return u128{a.hi, a.lo + 1}, true
	}
	if a.hi == ^uint64(0) {
		return a, false
	}
	return u128{a.hi + 1, 0}, true
}

// span returns the first and last address b covers.
func (b block) span() (lo, hi u128) {
	lo = u128{b.hi, b.lo}
	n := uint(b.ones)
	ones := ^uint64(0)
	if n >= 64 {
		shift := 128 - n
		m := ones
		if shift < 64 {
			m = 1<<shift - 1
		}
		return lo, u128{lo.hi, lo.lo | m}
	}
	shift := 64 - n
	m := ones
	if shift < 64 {
		m = 1<<shift - 1
	}
	return lo, u128{lo.hi | m, ones}
}

// countRanges reports how many disjoint address ranges the blocks collapse to
// once duplicates, nesting and adjacency are merged away.
//
// For a boolean membership query the prefixes themselves carry no information
// the ranges do not, so this is the true size of the problem — and it can be a
// small fraction of the block count. Published provider ranges routinely
// contain the same prefix twice, a /24 inside a /16, and long runs of adjacent
// blocks, all of which vanish here.
func countRanges(blocks []block) int {
	if len(blocks) == 0 {
		return 0
	}
	type span struct{ lo, hi u128 }
	spans := make([]span, len(blocks))
	for i, b := range blocks {
		lo, hi := b.span()
		spans[i] = span{lo, hi}
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].lo.less(spans[j].lo) })

	count := 1
	cur := spans[0].hi
	for _, s := range spans[1:] {
		// Adjacent counts as joined: for membership, [a,b] and [b+1,c] are one
		// range. If cur is the last address there is nothing beyond it.
		limit, ok := cur.next()
		if !ok || !limit.less(s.lo) {
			if cur.less(s.hi) {
				cur = s.hi
			}
			continue
		}
		count++
		cur = s.hi
	}
	return count
}

// Shape describes the inserted blocks in the terms that predict this
// structure's lookup cost.
//
// Block count alone predicts very little. Two sets of a thousand prefixes can
// differ by an order of magnitude depending on how their address space is
// arranged, so these are measurements of the arrangement. Call Shape after
// GenTree; before that the derived fields are zero.
type Shape struct {
	// Blocks is how many blocks were inserted for this family.
	Blocks int

	// Ranges is how many disjoint address ranges they collapse to. See
	// countRanges: this is the size of the underlying membership problem,
	// which for published provider ranges is often far below Blocks.
	Ranges int

	// Buckets is how many buckets GenTree built. A lookup that reaches the
	// buckets probes them in order, so this bounds the probe count.
	Buckets int

	// WorstKey is the most blocks filed under any single bucket key, which is
	// the longest scan a lookup can perform. GenTree's automatic mode bounds
	// this; an explicit bucket count does not.
	WorstKey int

	// RejectRate is the share of the coarse index holding no coverage at all,
	// and so the share of uniformly distributed misses answered by one load.
	// DirectRate is the share wholly covered, answered true by that same load.
	// Together they are the fraction of lookups that never reach a bucket.
	RejectRate float64
	DirectRate float64
}

// Shape reports the shape of the IPv4 and IPv6 blocks currently built.
func (r *IPRanger) Shape() (v4, v6 Shape) {
	return r.v4.shape(), r.v6.shape()
}

func (t *ipNetTree) shape() Shape {
	s := Shape{
		Blocks:  len(t.cidrs),
		Ranges:  countRanges(t.cidrs),
		Buckets: len(t.buckets),
	}
	for i := range t.buckets {
		t.buckets[i].table.forEachGroup(func(blocks []block) {
			if len(blocks) > s.WorstKey {
				s.WorstKey = len(blocks)
			}
		})
	}
	if t.coarse != nil {
		slots := 1 << t.coarse.width
		empty, full := 0, 0
		for idx := 0; idx < slots; idx++ {
			switch t.coarse.at(uint64(idx) << (64 - t.coarse.width)) {
			case coarseEmpty:
				empty++
			case coarseFull:
				full++
			}
		}
		s.RejectRate = float64(empty) / float64(slots)
		s.DirectRate = float64(full) / float64(slots)
	}
	return s
}

// String renders the shape together with what it implies, so the numbers do not
// have to be interpreted from memory. The thresholds come from measurements
// across published provider ranges; see the README.
func (s Shape) String() string {
	if s.Blocks == 0 {
		return "no blocks"
	}
	collapse := 100 * (1 - float64(s.Ranges)/float64(s.Blocks))
	return fmt.Sprintf(
		"%d blocks -> %d disjoint ranges (%.0f%% collapse); %d buckets, worst key %d; "+
			"%.1f%% of misses and %.1f%% of hits answered without reaching a bucket. %s",
		s.Blocks, s.Ranges, collapse, s.Buckets, s.WorstKey,
		100*s.RejectRate, 100*s.DirectRate, s.Verdict())
}

// Verdict summarises whether this structure suits the blocks it holds.
//
// It is deliberately willing to say no: a set that stays fragmented is better
// served by a trie, and that is more useful to know than a number.
//
// It does not recommend a merged-range library for the small case, even though
// merging is what Ranges measures. The obvious one, go4.org/netipx, merges to
// ranges and then binary-searches them, and measured slower than this package
// on every mix — the search costs more in branch misprediction than the smaller
// structure saves. A range array with a direct index would win, but that is not
// something to point a caller at until it exists.
func (s Shape) Verdict() string {
	switch {
	case s.Blocks == 0:
		return "Empty."
	case s.Ranges <= 256:
		return "Well suited: the set is small enough after merging that it sits " +
			"in cache whatever you do."
	case s.Ranges <= 2048 && s.WorstKey <= 64:
		return "Well suited."
	case s.WorstKey > 256:
		return "Poorly suited: some key collects a long scan. Call GenTree(0, 0) " +
			"if you passed an explicit bucket count, and if that does not help, " +
			"prefer a trie such as github.com/gaissmai/bart."
	default:
		return "Fragmented enough that a trie such as github.com/gaissmai/bart " +
			"will likely do better; measure before committing."
	}
}
