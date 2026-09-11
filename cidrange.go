// Package cidrange provides fast membership lookups of an IP address against a
// large set of CIDR blocks.
//
// A ranger is used in two phases. First insert every block with InsertCIDR or
// InsertCIDRString, then call GenTree once to build the lookup structure:
//
//	r := cidrange.NewIPRanger()
//	if err := r.InsertCIDRString("192.168.1.0/24"); err != nil { ... }
//	r.GenTree(2, 4)
//	r.ContainsString("192.168.1.7") // true
//
// After GenTree returns, Contains and OverlapContains only read the structure
// and are safe for concurrent use. Blocks inserted after GenTree do not take
// effect until GenTree is called again; GenTree may be called repeatedly and
// rebuilds from scratch each time.
//
// Contains is the fast path but requires the inserted blocks to be
// non-overlapping. OverlapContains carries no such requirement and works with
// any set of blocks, at the cost of probing every bucket.
package cidrange

import (
	"fmt"
	"math"
	"net"
	"sort"
)

// netKey is a masked IP used as a map key. IPv4 keys occupy the leading four
// bytes and leave the rest zero. A fixed-size array rather than a string keeps
// the lookup path free of allocations.
type netKey [net.IPv6len]byte

// IPRanger holds a set of CIDR blocks, kept in separate IPv4 and IPv6 trees.
//
// The zero value is not usable; create one with NewIPRanger.
type IPRanger struct {
	v4 *ipNetTree
	v6 *ipNetTree
}

// bucket indexes one group of blocks by their network address masked to the
// group's shortest prefix.
type bucket struct {
	mask  net.IPMask
	table *blockTable
}

// ipNetTree indexes blocks of a single address family as a series of buckets,
// ordered from the longest prefix mask to the shortest.
//
// Each bucket owns its table. One table shared across buckets would conflate
// them: a netKey records masked address bytes but not the mask it was masked
// with, so the key for 83.0.0.0/13 and for 83.0.0.0/8 are identical and the
// two buckets' block lists would merge - lengthening every scan that touches
// either, and making the per-key population that auto mode bounds unknowable
// at build time.
type ipNetTree struct {
	// bits is the address width of this tree's family, 32 or 128. A packed
	// block does not carry its family, and the tree is the level that knows.
	bits    int
	cidrs   []block
	buckets []bucket
	// coarse short-circuits lookups that a direct-indexed summary of the
	// address space can already answer. Nil until GenTree has run.
	coarse *coarse
}

// NewIPRanger returns an empty ranger.
func NewIPRanger() *IPRanger {
	return &IPRanger{
		v4: newIPNetTree(net.IPv4len * 8),
		v6: newIPNetTree(net.IPv6len * 8),
	}
}

// InsertCIDRString parses cidr and adds it to the ranger. It returns an error
// if cidr is not a valid CIDR block. The block is not visible to lookups until
// GenTree is called.
func (r *IPRanger) InsertCIDRString(cidr string) error {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	return r.InsertCIDR(network)
}

// InsertCIDR adds cidr to the ranger. It returns an error if cidr is nil or
// malformed. The block is not visible to lookups until GenTree is called.
func (r *IPRanger) InsertCIDR(cidr *net.IPNet) error {
	if cidr == nil {
		return fmt.Errorf("cidrange: nil *net.IPNet")
	}
	network, isV4, ok := normalizeNet(cidr)
	if !ok {
		return fmt.Errorf("cidrange: malformed network: %d-byte IP with %d-byte mask", len(cidr.IP), len(cidr.Mask))
	}
	packed, ok := packNet(network)
	if !ok {
		return fmt.Errorf("cidrange: malformed network: %s", network)
	}
	if isV4 {
		r.v4.insertBlock(packed)
	} else {
		r.v6.insertBlock(packed)
	}
	return nil
}

// GenTree builds the lookup structure from the blocks inserted so far. It must
// be called before Contains or OverlapContains, and again after any further
// insert. Calling it repeatedly is safe: each call rebuilds from scratch.
//
// v4bucket and v6bucket set how many buckets each tree is split into. More
// buckets mean fewer blocks scanned on a hit but more map probes on a miss.
// Buckets are only split at a prefix-length boundary, so the count is an upper
// bound rather than an exact figure — ViewMaskKeyList reports what was
// actually built.
//
// Pass zero or less for either family to size that family automatically. Auto
// mode does not pick a count at all: it places bucket boundaries so that no
// single key collects more than AutoMaxPerKey blocks, which is the quantity
// a lookup actually scans. Prefer it unless you have measured a better fixed
// count for your own data.
func (r *IPRanger) GenTree(v4bucket, v6bucket int) {
	r.v4.genTree(v4bucket)
	r.v6.genTree(v6bucket)
}

// AutoMaxPerKey returns the ceiling auto mode places on how many blocks may
// share one bucket key, for a family holding n blocks.
//
// A lookup costs one map probe per bucket plus one comparison per block
// sharing the query's key, so the ceiling trades the two against each other:
// lowering it splits more eagerly, buying a shorter scan with an extra probe
// on every lookup. The balance moves with n. A small set yields few buckets
// and absorbs a longer scan cheaply; a large one cannot, since an over-long
// scan is the failure this mode exists to prevent.
//
// Measured optima across synthetic BGP-shaped sets of 1e3 to 1e6 prefixes and
// the AWS ranges fit roughly 1024/sqrt(n), clamped to [8, 64]. That is an
// empirical fit on two corpora, not a derivation — measure your own data and
// pass an explicit bucket count to GenTree if the difference matters to you.
func AutoMaxPerKey(n int) int {
	const minPerKey, maxPerKey = 8, 64
	if n <= 0 {
		return minPerKey
	}
	c := int(1024 / math.Sqrt(float64(n)))
	if c < minPerKey {
		return minPerKey
	}
	if c > maxPerKey {
		return maxPerKey
	}
	return c
}

// ContainsString reports whether ip falls inside one of the inserted blocks. It
// returns false if ip is not a valid IP address.
//
// It assumes the inserted blocks do not overlap: once a bucket is found to hold
// the masked key for ip, no shorter-prefix bucket is consulted. Use
// OverlapContainsString for a set that may contain nested or duplicate blocks.
func (r *IPRanger) ContainsString(ip string) bool {
	return r.Contains(net.ParseIP(ip))
}

// Contains reports whether ip falls inside one of the inserted blocks. It
// returns false if ip is nil.
//
// It assumes the inserted blocks do not overlap; see ContainsString.
func (r *IPRanger) Contains(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		return r.v4.contains(ip4)
	}
	return r.v6.contains(ip)
}

// OverlapContainsString reports whether ip falls inside one of the inserted
// blocks, probing every bucket so that overlapping, nested or duplicate blocks
// are handled correctly. It returns false if ip is not a valid IP address.
func (r *IPRanger) OverlapContainsString(ip string) bool {
	return r.OverlapContains(net.ParseIP(ip))
}

// OverlapContains reports whether ip falls inside one of the inserted blocks,
// probing every bucket so that overlapping, nested or duplicate blocks are
// handled correctly. It returns false if ip is nil.
func (r *IPRanger) OverlapContains(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		return r.v4.overlapContains(ip4)
	}
	return r.v6.overlapContains(ip)
}

// ViewMaskKeyList returns the bucket masks of the IPv4 and IPv6 trees, in the
// order lookups consult them. It is intended for inspecting how GenTree
// distributed the blocks. The slices are freshly built, but the masks within
// them are shared with the ranger and must not be modified.
func (r *IPRanger) ViewMaskKeyList() ([]net.IPMask, []net.IPMask) {
	return r.v4.masks(), r.v6.masks()
}

// normalizeNet reduces cidr to the canonical form for its family: a 4-byte IP
// and 4-byte mask for IPv4, 16-byte for IPv6. This matches how
// net.IPNet.Contains interprets a block, and keeps every entry in a tree
// directly comparable. The IP and mask are copied so later mutation of cidr
// cannot corrupt the tree.
func normalizeNet(cidr *net.IPNet) (network *net.IPNet, isV4, ok bool) {
	if ip4 := cidr.IP.To4(); ip4 != nil {
		mask := cidr.Mask
		if len(mask) == net.IPv6len {
			// A 16-byte mask on a v4-mapped address covers the v4 bits in its
			// trailing four bytes, as net.networkNumberAndMask also assumes.
			mask = mask[12:]
		}
		if len(mask) != net.IPv4len {
			return nil, false, false
		}
		return &net.IPNet{
			IP:   append(net.IP(nil), ip4...),
			Mask: append(net.IPMask(nil), mask...),
		}, true, true
	}
	if len(cidr.IP) != net.IPv6len || len(cidr.Mask) != net.IPv6len {
		return nil, false, false
	}
	return &net.IPNet{
		IP:   append(net.IP(nil), cidr.IP...),
		Mask: append(net.IPMask(nil), cidr.Mask...),
	}, false, true
}

// maskKey computes the map key for ip under mask. It reports false when ip does
// not belong to the address family mask was built for.
func maskKey(ip net.IP, mask net.IPMask) (netKey, bool) {
	var key netKey
	switch len(mask) {
	case net.IPv4len:
		ip4 := ip.To4()
		if ip4 == nil {
			return key, false
		}
		for i := 0; i < net.IPv4len; i++ {
			key[i] = ip4[i] & mask[i]
		}
	case net.IPv6len:
		if len(ip) != net.IPv6len {
			return key, false
		}
		for i := 0; i < net.IPv6len; i++ {
			key[i] = ip[i] & mask[i]
		}
	default:
		return key, false
	}
	return key, true
}

func newIPNetTree(bits int) *ipNetTree {
	return &ipNetTree{bits: bits, cidrs: make([]block, 0)}
}

// masks returns the bucket masks in lookup order.
func (t *ipNetTree) masks() []net.IPMask {
	out := make([]net.IPMask, len(t.buckets))
	for i := range t.buckets {
		out[i] = t.buckets[i].mask
	}
	return out
}

// contains walks the buckets from the longest prefix to the shortest and stops
// at the first bucket holding ip's masked key.
//
// The early stop is sound only for non-overlapping blocks. If a bucket with
// mask m holds that key, some block c in it lies inside the /m supernet S of
// ip. Any block d in a later bucket has a prefix shorter than m, so d would
// have to contain all of S, and therefore c, in order to contain ip - which the
// non-overlap assumption rules out.
func (t *ipNetTree) contains(ip net.IP) bool {
	if len(ip)*8 != t.bits {
		return false
	}
	if t.coarse != nil {
		switch t.coarse.atIP(ip) {
		case coarseEmpty:
			return false
		case coarseFull:
			return true
		}
	}

	var hi, lo uint64
	packed := false

	for i := range t.buckets {
		b := &t.buckets[i]
		key, ok := maskKey(ip, b.mask)
		if !ok {
			continue
		}
		blocks := b.table.find(key)
		if len(blocks) == 0 {
			continue
		}
		// Pack lazily. A lookup that never reaches a populated bucket should
		// not pay for it, and most misses never do.
		if !packed {
			hi, lo, ok = packIP(ip)
			if !ok {
				return false
			}
			packed = true
		}
		for j := range blocks {
			if blocks[j].contains(hi, lo) {
				return true
			}
		}
		return false
	}
	return false
}

// overlapContains probes every bucket, making no assumption about the blocks
// being disjoint.
func (t *ipNetTree) overlapContains(ip net.IP) bool {
	if len(ip)*8 != t.bits {
		return false
	}
	if t.coarse != nil {
		switch t.coarse.atIP(ip) {
		case coarseEmpty:
			return false
		case coarseFull:
			return true
		}
	}

	var hi, lo uint64
	packed := false

	for i := range t.buckets {
		b := &t.buckets[i]
		key, ok := maskKey(ip, b.mask)
		if !ok {
			continue
		}
		blocks := b.table.find(key)
		if len(blocks) == 0 {
			continue
		}
		if !packed {
			hi, lo, ok = packIP(ip)
			if !ok {
				return false
			}
			packed = true
		}
		for j := range blocks {
			if blocks[j].contains(hi, lo) {
				return true
			}
		}
	}
	return false
}

func (t *ipNetTree) insertBlock(b block) {
	t.cidrs = append(t.cidrs, b)
}

// genTree builds the buckets. A positive buckets splits into that many chunks
// by block count; zero or less bounds the per-key population instead.
func (t *ipNetTree) genTree(buckets int) {
	// Rebuild from scratch so repeated calls stay idempotent and pick up any
	// blocks inserted since the last one.
	t.buckets = nil
	t.coarse = nil
	if len(t.cidrs) == 0 {
		return
	}
	t.sortCIDR()
	t.coarse = newCoarse(t.cidrs, coarseWidthFor(len(t.cidrs)))

	if buckets > 0 {
		t.genTreeFixed(buckets)
		return
	}
	t.genTreeAuto(AutoMaxPerKey(len(t.cidrs)))
}

// genTreeFixed groups the blocks, longest prefix first, into at most buckets
// chunks of roughly equal block count.
func (t *ipNetTree) genTreeFixed(buckets int) {
	bucketSize := (len(t.cidrs) + buckets - 1) / buckets
	var chunk []block
	lastOnes := int(t.cidrs[0].ones)
	for _, cidr := range t.cidrs {
		ones := int(cidr.ones)
		if ones != lastOnes {
			// A chunk is keyed by its shortest prefix, so blocks of equal
			// prefix length must not be split across chunks. That makes a
			// prefix-length change the only point at which a chunk may close.
			if len(chunk) >= bucketSize {
				t.solveChunk(chunk)
				chunk = nil
			}
			lastOnes = ones
		}
		chunk = append(chunk, cidr)
	}
	if len(chunk) > 0 {
		t.solveChunk(chunk)
	}
}

// genTreeAuto places bucket boundaries by bounding the per-key population
// rather than the block count.
//
// Splitting by block count leaves the size of the final chunk to chance: it is
// whatever remains after the last flush, and it is keyed by the shortest
// prefix in the whole set, so an unlucky split collapses a large tail into a
// handful of keys. Measured on a million BGP-shaped prefixes, four buckets
// left 698 blocks under one key while three left 200 and six left 63 — a 10x
// swing in lookup cost from a parameter that looks monotonic and is not.
//
// This walks the prefix-length runs from longest to shortest, extending the
// current chunk while the worst key stays within maxPerKey and closing it when
// the next run would push past. Extending a chunk can only shorten its mask
// and therefore only merge keys, so the worst key is monotonic in the walk and
// a greedy pass suffices.
func (t *ipNetTree) genTreeAuto(maxPerKey int) {
	chunkStart := 0
	counts := make(map[netKey]int)

	for _, r := range t.prefixRuns() {
		trial, worst := remask(counts, t.cidrs[r.start:r.end], r.ones, t.bits)
		if chunkStart < r.start && worst > maxPerKey {
			t.solveChunk(t.cidrs[chunkStart:r.start])
			chunkStart = r.start
			counts, _ = remask(nil, t.cidrs[r.start:r.end], r.ones, t.bits)
			continue
		}
		counts = trial
	}
	if chunkStart < len(t.cidrs) {
		t.solveChunk(t.cidrs[chunkStart:])
	}
}

// prefixRun is a maximal span of t.cidrs sharing one prefix length. A chunk is
// keyed by its shortest prefix, so a run is the smallest unit a chunk boundary
// may fall between.
type prefixRun struct {
	ones       int
	start, end int
}

func (t *ipNetTree) prefixRuns() []prefixRun {
	var runs []prefixRun
	for i := 0; i < len(t.cidrs); {
		ones := int(t.cidrs[i].ones)
		j := i + 1
		for j < len(t.cidrs) {
			if int(t.cidrs[j].ones) != ones {
				break
			}
			j++
		}
		runs = append(runs, prefixRun{ones: ones, start: i, end: j})
		i = j
	}
	return runs
}

// remask re-keys counts at a prefix length of ones, folds in the blocks of
// extra, and reports the largest resulting key population.
//
// Re-keying existing keys rather than re-deriving them from the blocks is what
// keeps the walk cheap: masking is monotonic, so a key already masked to a
// longer prefix can be masked again, and the work is proportional to the
// number of distinct keys rather than the number of blocks.
func remask(counts map[netKey]int, extra []block, ones, bits int) (map[netKey]int, int) {
	mask := net.CIDRMask(ones, bits)
	out := make(map[netKey]int, len(counts)+len(extra))
	for key, n := range counts {
		for i := 0; i < len(mask); i++ {
			key[i] &= mask[i]
		}
		out[key] += n
	}
	for _, blk := range extra {
		if key, ok := blk.maskKey(mask); ok {
			out[key]++
		}
	}
	worst := 0
	for _, n := range out {
		if n > worst {
			worst = n
		}
	}
	return out, worst
}

// solveChunk registers one bucket: every block in chunk is filed under its
// network address masked by the chunk's shortest prefix.
func (t *ipNetTree) solveChunk(chunk []block) {
	mask := net.CIDRMask(int(chunk[len(chunk)-1].ones), t.bits)

	// Group by key first. A map is fine here: this runs once, at build time.
	index := make(map[netKey]int, len(chunk))
	keys := make([]netKey, 0, len(chunk))
	groups := make([][]block, 0, len(chunk))
	for _, blk := range chunk {
		key, ok := blk.maskKey(mask)
		if !ok {
			continue
		}
		i, seen := index[key]
		if !seen {
			i = len(keys)
			index[key] = i
			keys = append(keys, key)
			groups = append(groups, nil)
		}
		groups[i] = append(groups[i], blk)
	}

	t.buckets = append(t.buckets, bucket{
		mask:  mask,
		table: newBlockTable(keys, groups, blockTableSlotsPerKey),
	})
}

// sortCIDR orders the blocks by prefix length, longest first.
func (t *ipNetTree) sortCIDR() {
	sort.Slice(t.cidrs, func(i, j int) bool {
		return t.cidrs[i].ones > t.cidrs[j].ones
	})
}
