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

// ipNetTree indexes blocks of a single address family by a descending series of
// prefix masks. maskKeyList holds one mask per bucket, ordered from the longest
// prefix to the shortest; maskTree maps a block's network address, masked by
// its bucket's mask, to the blocks sharing that key.
type ipNetTree struct {
	cidrs       []*net.IPNet
	maskKeyList []net.IPMask
	maskTree    map[netKey][]net.IPNet
}

// NewIPRanger returns an empty ranger.
func NewIPRanger() *IPRanger {
	return &IPRanger{
		v4: newIPNetTree(),
		v6: newIPNetTree(),
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
	if isV4 {
		r.v4.insertCIDR(network)
	} else {
		r.v6.insertCIDR(network)
	}
	return nil
}

// GenTree builds the lookup structure from the blocks inserted so far. It must
// be called before Contains or OverlapContains, and again after any further
// insert. Calling it repeatedly is safe: each call rebuilds from scratch.
//
// v4bucket and v6bucket set how many buckets each tree is split into. More
// buckets mean fewer blocks scanned on a hit but more map probes on a miss;
// values of zero or less fall back to 2 for IPv4 and 4 for IPv6. Buckets are
// only split at a prefix-length boundary, so the resulting count is an upper
// bound rather than an exact figure.
func (r *IPRanger) GenTree(v4bucket, v6bucket int) {
	if v4bucket <= 0 {
		v4bucket = 2
	}
	if v6bucket <= 0 {
		v6bucket = 4
	}
	r.v4.genTree(v4bucket)
	r.v6.genTree(v6bucket)
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
	if ip.To4() != nil {
		return r.v4.contains(ip)
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
	if ip.To4() != nil {
		return r.v4.overlapContains(ip)
	}
	return r.v6.overlapContains(ip)
}

// ViewMaskKeyList returns the bucket masks of the IPv4 and IPv6 trees, in the
// order lookups consult them. It is intended for inspecting how GenTree
// distributed the blocks; the returned slices must not be modified.
func (r *IPRanger) ViewMaskKeyList() ([]net.IPMask, []net.IPMask) {
	return r.v4.maskKeyList, r.v6.maskKeyList
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

func newIPNetTree() *ipNetTree {
	return &ipNetTree{
		cidrs:    make([]*net.IPNet, 0),
		maskTree: make(map[netKey][]net.IPNet),
	}
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
	for _, mask := range t.maskKeyList {
		key, ok := maskKey(ip, mask)
		if !ok {
			continue
		}
		cidrs, exists := t.maskTree[key]
		if !exists {
			continue
		}
		for i := range cidrs {
			if cidrs[i].Contains(ip) {
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
	for _, mask := range t.maskKeyList {
		key, ok := maskKey(ip, mask)
		if !ok {
			continue
		}
		cidrs := t.maskTree[key]
		for i := range cidrs {
			if cidrs[i].Contains(ip) {
				return true
			}
		}
	}
	return false
}

func (t *ipNetTree) insertCIDR(cidr *net.IPNet) {
	t.cidrs = append(t.cidrs, cidr)
}

// genTree groups the blocks, longest prefix first, into at most buckets chunks
// and indexes each chunk by its shortest prefix.
func (t *ipNetTree) genTree(buckets int) {
	// Rebuild from scratch so repeated calls stay idempotent and pick up any
	// blocks inserted since the last one.
	t.maskKeyList = nil
	t.maskTree = make(map[netKey][]net.IPNet)
	if len(t.cidrs) == 0 {
		return
	}
	t.sortCIDR()

	bucketSize := (len(t.cidrs) + buckets - 1) / buckets
	var chunk []*net.IPNet
	lastOnes, _ := t.cidrs[0].Mask.Size()
	for _, cidr := range t.cidrs {
		ones, _ := cidr.Mask.Size()
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

// solveChunk registers one bucket: every block in chunk is filed under its
// network address masked by the chunk's shortest prefix.
func (t *ipNetTree) solveChunk(chunk []*net.IPNet) {
	ones, bits := chunk[len(chunk)-1].Mask.Size()
	mask := net.CIDRMask(ones, bits)
	t.maskKeyList = append(t.maskKeyList, mask)
	for _, cidr := range chunk {
		key, ok := maskKey(cidr.IP, mask)
		if !ok {
			continue
		}
		t.maskTree[key] = append(t.maskTree[key], *cidr)
	}
}

// sortCIDR orders the blocks by prefix length, longest first.
func (t *ipNetTree) sortCIDR() {
	sort.Slice(t.cidrs, func(i, j int) bool {
		a, _ := t.cidrs[i].Mask.Size()
		b, _ := t.cidrs[j].Mask.Size()
		return a > b
	})
}
