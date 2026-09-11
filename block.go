package cidrange

import (
	"encoding/binary"
	"net"
)

// block is a CIDR block with its network address packed inline.
//
// The alternative, storing net.IPNet by value, costs 48 bytes of slice headers
// that hold no address at all — just two pointers into separately allocated
// backing arrays. Scanning a bucket then chases two pointers per candidate,
// and net.IPNet.Contains re-derives the canonical form of the block on every
// call. Packing the address into two words removes both: 24 bytes, no
// indirection, and a containment test that is a shift and a compare.
//
// IPv4 addresses are left-aligned into the top 32 bits of hi, so a prefix
// length always counts from the most significant bit and one containment
// routine serves both families.
type block struct {
	hi, lo uint64
	ones   uint8
}

// packIP packs an address into two words. It reports false for an address that
// is neither 4 nor 16 bytes, which includes the nil returned by a failed
// net.ParseIP.
func packIP(ip net.IP) (hi, lo uint64, ok bool) {
	if ip4 := ip.To4(); ip4 != nil {
		return uint64(binary.BigEndian.Uint32(ip4)) << 32, 0, true
	}
	if len(ip) != net.IPv6len {
		return 0, 0, false
	}
	return binary.BigEndian.Uint64(ip[:8]), binary.BigEndian.Uint64(ip[8:]), true
}

// packNet packs a network, which normalizeNet has already reduced to the
// canonical form for its family.
func packNet(cidr *net.IPNet) (block, bool) {
	hi, lo, ok := packIP(cidr.IP)
	if !ok {
		return block{}, false
	}
	ones, _ := cidr.Mask.Size()
	if len(cidr.Mask) == net.IPv4len {
		// A 4-byte mask counts from bit 0 of the address, and the address sits
		// in the top 32 bits of hi, so the prefix length carries over as is.
		if ones < 0 || ones > 32 {
			return block{}, false
		}
	} else if ones < 0 || ones > 128 {
		return block{}, false
	}
	return block{hi: hi, lo: lo, ones: uint8(ones)}, true
}

// contains reports whether the packed address (hi, lo) falls inside b.
//
// The boundaries need no special casing. Go defines a shift of 64 or more on a
// uint64 as producing zero — unlike C, where it is undefined — so a /0 block
// compares zero against a zero network and matches everything.
func (b block) contains(hi, lo uint64) bool {
	n := uint(b.ones)
	if n <= 64 {
		shift := 64 - n
		return hi>>shift<<shift == b.hi
	}
	if hi != b.hi {
		return false
	}
	shift := 128 - n
	return lo>>shift<<shift == b.lo
}
