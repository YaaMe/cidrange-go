package cidrange

import (
	"fmt"
	"math/rand"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// addrInSlot returns an address whose leading width bits select slot idx, with
// the remaining bits taken from r.
func addrInSlot(idx uint32, width uint, size int, r uint64) net.IP {
	ip := make(net.IP, size)
	if width == 8 {
		ip[0] = byte(idx)
	} else {
		ip[0], ip[1] = byte(idx>>8), byte(idx)
	}
	for i := int(width / 8); i < size; i++ {
		ip[i] = byte(r >> (8 * uint(i%8)))
	}
	return ip
}

// TestCoarseClaimsHold is the test that matters for this structure.
//
// The coarse index answers without consulting a single block, so a wrong slot
// is a wrong answer with nothing downstream to catch it — and it fails in the
// direction that looks like success: an address wrongly marked empty returns
// false instantly, which is indistinguishable from a fast correct miss.
//
// Both claims are checked against an exhaustive scan of the corpus:
//
//	empty -> no block contains any address in the slot
//	full  -> every address in the slot is inside some block
func TestCoarseClaimsHold(t *testing.T) {
	corpora := map[string]struct {
		nets []*net.IPNet
		size int
	}{
		"aws_v4":    {awsV4Nets, net.IPv4len},
		"aws_v6":    {awsV6Nets, net.IPv6len},
		"synth_10k": {synthNets(t, 10000), net.IPv4len},
	}

	for name, corpus := range corpora {
		for _, width := range []uint{8, 16} {
			t.Run(fmt.Sprintf("%s/width=%d", name, width), func(t *testing.T) {
				packedNets := make([]block, 0, len(corpus.nets))
				for _, n := range corpus.nets {
					canonical, _, ok := normalizeNet(n)
					require.True(t, ok)
					b, ok := packNet(canonical)
					require.True(t, ok)
					packedNets = append(packedNets, b)
				}
				c := newCoarse(packedNets, width)

				rng := rand.New(rand.NewSource(5))
				slots := 1 << width
				step := 1
				if slots > 4096 {
					step = slots / 4096 // sample the wide table
				}

				empty, full, partial := 0, 0, 0
				for idx := 0; idx < slots; idx += step {
					state := c.at(uint64(idx) << (64 - width))
					for probe := 0; probe < 4; probe++ {
						ip := addrInSlot(uint32(idx), width, corpus.size, rng.Uint64())
						actual := linearContains(corpus.nets, ip)
						switch state {
						case coarseEmpty:
							assert.False(t, actual,
								"slot %d marked empty but %s is inside a block", idx, ip)
						case coarseFull:
							assert.True(t, actual,
								"slot %d marked full but %s is in no block", idx, ip)
						}
					}
					switch state {
					case coarseEmpty:
						empty++
					case coarseFull:
						full++
					default:
						partial++
					}
				}
				t.Logf("slots sampled: %d empty, %d full, %d partial", empty, full, partial)
				assert.Greater(t, empty+full, 0, "table discriminates nothing")
			})
		}
	}
}

// TestCoarseCatchAll covers the degenerate case: a /0 block covers every slot,
// so the table must report full everywhere rather than rejecting anything.
func TestCoarseCatchAll(t *testing.T) {
	for _, spec := range []struct {
		cidr string
		ips  []string
	}{
		{"0.0.0.0/0", []string{"0.0.0.0", "8.8.8.8", "255.255.255.255"}},
		{"::/0", []string{"::", "2620::1", "ffff::ffff"}},
	} {
		r := NewIPRanger()
		require.NoError(t, r.InsertCIDRString(spec.cidr))
		r.GenTree(0, 0)
		for _, s := range spec.ips {
			assert.True(t, r.ContainsString(s), "%s should contain %s", spec.cidr, s)
			assert.True(t, r.OverlapContainsString(s), "%s should contain %s", spec.cidr, s)
		}
	}
}

// TestCoarseShortPrefixSpansSlots pins the one arithmetic step that can go
// wrong: a prefix shorter than the table width covers a run of slots, and
// marking only its first would leave the rest wrongly empty.
func TestCoarseShortPrefixSpansSlots(t *testing.T) {
	r := NewIPRanger()
	// 10.0.0.0/6 covers 8.0.0.0 through 11.255.255.255, so it spans four
	// leading-byte values and 1024 of the 16-bit slots.
	require.NoError(t, r.InsertCIDRString("8.0.0.0/6"))
	r.GenTree(0, 0)

	for _, s := range []string{"8.0.0.1", "9.1.2.3", "10.255.255.255", "11.255.255.254"} {
		assert.True(t, r.ContainsString(s), "8.0.0.0/6 should contain %s", s)
	}
	for _, s := range []string{"7.255.255.255", "12.0.0.0"} {
		assert.False(t, r.ContainsString(s), "8.0.0.0/6 should not contain %s", s)
	}
}

// TestCoarseBothWidths exercises the width switch by building corpora either
// side of the threshold and checking answers against a linear scan.
func TestCoarseBothWidths(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	for _, n := range []int{64, 511, 512, 4096} {
		nets := synthNets(t, n)
		r := NewIPRanger()
		insertAll(t, r, nets)
		r.GenTree(0, 0)
		require.NotNil(t, r.v4.coarse)
		assert.Equal(t, coarseWidthFor(n), r.v4.coarse.width)

		for i := 0; i < 3000; i++ {
			ip := sampleIP(rng, nets)
			assert.Equal(t, linearContains(nets, ip), r.OverlapContains(ip),
				"n=%d disagreement for %s", n, ip)
		}
	}
}
