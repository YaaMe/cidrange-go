package cidrange

import (
	"math/big"
	"net"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// referenceRanges merges with math/big rather than the packed 128-bit
// arithmetic countRanges uses, so the two agree only if the fast path's
// shifting and carry handling are right. The boundaries that matter — /0, /64
// where the shift is a full word, and /128 — are where a hand-rolled 128-bit
// path is most likely to be wrong.
func referenceRanges(nets []*net.IPNet) int {
	type r struct{ lo, hi *big.Int }
	rs := make([]r, 0, len(nets))
	for _, n := range nets {
		ip := n.IP
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		lo := new(big.Int).SetBytes(ip)
		ones, bits := n.Mask.Size()
		size := new(big.Int).Lsh(big.NewInt(1), uint(bits-ones))
		hi := new(big.Int).Sub(new(big.Int).Add(lo, size), big.NewInt(1))
		rs = append(rs, r{lo, hi})
	}
	if len(rs) == 0 {
		return 0
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].lo.Cmp(rs[j].lo) < 0 })

	count := 1
	cur := new(big.Int).Set(rs[0].hi)
	one := big.NewInt(1)
	for _, x := range rs[1:] {
		if x.lo.Cmp(new(big.Int).Add(cur, one)) <= 0 {
			if x.hi.Cmp(cur) > 0 {
				cur.Set(x.hi)
			}
			continue
		}
		count++
		cur.Set(x.hi)
	}
	return count
}

func packAll(t *testing.T, nets []*net.IPNet) []block {
	t.Helper()
	out := make([]block, 0, len(nets))
	for _, n := range nets {
		canonical, _, ok := normalizeNet(n)
		require.True(t, ok)
		b, ok := packNet(canonical)
		require.True(t, ok)
		out = append(out, b)
	}
	return out
}

func TestCountRangesAgreesWithBigInt(t *testing.T) {
	cases := map[string][]*net.IPNet{
		"aws_v4":     awsV4Nets,
		"aws_v6":     awsV6Nets,
		"synth_10k":  synthNets(t, 10000),
		"disjoint_4": disjointV4Nets,
		"disjoint_6": disjointV6Nets,
	}
	for name, nets := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, referenceRanges(nets), countRanges(packAll(t, nets)))
		})
	}
}

// TestCountRangesBoundaries covers the prefix lengths where the 128-bit span
// arithmetic shifts by a whole word, plus the merge rules themselves.
func TestCountRangesBoundaries(t *testing.T) {
	cases := []struct {
		name  string
		cidrs []string
		want  int
	}{
		{"single /32", []string{"1.2.3.4/32"}, 1},
		{"single /0", []string{"0.0.0.0/0"}, 1},
		{"v6 /0", []string{"::/0"}, 1},
		{"v6 /64 boundary", []string{"2620::/64"}, 1},
		{"v6 /65 crosses word", []string{"2620::/65"}, 1},
		{"v6 /128 host", []string{"2620::1/128"}, 1},
		{"exact duplicates collapse", []string{"10.0.0.0/8", "10.0.0.0/8"}, 1},
		{"nested collapses", []string{"10.0.0.0/8", "10.1.2.0/24"}, 1},
		{"adjacent joins", []string{"10.0.0.0/9", "10.128.0.0/9"}, 1},
		{"adjacent across octet", []string{"10.0.0.0/8", "11.0.0.0/8"}, 1},
		{"gap stays split", []string{"10.0.0.0/8", "12.0.0.0/8"}, 2},
		{"three into one", []string{"10.0.0.0/10", "10.64.0.0/10", "10.128.0.0/9"}, 1},
		{"v6 adjacent joins", []string{"2620::/33", "2620:0:8000::/33"}, 1},
		{"v6 gap stays split", []string{"2620::/32", "2622::/32"}, 2},
		{"last address does not wrap", []string{"255.255.255.255/32"}, 1},
		{"v6 last address", []string{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nets := make([]*net.IPNet, 0, len(tc.cidrs))
			for _, c := range tc.cidrs {
				_, n, err := net.ParseCIDR(c)
				require.NoError(t, err)
				nets = append(nets, n)
			}
			got := countRanges(packAll(t, nets))
			assert.Equal(t, tc.want, got)
			assert.Equal(t, referenceRanges(nets), got, "reference disagrees too")
		})
	}
}

func TestShapeReportsAWS(t *testing.T) {
	r := NewIPRanger()
	insertAll(t, r, awsV4Nets)
	insertAll(t, r, awsV6Nets)
	r.GenTree(0, 0)

	v4, v6 := r.Shape()

	assert.Equal(t, len(awsV4Nets), v4.Blocks)
	assert.Equal(t, referenceRanges(awsV4Nets), v4.Ranges)
	assert.Equal(t, referenceRanges(awsV6Nets), v6.Ranges)
	assert.Greater(t, v4.Buckets, 0)
	assert.Greater(t, v4.WorstKey, 0)
	assert.LessOrEqual(t, v4.WorstKey, AutoMaxPerKey(v4.Blocks))
	// The AWS IPv4 space is sparse, so most of the coarse index is empty.
	assert.Greater(t, v4.RejectRate, 0.9)

	t.Logf("v4: %s", v4)
	t.Logf("v6: %s", v6)
}

func TestShapeEmpty(t *testing.T) {
	r := NewIPRanger()
	r.GenTree(0, 0)
	v4, v6 := r.Shape()
	assert.Equal(t, 0, v4.Blocks)
	assert.Equal(t, 0, v4.Ranges)
	assert.Equal(t, "no blocks", v4.String())
	assert.Equal(t, "Empty.", v6.Verdict())
}

// TestShapeDiscriminates is the point of the type: two corpora of comparable
// block count must produce visibly different shapes, or it reports nothing
// worth acting on.
func TestShapeDiscriminates(t *testing.T) {
	// Heavily overlapping and adjacent: collapses hard.
	var dense []*net.IPNet
	for i := 0; i < 1000; i++ {
		_, n, err := net.ParseCIDR(net.IPv4(10, byte(i/256), byte(i%256), 0).String() + "/24")
		require.NoError(t, err)
		dense = append(dense, n)
	}
	// Scattered singletons: collapses barely at all.
	var sparse []*net.IPNet
	for i := 0; i < 1000; i++ {
		_, n, err := net.ParseCIDR(net.IPv4(byte(1+i%200), byte(i*7%256), byte(i*13%256), 0).String() + "/32")
		require.NoError(t, err)
		sparse = append(sparse, n)
	}

	shapeOf := func(nets []*net.IPNet) Shape {
		r := NewIPRanger()
		insertAll(t, r, nets)
		r.GenTree(0, 0)
		v4, _ := r.Shape()
		return v4
	}
	d, s := shapeOf(dense), shapeOf(sparse)
	t.Logf("dense:  %s", d)
	t.Logf("sparse: %s", s)

	assert.Less(t, d.Ranges, 20, "adjacent /24s should collapse to a handful of ranges")
	assert.Greater(t, s.Ranges, 900, "scattered /32s should barely collapse")
	assert.NotEqual(t, d.Verdict(), s.Verdict(), "shapes this different should not share a verdict")
}
