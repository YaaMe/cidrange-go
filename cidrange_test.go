package cidrange

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBasicIP(t *testing.T) {
	ipranger := NewIPRanger()
	require.NoError(t, ipranger.InsertCIDRString("192.168.1.0/24"))
	require.NoError(t, ipranger.InsertCIDRString("128.168.1.0/24"))
	require.NoError(t, ipranger.InsertCIDRString("52.68.93.4/31"))
	ipranger.GenTree(1, 1)
	assert.True(t, ipranger.ContainsString("128.168.1.0"))
	assert.False(t, ipranger.ContainsString("192.168.2.0"))
	assert.False(t, ipranger.ContainsString("52.68.93.254"))
}

func TestBenchKey(t *testing.T) {
	ipranger := NewIPRanger()
	insertAll(t, ipranger, awsV4Nets)
	insertAll(t, ipranger, awsV6Nets)
	ipranger.GenTree(2, 2)
	// The AWS set contains nested blocks, so OverlapContains is the method
	// whose contract it satisfies.
	assert.True(t, ipranger.OverlapContainsString("52.95.110.1"))
	assert.True(t, ipranger.OverlapContainsString("2620:107:300f::36b7:ff81"))
	assert.False(t, ipranger.OverlapContainsString("123.123.123.123"))
	assert.False(t, ipranger.OverlapContainsString("2620::ffff"))
}

// TestEveryInsertedBlockIsFound is the regression test for a bug in genTree
// that silently dropped one block at every prefix-length boundary: the block
// that closed a chunk was never filed into the mask tree, so lookups inside it
// returned false. It is a property the structure must hold for any input, which
// is why it is asserted over the whole corpus rather than a handful of cases.
func TestEveryInsertedBlockIsFound(t *testing.T) {
	for _, buckets := range []int{0, 1, 2, 4, 8, 16} {
		t.Run(bucketName(buckets), func(t *testing.T) {
			overlapping := NewIPRanger()
			insertAll(t, overlapping, awsV4Nets)
			insertAll(t, overlapping, awsV6Nets)
			overlapping.GenTree(buckets, buckets)

			for _, n := range append(append([]*net.IPNet{}, awsV4Nets...), awsV6Nets...) {
				assert.True(t, overlapping.OverlapContains(n.IP),
					"OverlapContains missed the network address of %s", n)
			}

			// Contains only promises to work on a disjoint set, so it gets one.
			disjoint := NewIPRanger()
			insertAll(t, disjoint, disjointV4Nets)
			insertAll(t, disjoint, disjointV6Nets)
			disjoint.GenTree(buckets, buckets)

			for _, n := range append(append([]*net.IPNet{}, disjointV4Nets...), disjointV6Nets...) {
				assert.True(t, disjoint.Contains(n.IP),
					"Contains missed the network address of %s", n)
			}
		})
	}
}

// TestAgreesWithLinearScan cross-checks both lookup methods against the
// definition they are an optimisation of: a linear scan calling
// net.IPNet.Contains on every block.
func TestAgreesWithLinearScan(t *testing.T) {
	const seed = 20240611
	rng := rand.New(rand.NewSource(seed))

	overlapping := NewIPRanger()
	insertAll(t, overlapping, awsV4Nets)
	insertAll(t, overlapping, awsV6Nets)
	overlapping.GenTree(2, 4)
	allNets := append(append([]*net.IPNet{}, awsV4Nets...), awsV6Nets...)

	disjoint := NewIPRanger()
	insertAll(t, disjoint, disjointV4Nets)
	insertAll(t, disjoint, disjointV6Nets)
	disjoint.GenTree(2, 4)
	disjointNets := append(append([]*net.IPNet{}, disjointV4Nets...), disjointV6Nets...)

	hits, misses := 0, 0
	for i := 0; i < 20000; i++ {
		ip := sampleIP(rng, allNets)
		if linearContains(allNets, ip) {
			hits++
		} else {
			misses++
		}
		assert.Equal(t, linearContains(allNets, ip), overlapping.OverlapContains(ip),
			"OverlapContains disagrees with a linear scan for %s", ip)
		assert.Equal(t, linearContains(disjointNets, ip), disjoint.Contains(ip),
			"Contains disagrees with a linear scan for %s", ip)
	}
	// A run that never hits, or never misses, would pass vacuously.
	assert.Greater(t, hits, 0, "no sampled IP was inside any block")
	assert.Greater(t, misses, 0, "every sampled IP was inside a block")
}

// TestBucketCountDoesNotChangeResults pins the documented role of the bucket
// parameters: they trade lookup speed against memory, never correctness.
func TestBucketCountDoesNotChangeResults(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	allNets := append(append([]*net.IPNet{}, awsV4Nets...), awsV6Nets...)

	probes := make([]net.IP, 0, 2000)
	for i := 0; i < 2000; i++ {
		probes = append(probes, sampleIP(rng, allNets))
	}

	var reference []bool
	for _, buckets := range []int{0, 1, 2, 3, 5, 8, 13} {
		r := NewIPRanger()
		insertAll(t, r, awsV4Nets)
		insertAll(t, r, awsV6Nets)
		r.GenTree(buckets, buckets)

		got := make([]bool, len(probes))
		for i, ip := range probes {
			got[i] = r.OverlapContains(ip)
		}
		if reference == nil {
			reference = got
			continue
		}
		assert.Equal(t, reference, got, "results changed at %d buckets", buckets)
	}
}

// TestAutoBoundsPerKeyPopulation pins the guarantee auto mode makes: no key
// collects more than AutoMaxPerKey blocks. That population is exactly what
// a lookup scans linearly, so it is the thing worth asserting - a bucket count
// is not, because the same count yields wildly different populations depending
// on where the split lands.
func TestAutoBoundsPerKeyPopulation(t *testing.T) {
	corpora := map[string][]*net.IPNet{
		"aws_v4":     awsV4Nets,
		"aws_v6":     awsV6Nets,
		"synth_10k":  synthNets(t, 10000),
		"synth_100k": synthNets(t, 100000),
	}

	for name, nets := range corpora {
		t.Run(name, func(t *testing.T) {
			r := NewIPRanger()
			insertAll(t, r, nets)
			r.GenTree(0, 0)

			for _, tree := range []*ipNetTree{r.v4, r.v6} {
				for _, b := range tree.buckets {
					ones, _ := b.mask.Size()
					b.table.forEachGroup(func(blocks []block) {
						assert.LessOrEqual(t, len(blocks), AutoMaxPerKey(len(tree.cidrs)),
							"a key in the /%d bucket holds %d blocks, over the auto-mode ceiling",
							ones, len(blocks))
					})
				}
			}
		})
	}
}

// TestAutoAvoidsCatastrophicSplits guards the reason auto mode exists.
//
// Splitting by block count leaves the tail's size to chance, so some fixed
// counts collapse a large remainder under one key - and which counts do that
// is not predictable from the count, nor monotonic in it. Auto must stay
// within its ceiling on a corpus where fixed counts do not.
//
// Auto is not required to beat every fixed count on this metric: driving the
// worst key to its minimum means maximising buckets, which costs a map probe
// per bucket on every lookup. Staying under the ceiling is the guarantee.
func TestAutoAvoidsCatastrophicSplits(t *testing.T) {
	nets := synthNets(t, 100000)

	worstKey := func(buckets int) (worst, nbuckets int) {
		r := NewIPRanger()
		insertAll(t, r, nets)
		r.GenTree(buckets, buckets)
		for _, b := range r.v4.buckets {
			b.table.forEachGroup(func(blocks []block) {
				if len(blocks) > worst {
					worst = len(blocks)
				}
			})
		}
		return worst, len(r.v4.buckets)
	}

	auto, autoN := worstKey(0)
	assert.LessOrEqual(t, auto, AutoMaxPerKey(len(nets)),
		"auto left %d blocks under one key", auto)
	t.Logf("auto: %d buckets, worst key %d blocks (ceiling %d)", autoN, auto, AutoMaxPerKey(len(nets)))

	overCeiling := 0
	for _, buckets := range []int{2, 3, 4, 6, 8, 12, 16} {
		fixed, _ := worstKey(buckets)
		if fixed > AutoMaxPerKey(len(nets)) {
			overCeiling++
		}
		t.Logf("  %2d buckets: worst key %d blocks", buckets, fixed)
	}
	assert.Greater(t, overCeiling, 0,
		"corpus does not discriminate: every fixed count stayed within the ceiling too")
}

func TestInsertRejectsBadInput(t *testing.T) {
	r := NewIPRanger()

	assert.Error(t, r.InsertCIDRString("not-a-cidr"))
	assert.Error(t, r.InsertCIDRString("192.168.1.0/33"))
	assert.Error(t, r.InsertCIDRString(""))
	assert.Error(t, r.InsertCIDR(nil))
	assert.Error(t, r.InsertCIDR(&net.IPNet{IP: net.IP{1, 2, 3}, Mask: net.CIDRMask(24, 32)}))

	// Nothing above should have landed in the tree, and none of it should have
	// panicked on the way.
	r.GenTree(1, 1)
	assert.False(t, r.ContainsString("192.168.1.1"))
}

func TestGenTreeIsIdempotent(t *testing.T) {
	r := NewIPRanger()
	require.NoError(t, r.InsertCIDRString("192.168.1.0/24"))
	require.NoError(t, r.InsertCIDRString("10.0.0.0/8"))

	r.GenTree(1, 1)
	v4First, v6First := r.ViewMaskKeyList()
	firstV4, firstV6 := len(v4First), len(v6First)

	for i := 0; i < 3; i++ {
		r.GenTree(1, 1)
		v4, v6 := r.ViewMaskKeyList()
		assert.Equal(t, firstV4, len(v4), "IPv4 bucket count grew on rebuild %d", i+1)
		assert.Equal(t, firstV6, len(v6), "IPv6 bucket count grew on rebuild %d", i+1)
		assert.True(t, r.ContainsString("192.168.1.7"))
		assert.False(t, r.ContainsString("192.168.2.7"))
	}
}

func TestInsertAfterGenTreeNeedsRebuild(t *testing.T) {
	r := NewIPRanger()
	require.NoError(t, r.InsertCIDRString("192.168.1.0/24"))
	r.GenTree(1, 1)
	assert.True(t, r.ContainsString("192.168.1.7"))

	require.NoError(t, r.InsertCIDRString("10.0.0.0/8"))
	assert.False(t, r.ContainsString("10.1.2.3"), "insert must not take effect before GenTree")

	r.GenTree(1, 1)
	assert.True(t, r.ContainsString("10.1.2.3"), "insert must take effect after GenTree")
	assert.True(t, r.ContainsString("192.168.1.7"), "rebuild must keep earlier blocks")
}

func TestLookupBeforeGenTree(t *testing.T) {
	r := NewIPRanger()
	require.NoError(t, r.InsertCIDRString("192.168.1.0/24"))
	assert.False(t, r.ContainsString("192.168.1.7"))
	assert.False(t, r.OverlapContainsString("192.168.1.7"))
}

// TestV4MappedFormsAgree covers the several spellings of the same IPv4 network
// and address. All of them must reach the IPv4 tree and agree.
func TestV4MappedFormsAgree(t *testing.T) {
	r := NewIPRanger()
	require.NoError(t, r.InsertCIDRString("192.168.1.0/24"))
	// The same network built by hand in v4-mapped IPv6 form.
	require.NoError(t, r.InsertCIDR(&net.IPNet{
		IP:   net.ParseIP("::ffff:10.0.0.0"),
		Mask: net.CIDRMask(96+8, 128),
	}))
	r.GenTree(1, 1)

	assert.True(t, r.Contains(net.ParseIP("192.168.1.7")))
	assert.True(t, r.Contains(net.IP{192, 168, 1, 7}))
	assert.True(t, r.Contains(net.ParseIP("::ffff:192.168.1.7")))
	assert.True(t, r.Contains(net.ParseIP("10.1.2.3")))
	assert.True(t, r.Contains(net.ParseIP("::ffff:10.1.2.3")))
	assert.False(t, r.Contains(net.ParseIP("11.1.2.3")))
}

func TestNilAndInvalidLookups(t *testing.T) {
	r := NewIPRanger()
	require.NoError(t, r.InsertCIDRString("192.168.1.0/24"))
	require.NoError(t, r.InsertCIDRString("2620::/32"))
	r.GenTree(1, 1)

	assert.False(t, r.Contains(nil))
	assert.False(t, r.OverlapContains(nil))
	assert.False(t, r.ContainsString("not-an-ip"))
	assert.False(t, r.OverlapContainsString(""))
	assert.False(t, r.Contains(net.IP{1, 2, 3}))
}

func TestEmptyRanger(t *testing.T) {
	r := NewIPRanger()
	r.GenTree(2, 4)
	assert.False(t, r.ContainsString("192.168.1.1"))
	assert.False(t, r.OverlapContainsString("2620::1"))
	v4, v6 := r.ViewMaskKeyList()
	assert.Empty(t, v4)
	assert.Empty(t, v6)
}

func TestDefaultZeroBucket(t *testing.T) {
	r := NewIPRanger()
	require.NoError(t, r.InsertCIDRString("192.168.1.0/24"))
	r.GenTree(0, -1) // documented to fall back to 2 and 4
	assert.True(t, r.ContainsString("192.168.1.7"))
}

func TestCatchAllBlock(t *testing.T) {
	r := NewIPRanger()
	require.NoError(t, r.InsertCIDRString("0.0.0.0/0"))
	require.NoError(t, r.InsertCIDRString("::/0"))
	r.GenTree(2, 4)
	assert.True(t, r.ContainsString("8.8.8.8"))
	assert.True(t, r.ContainsString("2620::1"))
}

func BenchmarkHitIPv4UsingAWSRanges(b *testing.B) {
	benchmarkContains(b, net.ParseIP("52.95.110.1"), 2, 4, false)
}

func BenchmarkHitIPv6UsingAWSRanges(b *testing.B) {
	benchmarkContains(b, net.ParseIP("2620:107:300f::36b7:ff81"), 2, 4, false)
}

func BenchmarkMissIPv4UsingAWSRanges(b *testing.B) {
	benchmarkContains(b, net.ParseIP("123.123.123.123"), 2, 4, false)
}

func BenchmarkMissIPv6UsingAWSRanges(b *testing.B) {
	benchmarkContains(b, net.ParseIP("2620::ffff"), 2, 4, false)
}

func BenchmarkHitIPv4UsingAWSRangesAuto(b *testing.B) {
	benchmarkContains(b, net.ParseIP("52.95.110.1"), 0, 0, false)
}

func BenchmarkHitIPv6UsingAWSRangesAuto(b *testing.B) {
	benchmarkContains(b, net.ParseIP("2620:107:300f::36b7:ff81"), 0, 0, false)
}

func BenchmarkMissIPv4UsingAWSRangesAuto(b *testing.B) {
	benchmarkContains(b, net.ParseIP("123.123.123.123"), 0, 0, false)
}

func BenchmarkMissIPv6UsingAWSRangesAuto(b *testing.B) {
	benchmarkContains(b, net.ParseIP("2620::ffff"), 0, 0, false)
}

func BenchmarkHitIPv4UsingAWSRangesOverlap(b *testing.B) {
	benchmarkContains(b, net.ParseIP("52.95.110.1"), 2, 4, true)
}

func BenchmarkHitIPv6UsingAWSRangesOverlap(b *testing.B) {
	benchmarkContains(b, net.ParseIP("2620:107:300f::36b7:ff81"), 2, 4, true)
}

func BenchmarkMissIPv4UsingAWSRangesOverlap(b *testing.B) {
	benchmarkContains(b, net.ParseIP("123.123.123.123"), 2, 4, true)
}

func BenchmarkMissIPv6UsingAWSRangesOverlap(b *testing.B) {
	benchmarkContains(b, net.ParseIP("2620::ffff"), 2, 4, true)
}

func BenchmarkHitIPv4UsingAWSRanges1Bucket(b *testing.B) {
	benchmarkContains(b, net.ParseIP("52.95.110.1"), 1, 1, false)
}

func BenchmarkHitIPv6UsingAWSRanges1Bucket(b *testing.B) {
	benchmarkContains(b, net.ParseIP("2620:107:300f::36b7:ff81"), 1, 1, false)
}

func BenchmarkMissIPv4UsingAWSRanges1Bucket(b *testing.B) {
	benchmarkContains(b, net.ParseIP("123.123.123.123"), 1, 1, false)
}

func BenchmarkMissIPv6UsingAWSRanges1Bucket(b *testing.B) {
	benchmarkContains(b, net.ParseIP("2620::ffff"), 1, 1, false)
}

func BenchmarkHitIPv4UsingAWSRanges8Bucket(b *testing.B) {
	benchmarkContains(b, net.ParseIP("52.95.110.1"), 8, 8, false)
}

func BenchmarkHitIPv6UsingAWSRanges8Bucket(b *testing.B) {
	benchmarkContains(b, net.ParseIP("2620:107:300f::36b7:ff81"), 8, 8, false)
}

func BenchmarkMissIPv4UsingAWSRanges8Bucket(b *testing.B) {
	benchmarkContains(b, net.ParseIP("123.123.123.123"), 8, 8, false)
}

func BenchmarkMissIPv6UsingAWSRanges8Bucket(b *testing.B) {
	benchmarkContains(b, net.ParseIP("2620::ffff"), 8, 8, false)
}

func BenchmarkHitIPv4UsingSmallRanges(b *testing.B) {
	benchmarkSmallRanges(b, "128.168.1.0")
}

func BenchmarkMissIPv4UsingSmallRanges(b *testing.B) {
	benchmarkSmallRanges(b, "192.168.2.0")
}

// BenchmarkLinearScanIPv4 is the baseline the whole package exists to beat.
func BenchmarkLinearScanIPv4(b *testing.B) {
	target := net.ParseIP("52.95.110.1")
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		linearContains(awsV4Nets, target)
	}
}

func benchmarkContains(b *testing.B, target net.IP, v4bucket, v6bucket int, overlap bool) {
	b.Helper()
	ipranger := NewIPRanger()
	for _, n := range awsV4Nets {
		if err := ipranger.InsertCIDR(n); err != nil {
			b.Fatal(err)
		}
	}
	for _, n := range awsV6Nets {
		if err := ipranger.InsertCIDR(n); err != nil {
			b.Fatal(err)
		}
	}
	ipranger.GenTree(v4bucket, v6bucket)

	b.ReportAllocs()
	b.ResetTimer()
	if overlap {
		for n := 0; n < b.N; n++ {
			ipranger.OverlapContains(target)
		}
		return
	}
	for n := 0; n < b.N; n++ {
		ipranger.Contains(target)
	}
}

func benchmarkSmallRanges(b *testing.B, target string) {
	b.Helper()
	ipranger := NewIPRanger()
	if err := ipranger.InsertCIDRString("192.168.1.0/24"); err != nil {
		b.Fatal(err)
	}
	if err := ipranger.InsertCIDRString("128.168.0.0/16"); err != nil {
		b.Fatal(err)
	}
	ipranger.GenTree(1, 1)

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		ipranger.ContainsString(target)
	}
}

func insertAll(tb testing.TB, r *IPRanger, nets []*net.IPNet) {
	tb.Helper()
	for _, n := range nets {
		require.NoError(tb, r.InsertCIDR(n))
	}
}

func bucketName(buckets int) string {
	if buckets <= 0 {
		return "auto"
	}
	return fmt.Sprintf("%dbuckets", buckets)
}

// synthNets builds n distinct IPv4 prefixes with a length distribution loosely
// resembling a BGP table: mostly /24, with a tail of shorter aggregates. The
// AWS corpus is too small and too evenly shaped to exercise bucket placement.
func synthNets(tb testing.TB, n int) []*net.IPNet {
	tb.Helper()
	rng := rand.New(rand.NewSource(42))
	nets := make([]*net.IPNet, 0, n)
	seen := make(map[string]bool, n)
	for len(nets) < n {
		var ones int
		switch r := rng.Intn(100); {
		case r < 55:
			ones = 24
		case r < 75:
			ones = 20 + rng.Intn(4)
		case r < 90:
			ones = 16 + rng.Intn(4)
		case r < 98:
			ones = 12 + rng.Intn(4)
		default:
			ones = 8 + rng.Intn(4)
		}
		buf := make([]byte, 4)
		rng.Read(buf)
		buf[0] = 1 + byte(rng.Intn(222)) // keep clear of 0/8 and multicast
		mask := net.CIDRMask(ones, net.IPv4len*8)
		network := &net.IPNet{
			IP:   net.IPv4(buf[0], buf[1], buf[2], buf[3]).To4().Mask(mask),
			Mask: mask,
		}
		if seen[network.String()] {
			continue
		}
		seen[network.String()] = true
		nets = append(nets, network)
	}
	return nets
}

// linearContains is the reference implementation: the exhaustive scan the
// package replaces.
func linearContains(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// sampleIP draws an address that is inside one of nets roughly half the time,
// so a cross-check exercises both the hit and the miss path. Fully random
// addresses almost never land inside a real-world prefix set.
func sampleIP(rng *rand.Rand, nets []*net.IPNet) net.IP {
	switch rng.Intn(4) {
	case 0, 1:
		return randIPIn(rng, nets[rng.Intn(len(nets))])
	case 2:
		// Near a real prefix but usually just outside it: flip a bit inside the
		// network portion, which is where an off-by-one in the masking shows up.
		ip := randIPIn(rng, nets[rng.Intn(len(nets))])
		bit := rng.Intn(len(ip) * 8)
		ip[bit/8] ^= 1 << (7 - uint(bit%8))
		return ip
	default:
		if rng.Intn(2) == 0 {
			return randIP(rng, net.IPv4len)
		}
		return randIP(rng, net.IPv6len)
	}
}

func randIP(rng *rand.Rand, size int) net.IP {
	buf := make([]byte, size)
	rng.Read(buf)
	return net.IP(buf)
}

// randIPIn returns a random address inside n.
func randIPIn(rng *rand.Rand, n *net.IPNet) net.IP {
	ip := append(net.IP(nil), n.IP...)
	ones, bits := n.Mask.Size()
	for i := ones; i < bits; i++ {
		if rng.Intn(2) == 1 {
			ip[i/8] |= 1 << (7 - uint(i%8))
		}
	}
	return ip
}

// disjointSubset drops every block that is nested inside, or duplicates,
// another block in nets. Contains only promises correct answers for a
// non-overlapping set, and the published AWS ranges are not one.
func disjointSubset(nets []*net.IPNet) []*net.IPNet {
	sorted := append([]*net.IPNet{}, nets...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, _ := sorted[i].Mask.Size()
		b, _ := sorted[j].Mask.Size()
		return a < b // shortest prefix, i.e. widest block, first
	})

	kept := make([]*net.IPNet, 0, len(sorted))
	for _, n := range sorted {
		if !linearContains(kept, n.IP) {
			kept = append(kept, n)
		}
	}
	return kept
}

type awsRangesFile struct {
	Prefixes []struct {
		IPPrefix string `json:"ip_prefix"`
	} `json:"prefixes"`
	IPv6Prefixes []struct {
		IPPrefix string `json:"ipv6_prefix"`
	} `json:"ipv6_prefixes"`
}

var (
	awsV4Nets      []*net.IPNet
	awsV6Nets      []*net.IPNet
	disjointV4Nets []*net.IPNet
	disjointV6Nets []*net.IPNet
)

func init() {
	raw, err := os.ReadFile("./testdata/aws_ip_ranges.json")
	if err != nil {
		panic(err)
	}
	var ranges awsRangesFile
	if err := json.Unmarshal(raw, &ranges); err != nil {
		panic(err)
	}
	for _, p := range ranges.Prefixes {
		_, network, err := net.ParseCIDR(p.IPPrefix)
		if err != nil {
			panic(err)
		}
		awsV4Nets = append(awsV4Nets, network)
	}
	for _, p := range ranges.IPv6Prefixes {
		_, network, err := net.ParseCIDR(p.IPPrefix)
		if err != nil {
			panic(err)
		}
		awsV6Nets = append(awsV6Nets, network)
	}
	disjointV4Nets = disjointSubset(awsV4Nets)
	disjointV6Nets = disjointSubset(awsV6Nets)
}
