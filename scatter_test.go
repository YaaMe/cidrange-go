package cidrange

import (
	"math/rand"
	"net"
	"testing"
)

// The benchmarks in cidrange_test.go each probe a single fixed address. That
// keeps one map bucket permanently in L1 and makes every branch in the lookup
// perfectly predictable, which flatters the map far more than any real
// workload would: it hides both the hash cost and the cache miss that a
// scattered query pattern pays on every call.
//
// These probe a large rotating set instead. The difference between the two is
// the part of the cost a single-address benchmark cannot see.

const nScatter = 1 << 13

func scatterProbes(tb testing.TB, nets []*net.IPNet, hitRatio float64) []net.IP {
	tb.Helper()
	rng := rand.New(rand.NewSource(99))
	out := make([]net.IP, 0, nScatter)
	for i := 0; i < nScatter; i++ {
		if rng.Float64() < hitRatio {
			out = append(out, randIPIn(rng, nets[rng.Intn(len(nets))]))
			continue
		}
		// Reserved space, guaranteed absent from the AWS corpus.
		out = append(out, net.IPv4(240, byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256))).To4())
	}
	return out
}

func benchmarkScattered(b *testing.B, hitRatio float64) {
	b.Helper()
	r := NewIPRanger()
	for _, n := range awsV4Nets {
		if err := r.InsertCIDR(n); err != nil {
			b.Fatal(err)
		}
	}
	r.GenTree(0, 0)
	probes := scatterProbes(b, awsV4Nets, hitRatio)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.OverlapContains(probes[i&(nScatter-1)])
	}
}

func BenchmarkScatteredIPv4AllHit(b *testing.B)  { benchmarkScattered(b, 1.0) }
func BenchmarkScatteredIPv4HalfHit(b *testing.B) { benchmarkScattered(b, 0.5) }
func BenchmarkScatteredIPv4AllMiss(b *testing.B) { benchmarkScattered(b, 0.0) }

// scatterProbesV6 mirrors the IPv4 version. The misses are drawn from the
// documentation range 2001:db8::/32 rather than from beside the corpus, so this
// measures an ordinary miss. The fixed-probe benchmarks above use 2620::ffff,
// which sits in the same leading bytes as real AWS space and is therefore the
// adversarial case for any coarse index — worth having both.
func scatterProbesV6(tb testing.TB, nets []*net.IPNet, hitRatio float64) []net.IP {
	tb.Helper()
	rng := rand.New(rand.NewSource(101))
	out := make([]net.IP, 0, nScatter)
	for i := 0; i < nScatter; i++ {
		if rng.Float64() < hitRatio {
			out = append(out, randIPIn(rng, nets[rng.Intn(len(nets))]))
			continue
		}
		ip := make(net.IP, net.IPv6len)
		copy(ip, net.ParseIP("2001:db8::"))
		for j := 4; j < net.IPv6len; j++ {
			ip[j] = byte(rng.Intn(256))
		}
		out = append(out, ip)
	}
	return out
}

func benchmarkScatteredV6(b *testing.B, hitRatio float64) {
	b.Helper()
	r := NewIPRanger()
	for _, n := range awsV6Nets {
		if err := r.InsertCIDR(n); err != nil {
			b.Fatal(err)
		}
	}
	r.GenTree(0, 0)
	probes := scatterProbesV6(b, awsV6Nets, hitRatio)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.OverlapContains(probes[i&(nScatter-1)])
	}
}

func BenchmarkScatteredIPv6AllHit(b *testing.B)  { benchmarkScatteredV6(b, 1.0) }
func BenchmarkScatteredIPv6HalfHit(b *testing.B) { benchmarkScatteredV6(b, 0.5) }
func BenchmarkScatteredIPv6AllMiss(b *testing.B) { benchmarkScatteredV6(b, 0.0) }
