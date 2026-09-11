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
