package bench

import (
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"runtime"
	"testing"

	cidrange "github.com/YaaMe/cidrange-go"
	"github.com/gaissmai/bart"
	"github.com/yl2chen/cidranger"
	"go4.org/netipx"
)

// The comparison runs against real provider ranges rather than one snapshot,
// because the providers differ enough that a structure can win on one and lose
// on another — see README.md.

type impl struct {
	name     string
	build    func(nets []*net.IPNet) any
	contains func(h any, ip net.IP, addr netip.Addr) bool
}

func prefixesOf(nets []*net.IPNet) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(nets))
	for _, n := range nets {
		p, err := netip.ParsePrefix(n.String())
		if err != nil {
			continue
		}
		out = append(out, p.Masked())
	}
	return out
}

var impls = []impl{
	{
		name: "cidrange",
		build: func(nets []*net.IPNet) any {
			r := cidrange.NewIPRanger()
			for _, n := range nets {
				if err := r.InsertCIDR(n); err != nil {
					panic(err)
				}
			}
			r.GenTree(0, 0)
			return r
		},
		contains: func(h any, ip net.IP, _ netip.Addr) bool {
			return h.(*cidrange.IPRanger).OverlapContains(ip)
		},
	},
	{
		name: "bart/Table",
		build: func(nets []*net.IPNet) any {
			t := new(bart.Table[struct{}])
			for _, p := range prefixesOf(nets) {
				t.Insert(p, struct{}{})
			}
			return t
		},
		contains: func(h any, _ net.IP, addr netip.Addr) bool {
			return h.(*bart.Table[struct{}]).Contains(addr)
		},
	},
	{
		// The membership opponent bart is actually built for: no payload at
		// all. Suggested by bart's author in cidrange-go#6.
		name: "bart/Lite",
		build: func(nets []*net.IPNet) any {
			t := new(bart.Lite)
			for _, p := range prefixesOf(nets) {
				t.Insert(p)
			}
			return t
		},
		contains: func(h any, _ net.IP, addr netip.Addr) bool {
			return h.(*bart.Lite).Contains(addr)
		},
	},
	{
		// Carries a payload like Table, but trades memory for speed.
		name: "bart/Fast",
		build: func(nets []*net.IPNet) any {
			t := new(bart.Fast[struct{}])
			for _, p := range prefixesOf(nets) {
				t.Insert(p, struct{}{})
			}
			return t
		},
		contains: func(h any, _ net.IP, addr netip.Addr) bool {
			return h.(*bart.Fast[struct{}]).Contains(addr)
		},
	},
	{
		name: "cidranger",
		build: func(nets []*net.IPNet) any {
			r := cidranger.NewPCTrieRanger()
			for _, n := range nets {
				if err := r.Insert(cidranger.NewBasicRangerEntry(*n)); err != nil {
					panic(err)
				}
			}
			return r
		},
		contains: func(h any, ip net.IP, _ netip.Addr) bool {
			ok, err := h.(cidranger.Ranger).Contains(ip)
			if err != nil {
				panic(err)
			}
			return ok
		},
	},
	{
		name: "netipx",
		build: func(nets []*net.IPNet) any {
			var b netipx.IPSetBuilder
			for _, p := range prefixesOf(nets) {
				b.AddPrefix(p)
			}
			s, err := b.IPSet()
			if err != nil {
				panic(err)
			}
			return s
		},
		contains: func(h any, _ net.IP, addr netip.Addr) bool {
			return h.(*netipx.IPSet).Contains(addr)
		},
	},
}

// probes returns a rotating set of addresses, a given share of them inside the
// corpus. A fixed single probe measures a best case no caller has: it pins one
// cache line and makes every branch predictable.
func probes(nets []*net.IPNet, hitRatio float64, v4 bool, n int) ([]net.IP, []netip.Addr) {
	rng := rand.New(rand.NewSource(99))
	ips := make([]net.IP, 0, n)
	addrs := make([]netip.Addr, 0, n)
	for i := 0; i < n; i++ {
		var ip net.IP
		if rng.Float64() < hitRatio && len(nets) > 0 {
			x := nets[rng.Intn(len(nets))]
			ip = append(net.IP(nil), x.IP...)
			ones, bits := x.Mask.Size()
			for b := ones; b < bits; b++ {
				if rng.Intn(2) == 1 {
					ip[b/8] |= 1 << (7 - uint(b%8))
				}
			}
		} else if v4 {
			// Reserved space, absent from every provider list.
			ip = net.IPv4(240, byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256))).To4()
		} else {
			ip = make(net.IP, net.IPv6len)
			copy(ip, net.ParseIP("2001:db8::"))
			for j := 4; j < net.IPv6len; j++ {
				ip[j] = byte(rng.Intn(256))
			}
		}
		ips = append(ips, ip)
		a, _ := netip.AddrFromSlice(ip)
		addrs = append(addrs, a.Unmap())
	}
	return ips, addrs
}

// benchProviders are the three shapes worth measuring: one large and heavily
// collapsing, one fragmented, one collapsing almost completely. Running all
// eight would be 96 sub-benchmarks and would say little the three do not.
var benchProviders = map[string]bool{"aws": true, "github": true, "linode": true}

func TestCompareAgree(t *testing.T) {
	corpora, err := Load("")
	if err != nil {
		t.Skipf("no corpora: %v (run ./fetch.sh)", err)
	}
	for _, c := range corpora {
		all := append(append([]*net.IPNet{}, c.V4...), c.V6...)
		handles := make([]any, len(impls))
		for i, im := range impls {
			handles[i] = im.build(all)
		}
		ips, addrs := probes(all, 0.5, true, 4000)
		for i := range ips {
			want := false
			for _, n := range all {
				if n.Contains(ips[i]) {
					want = true
					break
				}
			}
			for j, im := range impls {
				if got := im.contains(handles[j], ips[i], addrs[i]); got != want {
					t.Fatalf("%s/%s: %s got %v want %v", c.Name, im.name, ips[i], got, want)
				}
			}
		}
		t.Logf("%-14s %d blocks, %d probes, all four agree", c.Name, len(all), len(ips))
	}
}

func TestCompareFootprint(t *testing.T) {
	corpora, err := Load("")
	if err != nil {
		t.Skipf("no corpora: %v", err)
	}
	t.Logf("%-14s %-10s %10s %12s", "provider", "impl", "MB", "bytes/block")
	for _, c := range corpora {
		all := append(append([]*net.IPNet{}, c.V4...), c.V6...)
		if len(all) < 1000 {
			continue // too small for the delta to mean anything
		}
		for _, im := range impls {
			runtime.GC()
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			h := im.build(all)
			runtime.GC()
			runtime.GC()
			runtime.ReadMemStats(&after)
			b := float64(int64(after.HeapAlloc) - int64(before.HeapAlloc))
			t.Logf("%-14s %-10s %10.2f %12.0f", c.Name, im.name, b/(1<<20), b/float64(len(all)))
			// The inputs must stay reachable: a structure that copies its input
			// would otherwise let the GC reclaim it between the two samples, and
			// the freed memory would cancel out the structure's own.
			runtime.KeepAlive(h)
			runtime.KeepAlive(all)
		}
	}
}

func BenchmarkCompare(b *testing.B) {
	corpora, err := Load("")
	if err != nil {
		b.Skipf("no corpora: %v", err)
	}
	for _, c := range corpora {
		if !benchProviders[c.Name] {
			continue
		}
		all := append(append([]*net.IPNet{}, c.V4...), c.V6...)
		handles := make([]any, len(impls))
		for i, im := range impls {
			handles[i] = im.build(all)
		}
		for _, mix := range []struct {
			name  string
			ratio float64
		}{{"AllHit", 1.0}, {"HalfHit", 0.5}, {"AllMiss", 0.0}} {
			ips, addrs := probes(c.V4, mix.ratio, true, 8192)
			for j, im := range impls {
				name := fmt.Sprintf("%s/%s/%s", c.Name, mix.name, im.name)
				h := handles[j]
				b.Run(name, func(b *testing.B) {
					for i := 0; i < b.N; i++ {
						im.contains(h, ips[i&8191], addrs[i&8191])
					}
				})
			}
		}
	}
}
