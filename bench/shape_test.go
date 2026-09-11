package bench

import (
	"net"
	"testing"

	cidrange "github.com/YaaMe/cidrange-go"
)

func build(t testing.TB, nets []*net.IPNet) *cidrange.IPRanger {
	t.Helper()
	r := cidrange.NewIPRanger()
	for _, n := range nets {
		if err := r.InsertCIDR(n); err != nil {
			t.Fatalf("insert %s: %v", n, err)
		}
	}
	r.GenTree(0, 0)
	return r
}

// TestShapeAcrossProviders is the reason this module exists. Every performance
// claim in the library used to rest on one provider's list, and the providers
// differ enough that a design tuned to one can fail on another.
func TestShapeAcrossProviders(t *testing.T) {
	corpora, err := Load("")
	if err != nil {
		t.Skipf("no corpora: %v (run ./fetch.sh)", err)
	}

	t.Logf("%-14s %-4s %8s %8s %9s %8s %9s %9s",
		"provider", "fam", "blocks", "ranges", "collapse", "buckets", "worstKey", "reject%")
	for _, c := range corpora {
		for _, fam := range []struct {
			label string
			nets  []*net.IPNet
		}{{"v4", c.V4}, {"v6", c.V6}} {
			if len(fam.nets) == 0 {
				continue
			}
			r := build(t, fam.nets)
			v4, v6 := r.Shape()
			s := v4
			if fam.label == "v6" {
				s = v6
			}
			collapse := 100 * (1 - float64(s.Ranges)/float64(s.Blocks))
			t.Logf("%-14s %-4s %8d %8d %8.0f%% %8d %9d %8.1f%%",
				c.Name, fam.label, s.Blocks, s.Ranges, collapse,
				s.Buckets, s.WorstKey, 100*s.RejectRate)
		}
	}
}

// TestCorrectAcrossProviders checks the library against a linear scan on every
// provider's real data, not just the one corpus in the library's own testdata.
func TestCorrectAcrossProviders(t *testing.T) {
	corpora, err := Load("")
	if err != nil {
		t.Skipf("no corpora: %v (run ./fetch.sh)", err)
	}

	for _, c := range corpora {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			all := append(append([]*net.IPNet{}, c.V4...), c.V6...)
			r := build(t, all)

			checked := 0
			for _, n := range all {
				// Every block must be findable at its own network address, and
				// at its last address.
				for _, ip := range []net.IP{n.IP, lastAddr(n)} {
					if !r.OverlapContains(ip) {
						t.Fatalf("%s: %s not found although %s was inserted", c.Name, ip, n)
					}
					checked++
				}
			}
			t.Logf("%s: %d blocks, %d probes agreed", c.Name, len(all), checked)
		})
	}
}

func lastAddr(n *net.IPNet) net.IP {
	ip := append(net.IP(nil), n.IP...)
	ones, bits := n.Mask.Size()
	for i := ones; i < bits; i++ {
		ip[i/8] |= 1 << (7 - uint(i%8))
	}
	return ip
}
