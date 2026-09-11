package cidrange

import (
	"math/rand"
	"net"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBlockContainsBoundaries pins the prefix lengths where the shift
// arithmetic changes behaviour: /0 shifts by the full word width, /64 shifts by
// zero, /65 crosses into the low word, and /128 compares both words exactly.
func TestBlockContainsBoundaries(t *testing.T) {
	cases := []struct {
		cidr string
		in   []string
		out  []string
	}{
		{"0.0.0.0/0", []string{"0.0.0.0", "8.8.8.8", "255.255.255.255"}, nil},
		{"::/0", []string{"::", "2620::1", "ffff::1"}, nil},
		{"10.0.0.0/8", []string{"10.0.0.0", "10.255.255.255"}, []string{"9.255.255.255", "11.0.0.0"}},
		{"192.168.1.0/24", []string{"192.168.1.0", "192.168.1.255"}, []string{"192.168.0.255", "192.168.2.0"}},
		{"52.68.93.4/31", []string{"52.68.93.4", "52.68.93.5"}, []string{"52.68.93.3", "52.68.93.6"}},
		{"1.2.3.4/32", []string{"1.2.3.4"}, []string{"1.2.3.5", "1.2.3.3"}},
		{"2620::/16", []string{"2620::", "2620:ffff::ffff"}, []string{"261f::", "2621::"}},
		// /64 shifts by zero in the high word.
		{"2620:107:300f::/64", []string{"2620:107:300f::", "2620:107:300f::ffff:ffff:ffff:ffff"},
			[]string{"2620:107:300e:ffff::", "2620:107:3010::"}},
		// /65 is the first length that reaches the low word.
		{"2620:107:300f:0:8000::/65", []string{"2620:107:300f:0:8000::", "2620:107:300f:0:ffff:ffff:ffff:ffff"},
			[]string{"2620:107:300f:0:7fff:ffff:ffff:ffff", "2620:107:3010:0:8000::"}},
		{"2620::1/128", []string{"2620::1"}, []string{"2620::2", "2620::"}},
	}

	for _, tc := range cases {
		t.Run(tc.cidr, func(t *testing.T) {
			_, network, err := net.ParseCIDR(tc.cidr)
			require.NoError(t, err)
			canonical, _, ok := normalizeNet(network)
			require.True(t, ok)
			b, ok := packNet(canonical)
			require.True(t, ok)

			for _, s := range tc.in {
				ip := net.ParseIP(s)
				require.NotNil(t, ip, s)
				hi, lo, ok := packIP(ip)
				require.True(t, ok)
				assert.True(t, b.contains(hi, lo), "%s should contain %s", tc.cidr, s)
				// Cross-check against the standard library.
				assert.True(t, network.Contains(ip), "stdlib disagrees for %s in %s", s, tc.cidr)
			}
			for _, s := range tc.out {
				ip := net.ParseIP(s)
				require.NotNil(t, ip, s)
				hi, lo, ok := packIP(ip)
				require.True(t, ok)
				assert.False(t, b.contains(hi, lo), "%s should not contain %s", tc.cidr, s)
				assert.False(t, network.Contains(ip), "stdlib disagrees for %s in %s", s, tc.cidr)
			}
		})
	}
}

// TestBlockAgreesWithStdlib is the property that matters: for any block and any
// address, the packed test and net.IPNet.Contains must return the same thing.
func TestBlockAgreesWithStdlib(t *testing.T) {
	rng := rand.New(rand.NewSource(1234))
	nets := append(append([]*net.IPNet{}, awsV4Nets...), awsV6Nets...)

	checked := 0
	for _, network := range nets {
		canonical, _, ok := normalizeNet(network)
		require.True(t, ok)
		b, ok := packNet(canonical)
		require.True(t, ok)

		for i := 0; i < 20; i++ {
			ip := sampleIP(rng, nets)
			hi, lo, ok := packIP(ip)
			if !ok {
				continue
			}
			// net.IPNet.Contains returns false across families; the packed form
			// has no family, so only compare within one.
			if (ip.To4() != nil) != (len(canonical.IP) == net.IPv4len) {
				continue
			}
			assert.Equal(t, network.Contains(ip), b.contains(hi, lo),
				"disagreement for %s in %s", ip, network)
			checked++
		}
	}
	assert.Greater(t, checked, 1000, "too few comparisons to be meaningful")
}

// TestPackIPRejectsMalformed covers the inputs a lookup can actually receive.
func TestPackIPRejectsMalformed(t *testing.T) {
	_, _, ok := packIP(nil)
	assert.False(t, ok)
	_, _, ok = packIP(net.IP{1, 2, 3})
	assert.False(t, ok)
	_, _, ok = packIP(net.ParseIP("not-an-ip"))
	assert.False(t, ok)

	// A v4-mapped IPv6 address must pack as IPv4, so it matches IPv4 blocks.
	hiMapped, loMapped, ok := packIP(net.ParseIP("::ffff:192.168.1.7"))
	require.True(t, ok)
	hiPlain, loPlain, ok := packIP(net.ParseIP("192.168.1.7"))
	require.True(t, ok)
	assert.Equal(t, hiPlain, hiMapped)
	assert.Equal(t, loPlain, loMapped)
}

func TestBlockSize(t *testing.T) {
	// Guards the reason this type exists: net.IPNet is 48 bytes of slice
	// headers plus two separate heap allocations for the bytes they point at.
	// A field reordering that padded this out would silently undo the win.
	assert.LessOrEqual(t, int(unsafe.Sizeof(block{})), 24)
	assert.Equal(t, 48, int(unsafe.Sizeof(net.IPNet{})))
}
