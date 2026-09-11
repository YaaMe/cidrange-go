package cidrange

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMaskKeyPathsAgree pins an invariant that would otherwise fail silently.
//
// Two different functions derive a bucket key. The build path calls
// block.maskKey on the packed form; the lookup path calls maskKey on a net.IP.
// If they ever disagreed, blocks would be filed under keys no query could
// produce, and every lookup for them would return false — with no error, no
// panic, and every existing test still passing if it happened to use a mask
// length the divergence did not touch.
func TestMaskKeyPathsAgree(t *testing.T) {
	nets := append(append([]*net.IPNet{}, awsV4Nets...), awsV6Nets...)
	require.NotEmpty(t, nets)

	checked := 0
	for _, network := range nets {
		canonical, isV4, ok := normalizeNet(network)
		require.True(t, ok)
		blk, ok := packNet(canonical)
		require.True(t, ok)

		bits := net.IPv6len * 8
		if isV4 {
			bits = net.IPv4len * 8
		}

		// Every mask length a bucket could legitimately be keyed at, meaning
		// any length no longer than the block's own prefix.
		for ones := 0; ones <= int(blk.ones); ones++ {
			mask := net.CIDRMask(ones, bits)

			fromIP, okIP := maskKey(canonical.IP, mask)
			fromBlock, okBlock := blk.maskKey(mask)

			assert.Equal(t, okIP, okBlock, "%s at /%d: ok differs", network, ones)
			assert.Equal(t, fromIP, fromBlock, "%s at /%d: key differs", network, ones)
			checked++
		}
	}
	assert.Greater(t, checked, 10000, "too few comparisons to be meaningful")
	t.Logf("%d (block, mask) pairs agreed across both derivations", checked)
}
