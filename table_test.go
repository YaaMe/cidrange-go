package cidrange

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBlockTableAgreesWithMap checks the table against the map it replaces.
//
// The risk specific to open addressing is the probe loop: a slot whose
// fingerprint collides must be stepped over, not treated as a miss. Stopping
// there would lose every block filed after the collision — silently, since a
// lost group is indistinguishable from a key that was never inserted. The
// corpus here is large enough that fingerprint collisions occur.
func TestBlockTableAgreesWithMap(t *testing.T) {
	for _, nKeys := range []int{0, 1, 2, 3, 17, 1000, 20000} {
		rng := rand.New(rand.NewSource(int64(nKeys) + 7))

		reference := make(map[netKey][]block, nKeys)
		keys := make([]netKey, 0, nKeys)
		groups := make([][]block, 0, nKeys)
		for i := 0; i < nKeys; i++ {
			var k netKey
			rng.Read(k[:])
			if _, dup := reference[k]; dup {
				continue
			}
			n := 1 + rng.Intn(3)
			g := make([]block, n)
			for j := range g {
				g[j] = block{hi: rng.Uint64(), lo: rng.Uint64(), ones: uint8(rng.Intn(129))}
			}
			reference[k] = g
			keys = append(keys, k)
			groups = append(groups, g)
		}

		tbl := newBlockTable(keys, groups, blockTableSlotsPerKey)
		require.Equal(t, len(keys), tbl.groupCount(), "nKeys=%d", nKeys)

		for i, k := range keys {
			got := tbl.find(k)
			assert.Equal(t, groups[i], got, "nKeys=%d: key %d not returned intact", nKeys, i)
		}

		// Keys that were never inserted must not resolve.
		absent := 0
		for i := 0; i < 2000; i++ {
			var k netKey
			rng.Read(k[:])
			if _, present := reference[k]; present {
				continue
			}
			absent++
			assert.Nil(t, tbl.find(k), "nKeys=%d: absent key resolved", nKeys)
		}
		if nKeys > 0 {
			assert.Greater(t, absent, 0)
		}
	}
}

// TestBlockTableNeverFull guards the probe loop's termination condition. find
// walks until it meets an empty slot, so a table with no empty slot would spin
// forever; the sizing must always leave one.
func TestBlockTableNeverFull(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	for nKeys := 0; nKeys < 40; nKeys++ {
		keys := make([]netKey, nKeys)
		groups := make([][]block, nKeys)
		seen := map[netKey]bool{}
		for i := range keys {
			for {
				rng.Read(keys[i][:])
				if !seen[keys[i]] {
					seen[keys[i]] = true
					break
				}
			}
			groups[i] = []block{{hi: rng.Uint64()}}
		}
		tbl := newBlockTable(keys, groups, blockTableSlotsPerKey)
		assert.Greater(t, len(tbl.slots), nKeys,
			"nKeys=%d: table has no empty slot, find would not terminate", nKeys)
	}
}
