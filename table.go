package cidrange

import (
	"encoding/binary"
	"math/bits"
)

// slotEntry addresses one group of blocks sharing a bucket key.
//
// It holds no key. Verification is done against the group's first block, whose
// masked network address is the key by construction, which keeps an entry at 12
// bytes instead of 28.
type slotEntry struct {
	fp     uint32 // fingerprint of the key; 0 marks an empty slot
	off, n int32  // window into the bucket's dense block array
	key    netKey
}

// blockTable maps a bucket key to a group of blocks.
//
// It replaces a map[netKey][]block. The runtime's map has to support insert,
// delete and growth while a lookup is in flight; none of that is needed once
// GenTree has run, and it is paid for twice over here — once in the control
// logic, and once in memory, since every group also carried its own slice
// header and its own backing allocation.
//
// This is sized exactly, open-addressed with linear probing, and stores every
// block of the bucket in one contiguous array so a group is a window into it
// rather than a separate object.
type blockTable struct {
	slots    []slotEntry
	blocks   []block
	slotMask uint32
}

func hashNetKey(k netKey) uint64 {
	hi := binary.BigEndian.Uint64(k[0:8])
	lo := binary.BigEndian.Uint64(k[8:16])
	h := hi*0x9E3779B97F4A7C15 ^ lo*0xC2B2AE3D27D4EB4F
	h ^= h >> 32
	h *= 0xD6E8FEB86659FD93
	h ^= h >> 32
	return h
}

// newBlockTable builds a table from key-ordered groups. groups must list each
// key once, with the blocks that share it.
func newBlockTable(keys []netKey, groups [][]block, slotsPerKey int) *blockTable {
	capacity := 1
	if len(keys) > 0 {
		capacity = 1 << uint(bits.Len(uint(len(keys)*slotsPerKey-1)))
	}
	t := &blockTable{
		slots:    make([]slotEntry, capacity),
		slotMask: uint32(capacity - 1),
	}
	for _, g := range groups {
		t.blocks = append(t.blocks, g...)
	}

	off := int32(0)
	for i, key := range keys {
		h := hashNetKey(key)
		s := uint32(h>>32) & t.slotMask
		for t.slots[s].fp != 0 {
			s = (s + 1) & t.slotMask
		}
		t.slots[s] = slotEntry{
			fp:  uint32(h) | 1, // fold 0 away so it can mean "empty"
			off: off,
			n:   int32(len(groups[i])),
			key: key,
		}
		off += int32(len(groups[i]))
	}
	return t
}

// find returns the blocks filed under key, or nil.
//
// A fingerprint match is only a hint: the key is confirmed against the group's
// first block, whose network address masked by the bucket's mask is the key.
// Confirming rather than trusting matters because probing must continue past a
// colliding slot, and stopping early there would silently lose a block.
func (t *blockTable) find(key netKey) []block {
	h := hashNetKey(key)
	s := uint32(h>>32) & t.slotMask
	fp := uint32(h) | 1
	for {
		e := &t.slots[s]
		if e.fp == 0 {
			return nil
		}
		if e.fp == fp && e.key == key {
			return t.blocks[e.off : e.off+e.n]
		}
		s = (s + 1) & t.slotMask
	}
}

// groupCount reports how many distinct keys the table holds.
func (t *blockTable) groupCount() int {
	n := 0
	for i := range t.slots {
		if t.slots[i].fp != 0 {
			n++
		}
	}
	return n
}

// blockTableSlotsPerKey sets the table's load factor. Linear probing degrades
// sharply on unsuccessful search — expected probes are about
// (1 + 1/(1-a)^2)/2, so 2.5 at a=0.5 against 1.3 at a=0.25 — and a slot is
// only 12 bytes, so the space buys more than it costs.
const blockTableSlotsPerKey = 2

// forEachGroup visits every group in the table. Order is unspecified.
func (t *blockTable) forEachGroup(f func(blocks []block)) {
	for i := range t.slots {
		if e := &t.slots[i]; e.fp != 0 {
			f(t.blocks[e.off : e.off+e.n])
		}
	}
}
