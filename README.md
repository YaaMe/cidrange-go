# cidrange-go

Fast IP to CIDR blocks lookup.

Built for a set that is loaded once and queried constantly — cloud-provider IP
ranges, ACLs, blocklists — from a few dozen up to ~100k blocks. See
[When this fits](#when-this-fits).

## Install

```sh
go get github.com/YaaMe/cidrange-go
```

The module path is case-sensitive and must be spelled exactly as above, even
though the GitHub URL itself is not.

## Getting Started

```go
import "github.com/YaaMe/cidrange-go"

ipranger := cidrange.NewIPRanger()

// Insert the blocks. Non-overlapping blocks unlock the faster Contains path.
if err := ipranger.InsertCIDRString("192.168.1.0/24"); err != nil {
	log.Fatal(err)
}
_ = ipranger.InsertCIDRString("128.168.1.0/24")
_ = ipranger.InsertCIDRString("52.68.93.4/31")

// Zero means "size it for me" - recommended unless you have measured
// a better fixed count for your own data. See Bucket sizing below.
ipranger.GenTree(0, 0)

ipranger.ContainsString("128.168.1.0") // true
ipranger.ContainsString("192.168.2.0") // false
```

### Lifecycle

Insert every block first, then call `GenTree` once. Lookups before `GenTree`
return `false`, and blocks inserted afterwards are invisible until `GenTree` is
called again — it rebuilds from scratch, so calling it repeatedly is safe. Once
`GenTree` has returned, `Contains` and `OverlapContains` only read the structure
and are safe for concurrent use.

### Bucket sizing

`GenTree(v4, v6)` takes an explicit bucket count per family, or zero to size
that family automatically.

A lookup costs **one map probe per bucket**, plus **one comparison per block
sharing the query's key**. Buckets only split at a prefix-length boundary, so
asking for *n* buckets is a request, not a guarantee.

Counting buckets turns out to be the wrong knob. A count says nothing about how
many blocks end up under a single key, and that population is what a lookup
actually scans. Because splitting by block count leaves the final chunk to be
whatever remains after the last flush, the result is not even monotonic in the
count. On a million BGP-shaped prefixes:

| buckets | blocks in last bucket | worst key | lookup |
|---|---|---|---|
| 2 | 401k under `/8` | 1904 | 4962 ns |
| 3 | 40k under `/8` | 200 | 70 ns |
| **4** | **143k under `/8`** | **698** | **786 ns** |
| 6 | 14k under `/8` | 63 | 89 ns |
| **8** | **105k under `/8`** | **514** | **520 ns** |
| 16 | 40k under `/8` | 200 | 87 ns |

Four buckets is 11x slower than three, and eight is 6x slower than six. Nothing
about the number predicts which.

Auto mode therefore does not pick a count at all. It walks the prefix-length
runs and places each boundary so that no key exceeds `AutoMaxPerKey(n)` blocks,
bounding the scan directly. The resulting cost is flat across four orders of
magnitude:

| blocks | auto | buckets chosen | best fixed count | worst fixed count |
|---|---|---|---|---|
| 1e3 | 103 ns | 1 | 59 ns | 107 ns |
| 1e4 | **46 ns** | 2 | 77 ns | 146 ns |
| 1e5 | **61 ns** | 4 | 83 ns | 702 ns |
| 1e6 | 76 ns | 5 | 73 ns | 5036 ns |

At 1e4 and 1e5 auto beats *every* fixed count, because placing the boundary
well beats any equal-count split. At 1e3 a hand-tuned count is still ~1.7x
better — small sets are cheap to tune yourself, so pass an explicit count if
you have measured one.

### `Contains` vs `OverlapContains`

| | requires disjoint blocks | stops at the first matching bucket |
|---|---|---|
| `Contains` / `ContainsString` | yes | yes |
| `OverlapContains` / `OverlapContainsString` | no | no |

`Contains` stops probing as soon as a bucket holds the masked key for the query
address — sound only when no block is nested inside another (see *Algorithm*
below). If your set may contain nested or duplicate blocks, use
`OverlapContains`; on a real-world set the two cost about the same.

Note that published cloud provider ranges, including the AWS ranges in
`testdata/`, **do** contain nested and duplicate prefixes. Either de-overlap
them before inserting, or use `OverlapContains`.

## When this fits

Roughly **a few dozen to ~100k blocks, in a set that rarely changes.**

Two things bound that range, and neither is lookup speed.

**Below ~4 blocks, just use a linear scan.** A lookup here costs a map probe
plus a short scan; below a handful of blocks the probe is the whole cost and a
bare loop over `net.IPNet.Contains` is cheaper. Mixed hit/miss, synthetic
prefixes:

| blocks | this | linear scan | |
|---|---|---|---|
| 2 | 24.4 ns | 18.4 ns | 0.8x — scan wins |
| 4 | 25.7 ns | 28.5 ns | break-even |
| 8 | 27.0 ns | 47.0 ns | 1.7x |
| 32 | 24.4 ns | 167 ns | 6.8x |
| 256 | 23.9 ns | 1212 ns | 51x |
| 1024 | 25.7 ns | 5340 ns | 207x |

**Above ~100k blocks, memory and rebuild cost start to dominate.** Lookup
itself stays flat — that is what auto mode buys — but the other two columns do
not:

| blocks | hit | miss | buckets | memory | per block | `GenTree` |
|---|---|---|---|---|---|---|
| 1e3 | 35 ns | 20 ns | 1 | 0.16 MB | 166 B | 1.6 ms |
| 1e4 | 47 ns | 41 ns | 2 | 1.25 MB | 131 B | 12.7 ms |
| 1e5 | 72 ns | 81 ns | 4 | 11.75 MB | 123 B | 110 ms |
| 1e6 | 72 ns | 98 ns | 5 | 112.6 MB | 118 B | 1.02 s |

That is roughly **2.3x what a trie needs** — the same corpora cost
`gaissmai/bart` 58 and 55 bytes per block at 1e4 and 1e5, and
`yl2chen/cidranger` 470 and 441.

**The harder limit is that the set is static.** Every insert needs a full
`GenTree` to become visible, and that rebuild is linear in the corpus: one
second per million blocks. A structure that supports incremental insert
(`bart`, `yl2chen/cidranger`) is the right shape for a set that changes at
runtime, however small it is.

So this fits cloud-provider IP ranges, ACLs, blocklists and geo-IP tables —
sets loaded once at startup, refreshed occasionally, and queried constantly.
It does not fit a live BGP table or anything mutated per request.

One thing it is genuinely good at: lookup cost does not grow with prefix
length, where a trie pays a dependent memory load per stride. See
[Compared with a trie](#compared-with-a-trie).

## Benchmark

`go test -run '^$' -bench . -benchtime 500ms -count=3` on darwin/arm64 (Apple
M2), 8 threads, against the 889 IPv4 and IPv6 prefixes in `testdata/`. The
lookup path is allocation-free (`0 B/op, 0 allocs/op` throughout) and setup is
excluded from the timings.

Figures are the **minimum** of three runs. An unloaded laptop still produced
single samples 60% above the mode, so a single run is not a measurement —
re-measure before trusting any change smaller than about 10%.

| ns/op | `GenTree(2,4)` | `GenTree(0,0)` auto | 1 bucket | 8 buckets |
|---|---|---|---|---|
| Hit IPv4 | 48.9 | 49.0 | 225.0 | 45.0 |
| Hit IPv6 | 32.7 | 32.8 | 32.8 | 33.3 |
| Miss IPv4 | 55.6 | 82.3 | 33.0 | 158.1 |
| Miss IPv6 | 46.9 | 47.6 | 25.5 | 72.9 |

### Read these numbers with care

**They are a best case, not a typical one.** Every benchmark above probes a
single fixed address several million times, so one map bucket stays pinned in
L1 and every branch in the lookup is perfectly predicted. No real workload
looks like that.

`BenchmarkScattered*` rotates through 8192 distinct addresses instead. Same
corpus, same code:

| ns/op | single fixed address | 8192 rotating addresses | |
|---|---|---|---|
| all hit | 49.0 | 90.8 | 1.9x |
| all miss | 82.3 | 92.2 | 1.1x |

Scattered hits cost about 1.9x more than the headline figure.

**They depend on the Go version more than on this package.** The lookup is
mostly a map probe, and Go 1.24 replaced the runtime's map with a Swiss table.
Because that lives in the runtime, it follows the toolchain that compiles your
program, not the `go` directive in this module's `go.mod` — so a caller on Go
1.24+ gets it for free:

| ns/op | Go 1.22 | Go 1.26 | gain |
|---|---|---|---|
| Scattered, all hit | 90.8 | 87.0 | 1.04x |
| Scattered, half hit | 96.7 | 73.4 | **1.32x** |
| Scattered, all miss | 92.2 | 57.4 | **1.61x** |

The same comparison over the fixed-address benchmarks shows **no difference at
all** (every ratio between 0.98x and 1.08x) — further evidence that those hide
the map cost rather than measure it.

`OverlapContains` on the same set costs essentially what `Contains` does —
70.0 / 47.5 on a hit, 58.4 / 49.1 on a miss — because probing the remaining
buckets is a handful of map lookups that mostly miss.

Two baselines for scale:

```
BenchmarkLinearScanIPv4-8      342502      3473 ns/op   // net.IPNet.Contains over all 889
BenchmarkHitIPv4UsingSmallRanges-8   13967908    85.4 ns/op   // 2 blocks total
```

Reading the table: **one bucket** is the structure's worst shape for a hit —
everything lands in a single bucket, so the scan degenerates towards the linear
baseline (1811 ns). **Eight buckets** inverts it: hits get faster but every miss
pays eight map probes (153 ns). This is exactly the tradeoff auto mode exists to
navigate, and on a set this small a hand-picked `(2,4)` still beats it on the
IPv4 miss. See [Bucket sizing](#bucket-sizing).

### Effect of the allocation-free key

The three sections that follow each record one change against the state
immediately before it, so their "after" columns are snapshots rather than
current figures — later changes moved them again. The tables at the top of this
section are the current numbers.

Keys used to be `net.IP.String()`, which allocated on every bucket probe. They
are now a fixed-size `[16]byte` array. Same machine, same benchmarks:

| | before | after | |
|---|---|---|---|
| Hit IPv4 | 129.0 ns/op, 2 allocs | 70.3 ns/op, 0 allocs | 1.8x |
| Hit IPv6 | 196.8 ns/op, 2 allocs | 47.7 ns/op, 0 allocs | 4.1x |
| Miss IPv4 | 168.0 ns/op, 4 allocs | 57.2 ns/op, 0 allocs | 2.9x |
| Miss IPv6 | 398.6 ns/op, 4 allocs | 49.6 ns/op, 0 allocs | 8.0x |

### Effect of per-bucket tables

Every bucket used to share one map. A key records masked address bytes but not
the mask, so `83.0.0.0/13` and `83.0.0.0/8` hashed identically and the two
buckets' block lists merged — answers stayed correct, since every candidate is
verified, but scans were longer than they needed to be. Giving each bucket its
own table mostly helps misses:

| | shared table | per-bucket tables | |
|---|---|---|---|
| Miss IPv4 | 65.7 ns/op | 57.2 ns/op | 1.15x |
| Miss IPv6 | 54.4 ns/op | 49.6 ns/op | 1.10x |
| Miss IPv4, overlap | 63.9 ns/op | 58.4 ns/op | 1.09x |

### Effect of packed blocks

Blocks used to be stored as `net.IPNet` values: 48 bytes of slice headers that
hold no address at all, only two pointers into separately allocated backing
arrays. Every candidate comparison chased those pointers and called
`net.IPNet.Contains`, which re-derives the block's canonical form on each call.

They are now packed into two words plus a prefix length — 24 bytes, no
indirection, and a containment test that is one shift and one compare.

| ns/op | `net.IPNet` | packed | |
|---|---|---|---|
| Hit IPv4 | 70.6 | 48.9 | 1.44x |
| Hit IPv6 | 47.6 | 32.7 | 1.46x |
| Miss IPv4 | 55.9 | 55.6 | — |
| Miss IPv6 | 47.8 | 46.9 | — |
| Scattered, all hit | 115.6 | 90.8 | 1.27x |
| **Hit IPv4, 1 bucket** | **1813** | **225** | **8.1x** |
| bytes/block @1e5 | 193 | 123 | 1.57x |

Misses barely move, because a miss that never reaches a populated bucket never
touches a block. The one-bucket case moves most: that shape is almost pure
candidate scanning, which is exactly what got cheaper.

### A measurement trap worth naming

Several memory figures in earlier revisions of this file were too low, by about
1.6x. The cause was a missing `runtime.KeepAlive` on the *input* slice:

```go
nets := buildPrefixes(n)
runtime.ReadMemStats(&before)
r := buildRanger(nets)   // copies its input
runtime.GC()
runtime.ReadMemStats(&after)
runtime.KeepAlive(r)     // keeps the ranger — but not nets
```

Once the ranger stopped retaining pointers into `nets`, the whole input became
unreachable, and the GC reclaimed it between the two samples. The freed memory
cancelled out the ranger's own allocation, and the delta came out far too
small. The effect is perverse: it flatters precisely those implementations that
copy their input rather than aliasing it.

Keep the input alive across the measurement, and prefer two `runtime.GC()`
calls to one.

## Compared with a trie

All four structures below were built from the same 889 AWS prefixes and checked
to agree on 894 probes before being timed — a structure that answers wrongly
can otherwise look fast for the wrong reason. Minimum of five runs.

> These figures come from a binary built with **Go 1.26**, because `bart`
> requires ≥1.24. The `cidrange` column therefore does not match the Go 1.22
> table above. Compare within this table, not across.

| ns/op | cidrange | [bart][bart] | [cidranger][cidranger] | [netipx][netipx] |
|---|---|---|---|---|
| Hit IPv4 | 51.1 | **26.9** | 311.0 | 64.6 |
| Miss IPv4 | 91.4 | **4.6** | 75.9 | 64.2 |
| Hit IPv6 | **34.8** | 85.2 | 105.7 | 65.5 |
| Miss IPv6 | 56.8 | **16.2** | 79.9 | 63.3 |
| bytes/block @1e5 | 128 | **55** | 441 | see below |

`netipx` stores merged address *ranges* rather than prefixes, so on a corpus
with heavy adjacency it collapses to a fraction of the input and its
per-block figure is not comparable.

`bart` wins three of four, often by a lot. The exception is the IPv6 hit, and
it is not noise — it is structural.

### Why: lookup cost here is independent of prefix length

A trie descends one node per stride, and each step is a **dependent load** —
the next node's address is not known until the current one has been read, so
the CPU cannot prefetch or overlap them. Cost grows with how deep the match
lies.

This structure's bucket masks are fixed at `GenTree` time, so its one or two
map probes are at addresses that do not depend on each other, and the count
does not depend on prefix length at all.

Measured on 256 IPv6 prefixes at increasing depth:

| levels descended | cidrange | bart |
|---|---|---|
| 2 | 34.7 | **15.4** |
| 4 | 34.8 | 35.2 |
| 6 | **34.7** | 57.7 |
| 8 | **34.7** | 82.9 |
| 10 | **34.7** | 113.9 |
| 12 | **34.7** | 145.4 |
| 14 | **34.8** | 175.9 |
| 16 | **34.7** | 206.7 |

`bart` is linear at **~13.7 ns per level**; this structure is flat within 0.3%
across the whole range. They cross at about **4 levels (≈ `/32`)**.

That model predicts the AWS results. The IPv6 probe matches
`2620:107:300f::/64` — 8 levels, predicting 82.9 ns against 85.2 measured. The
IPv4 probe matches `52.95.110.0/24` — 3 levels, predicting ~25 ns against 26.9
measured.

13.7 ns is far more than the handful of instructions a stride actually costs
(`bart` resolves all nine prefix lengths within a byte using one 256-bit AND).
The whole set fits in cache here, so this is not a DRAM miss — it is the
serialized dependency chain itself.

### The caveat that cuts the other way

`bart` compresses any subtree holding a single prefix into a leaf, so a
**sparse** set is never walked to its nominal depth. Randomly generated `/128`
prefixes measure a flat 18.8 ns, because the descent collapses after two or
three levels and never happens.

The table above defeats that deliberately, by packing 256 siblings under one
parent so every level is a real node. Real-world prefix sets sit somewhere
between the two, and the sparser they are, the closer `bart` stays to its best
case. Take the crossover as the shape of the tradeoff, not a threshold to
design against.

So: this structure is competitive where matches are deep and the set is dense —
IPv6 especially. For shallow IPv4 prefixes, and for misses, a trie is simply
faster, and `bart`'s 4.6 ns miss is not reachable from here.

[bart]: https://github.com/gaissmai/bart
[cidranger]: https://github.com/yl2chen/cidranger
[netipx]: https://github.com/go4org/netipx

## Algorithm Explain

There's feature about ipmask(Set Theory):

> ip-x in cidr a.b.c.d/x => ip-x in cidr a.b.c.d/(x-n)

For example:

52.95.110.1 is contained 52.95.110.0/24, so 52.95.110.1 is aslo contained 52.95.110.0/23.

and vice versa

> ip-x not in cidr a.b.c.d/(x-n) => ip-x not in cidr a.b.c.d/x

It means we don't have to do a traversal on these blocks.

For blocks
```
a0.b0.c0.d0/30
a1.b1.c1.d1/28
a2.b2.c2.d2/27
a3.b3.c3.d3/26
```

Mask 26~32 assume result set A is ["e0.f0.g0,h0", "e1.f1.g1.h1"]

aslo mask target IP 26~32 if result is not in set A, we can directly pass these blocks.

Assume blocks
```
192.168.1.0/24
128.168.1.0/24
52.68.93.4/31
```
mask 24 and get key-values
```
52.68.93.0 => [52.68.93.4/31]
192.168.1.0 => [192.168.1.0/24]
128.168.1.0 => [128.168.1.0/24]
```
ip `128.168.1.14` mask 24 get `128.168.1.0`, and then check `"128.168.1.0/24".Contains("128.168.1.14")` returns true here.

ip `192.168.2.0` mask 24 get `192.168.2.0` returns false here.

ip `52.68.93.254` mask 24 get `52.68.93.0`, and then check `"52.68.93.4/31".Contains("52.68.93.254")` returns false here.

In extreme case, if you get a block so large like `0.0.0.0/0`, it will fallback to a traversal.So it maybe better to make some buckets, like `genTree(2)`

### Why the early stop is sound

`Contains` walks buckets from the longest prefix to the shortest and stops at
the first bucket holding the query's masked key. That is safe when the blocks
are disjoint:

Suppose the bucket with mask `m` holds the key. Then some block `c` in it lies
inside `S`, the `/m` supernet of the query address `ip`. Any block `d` in a
later bucket has a prefix shorter than `m`, so for `d` to contain `ip` it would
have to contain all of `S`, and therefore all of `c` — which is exactly the
nesting the disjointness assumption rules out. So no later bucket can hold a
match the current one missed.

If blocks are `overlap`, you have to check every bucket — that is what
`OverlapContains` does.

## Development

```sh
gofmt -l .          # must print nothing
go vet ./...
go test ./...
go test -run '^$' -bench . ./...
```

The suite cross-checks both lookup methods against a linear
`net.IPNet.Contains` scan over randomly sampled addresses, and asserts that
every inserted block is findable at its own network address across a range of
bucket counts.

## License

MIT. See [LICENSE](LICENSE).
