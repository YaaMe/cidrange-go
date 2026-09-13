# cidrange-go

Fast IP to CIDR blocks lookup.

Built for a set that is loaded once and queried constantly — cloud-provider IP
ranges, ACLs, blocklists — from a few dozen up to ~100k blocks.

**For most uses, [gaissmai/bart][bart] is the better choice.** It is faster on
ordinary lookups and uses less memory. Three specific things make this package
worth picking anyway; see [Choosing between this and bart](#choosing-between-this-and-bart).

## Choosing between this and bart

Measured on an ordinary prefix set, this package ties on misses and is about
1.7x behind `bart.Table` on hits — or roughly **3x** behind `bart.Fast`, the
faster variant — at 1.8x the memory. The
[full comparison](#compared-with-a-trie) has the numbers. So the default
recommendation is `bart`, and these are the cases that override it.

**Lookup cost here does not grow with prefix length.** A trie descends one node
per stride and each step is a dependent memory load, so its cost scales with how
deep the match lies. This structure's bucket masks are fixed when `GenTree`
runs, so its probes neither depend on each other nor grow in number:

| levels descended | this | bart |
|---|---|---|
| 4 | 29.8 ns | 35.1 ns |
| 8 | **30.2 ns** | 83.7 ns |
| 16 | **29.2 ns** | 206.7 ns |

The crossover is around 4 levels (≈ `/32`). The caveat is real, though: `bart`
collapses a subtree holding a single prefix into a leaf, so a *sparse* set is
never walked to its nominal depth and the advantage does not appear. It needs
prefixes that are both deep and densely packed — the table above forces that
deliberately.

**It runs on older Go.** `bart` requires Go 1.24 or newer. This module declares
Go 1.19 and is tested against it, which matters if your toolchain is pinned.

**It is small enough to read.** Roughly 600 lines in one package, against a
codebase with internal packages, generated files and three table variants. That
is worth something when you have to audit or vendor a dependency rather than
just import it.

Things `bart` does that this does not: incremental insert (every insert here
needs a full `GenTree`), longest-prefix *match* returning a value rather than a
boolean, and a `netip` API. On that last point — a caller holding `net.IP` pays
about 4 ns to convert, and `bart` still comes out ahead, so it is not a reason
to choose this one.

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

| blocks | scattered mixed | buckets | memory | per block | `GenTree` |
|---|---|---|---|---|---|
| 1e3 | 35.9 ns | 1 | 0.09 MB | 91 B | 1.9 ms |
| 1e4 | 26.6 ns | 2 | 1.04 MB | 109 B | 14.5 ms |
| 1e5 | 7.4 ns | 4 | 9.25 MB | 97 B | 116 ms |
| 1e6 | 7.3 ns | 5 | 117.8 MB | 123 B | 1.8 s |

Lookup gets *faster* as the corpus grows, which is the coarse index at work
rather than magic: a denser set covers more whole `/16`s, and a slot that is
entirely covered is answered in one load without reaching a bucket.

That is roughly **1.8x what a trie needs** — the same corpora cost
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
| Hit IPv4 | 29.9 | 29.8 | 220.3 | 26.4 |
| Hit IPv6 | 28.1 | 28.2 | 28.2 | 28.5 |
| Miss IPv4 | 11.8 | 11.8 | 11.8 | 11.7 |
| Miss IPv6 | 40.5 | 40.4 | 23.5 | 59.7 |

The IPv4 miss row no longer varies with the bucket count at all: those lookups
never reach a bucket, because the [coarse index](#effect-of-the-coarse-index)
answers them first. The IPv6 miss row still does, because the probe address
sits in the same leading bytes as the corpus and so falls through — see the
scattered figures below for the ordinary case.

### Read these numbers with care

**They are a best case, not a typical one.** Every benchmark above probes a
single fixed address several million times, so one map bucket stays pinned in
L1 and every branch in the lookup is perfectly predicted. No real workload
looks like that.

`BenchmarkScattered*` rotates through 8192 distinct addresses instead. Same
corpus, same code:

| ns/op | single fixed address | 8192 rotating addresses | |
|---|---|---|---|
| IPv4, all hit | 29.9 | 70.0 | 2.3x |
| IPv4, half hit | — | 42.3 | |
| IPv4, all miss | 11.8 | 5.4 | |
| IPv6, all hit | 28.1 | 74.2 | 2.6x |
| IPv6, half hit | — | 45.8 | |
| IPv6, all miss | 40.5 | 6.6 | |

Scattered hits cost about 2x the headline figure. The scattered misses are
*faster* than the fixed ones, because the fixed miss probes were deliberately
chosen next to the corpus — `123.123.123.123` and `2620::ffff` — which is the
worst case for the coarse index. Ordinary misses land in uncovered space and
are answered in one load.

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

### Effect of the coarse index

The bucket structure is weakest exactly where a trie is strongest: a miss must
probe every bucket before it can be ruled out, and an address covered by a
short prefix still pays a full hash lookup to find out. A trie answers both
from its root node.

That root node is now present, as a flat array rather than a tree — two bits
per slot over the leading 8 or 16 address bits, recording whether the slot is
entirely uncovered, entirely covered, or mixed. Only the mixed case reaches the
buckets. No per-level dependent loads are introduced, so the depth-independence
above is untouched.

It pays because real prefix sets are sparse. The AWS IPv4 ranges occupy **454
of 65536** sixteen-bit slots, so 99.3% of scattered misses are settled by a
single load:

| ns/op | packed only | + coarse | |
|---|---|---|---|
| Miss IPv4 | 55.6 | 11.7 | 4.8x |
| Miss IPv4, auto | 82.3 | 11.7 | 7.0x |
| **Scattered IPv4, all miss** | **92.2** | **5.4** | **17x** |
| Scattered IPv4, half hit | 96.7 | 44.5 | 2.2x |
| Hit IPv4 | 48.9 | 35.9 | 1.4x |
| Miss IPv6, fixed probe | 46.9 | 48.5 | 0.97x |
| **Scattered IPv6, all miss** | — | **6.6** | |

The one row that moves the wrong way is the fixed IPv6 miss. Both fixed IPv6
probes land in *partial* slots — `2620::ffff` shares its leading bytes with
real AWS space — so they pay for the index and get nothing back. That is the
adversarial case, not the typical one: an ordinary IPv6 miss costs 6.6 ns.

Cost is a fixed 16 KiB per family, which is noise at 1e5 blocks and would not
be at 50, so the table narrows to 8 bits and 64 bytes below 512 blocks.

A `/0` block covers every slot and so marks the whole table covered. That is
correct, and it does mean the index buys nothing for such a set.

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

All figures below use **8192 rotating addresses** rather than one fixed probe,
which is the access pattern a real caller has.

> **Two caveats on this table, both found while answering [#6][issue6].**
>
> The `bart` column is `bart.Table`, which carries a payload it is never asked
> for here. `bart.Lite` measures the same, but **`bart.Fast` is 1.6-1.9x
> faster**, so every figure in that column understates bart. The reproducible
> comparison, with all three variants, is in [bench/README.md](bench/README.md).
>
> The harness that produced this specific table — 889 prefixes from
> `testdata/`, both families, with a bytes/block row — is **not in the
> repository**. `bart` appears only in `bench/compare_test.go`, which probes
> IPv4 over the fetched provider corpora instead. These numbers therefore
> cannot be regenerated from anything committed and should be treated as
> indicative until the harness is restored.

| ns/op | cidrange | [bart.Table][bart] | [cidranger][cidranger] | [netipx][netipx] |
|---|---|---|---|---|
| IPv4, all hit | 73.2 | **42.8** | 251.1 | 89.3 |
| IPv4, half hit | 48.0 | **26.9** | 153.8 | 85.5 |
| IPv4, all miss | 5.3 | **5.1** | 43.6 | 71.6 |
| IPv6, all hit | 75.8 | **66.4** | 172.9 | 101.9 |
| IPv6, half hit | 46.5 | **40.4** | 126.9 | 89.3 |
| IPv6, all miss | 6.7 | **5.1** | 57.5 | 69.6 |
| bytes/block @1e5 | 97 | **55** | 441 | see below |

`netipx` stores merged address *ranges* rather than prefixes, so on a corpus
with heavy adjacency it collapses to a fraction of the input and its per-block
figure is not comparable.

**`bart` wins or ties every row.** Misses are effectively level — 5.3 against
5.1. Hits are about 1.7x behind `bart.Table`, and against `bart.Fast` closer to
**3x** (see [bench/README.md](bench/README.md), where the same probes give
113.8 against 37.0 on the AWS corpus). That is the honest summary for an
ordinary prefix set, and it is why the section above recommends `bart` by
default.


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
| 2 | 29.1 | **14.8** |
| 4 | 29.8 | 35.1 |
| 6 | **29.1** | 57.6 |
| 8 | **30.2** | 83.7 |
| 12 | **30.3** | 144.9 |
| 16 | **29.2** | 206.7 |

`bart` is linear at **~13.7 ns per level**; this structure is flat. They cross
at about **4 levels (≈ `/32`)**, and by 16 levels the gap is **7x**.

That model predicts `bart`'s AWS results. Its IPv6 probe matches
`2620:107:300f::/64` — 8 levels, predicting 83.7 ns against 85.2 measured. Its
IPv4 probe matches `52.95.110.0/24` — 3 levels, predicting ~28 ns against 26.9
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
[issue6]: https://github.com/YaaMe/cidrange-go/issues/6
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
