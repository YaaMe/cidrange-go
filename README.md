# cidrange-go

Fast IP to CIDR blocks lookup.

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

## Benchmark

`go test -run '^$' -bench . -benchtime 2s`, on darwin/arm64, 8 threads. The
lookup path is allocation-free; setup is excluded from the timings.

```
BenchmarkHitIPv4UsingAWSRanges-8           	32824452	        74.63 ns/op	       0 B/op	       0 allocs/op
BenchmarkHitIPv6UsingAWSRanges-8           	51008389	        47.24 ns/op	       0 B/op	       0 allocs/op
BenchmarkMissIPv4UsingAWSRanges-8          	39046876	        65.72 ns/op	       0 B/op	       0 allocs/op
BenchmarkMissIPv6UsingAWSRanges-8          	42058592	        54.38 ns/op	       0 B/op	       0 allocs/op
BenchmarkHitIPv4UsingAWSRangesOverlap-8    	34117077	        70.81 ns/op	       0 B/op	       0 allocs/op
BenchmarkHitIPv6UsingAWSRangesOverlap-8    	50873010	        47.08 ns/op	       0 B/op	       0 allocs/op
BenchmarkMissIPv4UsingAWSRangesOverlap-8   	36910843	        63.94 ns/op	       0 B/op	       0 allocs/op
BenchmarkMissIPv6UsingAWSRangesOverlap-8   	44314680	        53.82 ns/op	       0 B/op	       0 allocs/op
BenchmarkHitIPv4UsingAWSRanges1Bucket-8    	 1294713	      1833 ns/op	       0 B/op	       0 allocs/op
BenchmarkHitIPv6UsingAWSRanges1Bucket-8    	50895891	        48.98 ns/op	       0 B/op	       0 allocs/op
BenchmarkMissIPv4UsingAWSRanges1Bucket-8   	66869596	        39.67 ns/op	       0 B/op	       0 allocs/op
BenchmarkMissIPv6UsingAWSRanges1Bucket-8   	70479234	        28.60 ns/op	       0 B/op	       0 allocs/op
BenchmarkHitIPv4UsingAWSRanges8Bucket-8    	45744781	        53.27 ns/op	       0 B/op	       0 allocs/op
BenchmarkHitIPv6UsingAWSRanges8Bucket-8    	50265507	        47.15 ns/op	       0 B/op	       0 allocs/op
BenchmarkMissIPv4UsingAWSRanges8Bucket-8   	14132028	       169.2 ns/op	       0 B/op	       0 allocs/op
BenchmarkMissIPv6UsingAWSRanges8Bucket-8   	31218919	        80.49 ns/op	       0 B/op	       0 allocs/op
BenchmarkHitIPv4UsingSmallRanges-8         	27695250	        87.94 ns/op	       0 B/op	       0 allocs/op
BenchmarkMissIPv4UsingSmallRanges-8        	28228693	        84.82 ns/op	       0 B/op	       0 allocs/op
BenchmarkLinearScanIPv4-8                  	  689733	      3628 ns/op
```

`BenchmarkLinearScanIPv4` is the baseline this package exists to beat: calling
`net.IPNet.Contains` over all 889 AWS prefixes in a loop.

The single-bucket IPv4 hit case is the worst shape for the structure — every
block lands in one bucket, so a hit degenerates towards a linear scan. That is
the tradeoff `GenTree`'s bucket arguments exist to manage.

### Effect of the allocation-free key

Keys used to be `net.IP.String()`, which allocated on every bucket probe. They
are now a fixed-size `[16]byte` array. Same machine, same benchmarks:

| | before | after | |
|---|---|---|---|
| Hit IPv4 | 129.0 ns/op, 2 allocs | 74.63 ns/op, 0 allocs | 1.7x |
| Hit IPv6 | 196.8 ns/op, 2 allocs | 47.24 ns/op, 0 allocs | 4.2x |
| Miss IPv4 | 168.0 ns/op, 4 allocs | 65.72 ns/op, 0 allocs | 2.6x |
| Miss IPv6 | 398.6 ns/op, 4 allocs | 54.38 ns/op, 0 allocs | 7.3x |

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
