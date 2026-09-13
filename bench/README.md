# bench

Published provider IP range corpora, and the analysis that runs over them.

This is a **separate module**. The comparison work wants
`github.com/gaissmai/bart` as a dependency and bart requires Go 1.24; pulling
it into the library's `go.mod` would raise the library's own floor from 1.19
and cost one of the three reasons to choose it. Keeping the corpora here also
keeps roughly half a megabyte of data out of every `go get` of the library.

```sh
./fetch.sh                          # refresh the corpora from each provider
go test -v ./...                    # shape, correctness, footprint
go test -run '^$' -bench . ./...    # cross-library comparison
```

## Why this exists

Every performance claim in the parent README used to rest on one provider's
list. The providers differ enough that a design tuned to one can fail on
another, which is not visible until you look at more than one.

Measured 2026-09-11:

| provider | fam | blocks | ranges | collapse | buckets | worst key | miss reject |
|---|---|---|---|---|---|---|---|
| aws | v4 | 7809 | 933 | 88% | 6 | 8 | 97.4% |
| aws | v6 | 3417 | 2179 | **36%** | 5 | 16 | 100.0% |
| cloudflare | v4 | 15 | 14 | 7% | 1 | 2 | 95.3% |
| cloudflare | v6 | 7 | 7 | 0% | 1 | 1 | 98.0% |
| digitalocean | v4 | 1081 | 101 | 91% | 2 | 16 | 99.9% |
| digitalocean | v6 | 148 | 39 | 74% | 2 | 1 | 98.8% |
| fastly | v4 | 19 | 16 | 16% | 1 | 4 | 95.3% |
| fastly | v6 | 2 | 2 | 0% | 1 | 1 | 99.6% |
| gcp | v4 | 1007 | 160 | 84% | 2 | 20 | 99.5% |
| gcp | v6 | 95 | 17 | 82% | 1 | 1 | 99.6% |
| github | v4 | 5745 | **2017** | 65% | 4 | 12 | 99.1% |
| github | v6 | 1550 | 638 | 59% | 3 | 18 | 100.0% |
| linode | v4 | 5409 | **95** | **98%** | 2 | 1 | 99.9% |
| linode | v6 | 96 | 22 | 77% | 1 | 48 | 98.8% |
| oracle | v4 | 1107 | 478 | 57% | 2 | 26 | 99.8% |
| oracle | v6 | 220 | 122 | 45% | 1 | 32 | 99.6% |

Three things this table settles.

**Collapse varies from 0% to 98%.** Linode publishes 5409 IPv4 prefixes that
are really 95 ranges; GitHub publishes 5745 that are really 2017. A structure
that exploits merging is transformative for one and marginal for the other.
Generalising from a single provider would have got this wrong in either
direction. `Shape` exists so a caller can check their own data rather than
inherit an assumption.

**The coarse index holds up everywhere.** Miss rejection is 95–100% on every
provider, including the fragmented ones. It was designed against AWS, and it
was reasonable to worry that was overfitting; it was not.

**Automatic bucket sizing holds up everywhere.** The worst per-key population
stays between 1 and 48 across all sixteen families, so the bound `AutoMaxPerKey`
promises is being met on real data and not just on the synthetic sets it was
tuned against.

## The parent's testdata is stale

`../testdata/aws_ip_ranges.json` holds 889 IPv4 and 360 IPv6 prefixes. AWS
today publishes **7809 and 3417** — roughly nine times as many. Every benchmark
figure in the parent README is therefore measured against a corpus an order of
magnitude smaller than the thing it is meant to represent.

The shape held up at the new size (88% collapse against the snapshot's 87%), so
the conclusions survive, but the absolute numbers describe a smaller problem
than a caller has today.

## Compared with other libraries

All four are built from the same corpus and checked to agree on 4000 probes
before being timed. Probes rotate through 8192 addresses rather than repeating
one, which is the access pattern a caller has.

Three providers are benchmarked, chosen as three different shapes: `aws` large
and heavily collapsing, `github` fragmented, `linode` collapsing almost
completely. All eight are checked for correctness and footprint.

ns/op, minimum of five runs, Go 1.26 on darwin/arm64 (Apple M2). IPv4 probes.

`bart` appears as three variants because bart's author pointed out in
[#6](https://github.com/YaaMe/cidrange-go/issues/6) that a boolean question
should not be put to a payload-carrying `bart.Table`, and that `bart.Fast`
exists and is quicker than both:

| corpus | mix | cidrange | bart.Table | bart.Lite | **bart.Fast** | cidranger | netipx |
|---|---|---|---|---|---|---|---|
| aws | all hit | 113.8 | 58.5 | 57.3 | **37.0** | 377.1 | 125.1 |
| aws | half hit | 65.0 | 37.4 | 36.0 | **26.9** | 222.9 | 113.8 |
| aws | all miss | 7.2 | 6.9 | 6.8 | **6.8** | 42.9 | 91.5 |
| github | all hit | 118.3 | 59.5 | 57.7 | **36.0** | 387.6 | 143.3 |
| github | half hit | 66.9 | 38.1 | 36.8 | **27.0** | 225.9 | 121.9 |
| github | all miss | 7.2 | 6.9 | 6.8 | **6.8** | 43.0 | 92.1 |
| linode | all hit | 38.5 | 27.7 | 27.3 | **14.8** | 343.3 | 80.3 |
| linode | half hit | 26.7 | 23.7 | 23.1 | **19.1** | 205.8 | 74.3 |
| linode | all miss | 7.2 | 6.9 | 6.8 | **6.8** | 43.0 | 60.1 |

Two results, and only one of them changes anything:

**`bart.Lite` is within 2% of `bart.Table`.** `Contains` never reads the
payload, so asking a table for a boolean costs what a set costs. Naming `Lite`
is more honest but the earlier figures were not wrong because of it.

**`bart.Fast` is 1.6-1.9x faster than `bart.Table` on hits.** This one does
change things: it means every earlier revision of these tables understated bart.
Against `Fast`, `cidrange` is about 3x behind on hits rather than 1.7x.

Misses are level across all three bart variants and this package, at ~7 ns.

bytes per block:

| corpus | cidrange | bart | cidranger | netipx |
|---|---|---|---|---|
| aws | 105 | 36 | 503 | **14** |
| gcp | 107 | 27 | 501 | **9** |
| github | 97 | 29 | 508 | **18** |
| linode | 136 | 22 | 497 | **1** |
| oracle | 97 | 31 | 506 | **25** |

Four things worth reading off these.

**Misses are a tie.** 7.3 against 6.8 on every corpus, fragmented or not. That
is the coarse index, and it holds on data it was never tuned against.

**Hits are about 2x behind bart**, and the gap tracks fragmentation: on
`linode`, which collapses to 95 ranges, it narrows to 37.5 against 27.5. On
`aws` and `github` it is roughly 114 against 59.

**netipx confirms the range argument and refutes the obvious conclusion from
it.** It merges to ranges and its footprint shows it — 1 byte per block on
`linode`, where 5505 prefixes really are 95 ranges. Yet it is the slowest on
misses of anything here. A structure that small is entirely in cache, so the
cost is not memory: it binary-searches, and that is log n unpredictable
branches. Collapsing the set is worth a great deal; searching it afterwards is
where the saving goes.

**cidranger, the library this one was originally written against, is 3x to 10x
behind everything else** and uses 500 bytes per block on every corpus.

## Provenance

Each `testdata/*.cidr` records its source URL and fetch time in a header
comment. The lists are published by each provider for exactly this use and
change continuously, so re-running `fetch.sh` will move the numbers above.

Azure is deliberately absent: its service tag list sits behind an interstitial
download page with a weekly-changing filename and cannot be fetched unattended.
It is the largest of the set and probably the most fragmented, so it is worth
adding by hand if the fragmented case matters to you.
