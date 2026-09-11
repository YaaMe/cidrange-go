# bench

Published provider IP range corpora, and the analysis that runs over them.

This is a **separate module**. The comparison work wants
`github.com/gaissmai/bart` as a dependency and bart requires Go 1.24; pulling
it into the library's `go.mod` would raise the library's own floor from 1.19
and cost one of the three reasons to choose it. Keeping the corpora here also
keeps roughly half a megabyte of data out of every `go get` of the library.

```sh
./fetch.sh          # refresh the corpora from each provider
go test -v ./...    # shape and correctness across all of them
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

## Provenance

Each `testdata/*.cidr` records its source URL and fetch time in a header
comment. The lists are published by each provider for exactly this use and
change continuously, so re-running `fetch.sh` will move the numbers above.

Azure is deliberately absent: its service tag list sits behind an interstitial
download page with a weekly-changing filename and cannot be fetched unattended.
It is the largest of the set and probably the most fragmented, so it is worth
adding by hand if the fragmented case matters to you.
