# cidrange-go

Fast IP to CIDR blocks lookup.

## Getting Started

```go
ipranger := NewIPRanger()
// set non-overlap blocks
ipranger.InsertCIDRStr("192.168.1.0/24")
ipranger.InsertCIDRStr("128.168.1.0/24")
ipranger.InsertCIDRStr("52.68.93.4/31")
// It effect keys distribution base on blocks and mask numbers.
// It's a tradeoff, default is 2 for ipv4 and 4 for ipv6.
// The same mask will be distributed in the same bucket.
// If there's a little blocks, 1 is ok.
// More buckets here, more time will be cost on missing case.
ipranger.GenTree(2, 4) // default 2 slices for ipv4, 4 slices for ipv6
ipranger.Containstr("128.168.1.0") // returns true
ipranger.Containstr("192.168.2.0") // returns false
```

## Benchmark

```go
BenchmarkHitIPv4UsingAWSRanges-16            	11635243	        94.09 ns/op
BenchmarkHitIPv6UsingAWSRanges-16            	 8225546	       149.1 ns/op
BenchmarkMissIPv4UsingAWSRanges-16           	 9654986	       122.0 ns/op
BenchmarkMissIPv6UsingAWSRanges-16           	 6267660	       180.3 ns/op
BenchmarkHitIPv4UsingAWSRangesOverlap-16     	12967574	        86.77 ns/op
BenchmarkHitIPv6UsingAWSRangesOverlap-16     	 8048085	       146.8 ns/op
BenchmarkMissIPv4UsingAWSRangesOverlap-16    	 9781345	       123.2 ns/op
BenchmarkMissIPv6UsingAWSRangesOverlap-16    	 6108297	       181.1 ns/op
BenchmarkHitIPv4UsingAWSRanges1Bucket-16     	  940128	      1234 ns/op
BenchmarkHitIPv6UsingAWSRanges1Bucket-16     	 8836210	       130.6 ns/op
BenchmarkMissIPv4UsingAWSRanges1Bucket-16    	16015999	        64.97 ns/op
BenchmarkMissIPv6UsingAWSRanges1Bucket-16    	11910202	        97.63 ns/op
BenchmarkHitIPv4UsingAWSRanges8Bucket-16     	13573425	        77.51 ns/op
BenchmarkHitIPv6UsingAWSRanges8Bucket-16     	 8206742	       145.2 ns/op
BenchmarkMissIPv4UsingAWSRanges8Bucket-16    	 3314006	       379.0 ns/op
BenchmarkMissIPv6UsingAWSRanges8Bucket-16    	 4292500	       317.9 ns/op
BenchmarkHitIPv4UsingSmallRanges-16          	 9780699	       118.6 ns/op
BenchmarkMissIPv4UsingSmallRanges-16         	 8356198	       134.3 ns/op
```

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

what's more, the blocks are `non-overlap`. If you already get a prefixmatch cidr in `24=>32` mask range bucket, you haven't to find in `0=>24` buckets.

If blocks are `overlap`, you have to check every buckets.
