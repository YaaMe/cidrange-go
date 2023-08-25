package cidrange

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"encoding/binary"
	"encoding/json"
	"math/rand"
	"net"
	"os"
	"time"
)

func TestBasicIP(t *testing.T) {
	ipranger := NewIPRanger()
	ipranger.InsertCIDRStr("192.168.1.0/24")
	ipranger.InsertCIDRStr("128.168.1.0/24")
	ipranger.InsertCIDRStr("52.68.93.4/31")
	ipranger.GenTree(1, 1)
	assert.Equal(t, true, ipranger.Containstr("128.168.1.0"))
	assert.Equal(t, false, ipranger.Containstr("192.168.2.0"))
	assert.Equal(t, false, ipranger.Containstr("52.68.93.254"))
}

func TestBenchKey(t *testing.T) {
	ipranger := NewIPRanger()
	for _, prefix := range awsRanges.Prefixes {
		_, network, _ := net.ParseCIDR(prefix.IPPrefix)
		ipranger.InsertCIDR(network)
	}
	for _, prefix := range awsRanges.IPv6Prefixes {
		_, network, _ := net.ParseCIDR(prefix.IPPrefix)
		ipranger.InsertCIDR(network)
	}
	ipranger.GenTree(2, 2)
	assert.Equal(t, true, ipranger.Containstr("52.95.110.1"))
	assert.Equal(t, true, ipranger.Containstr("2620:107:300f::36b7:ff81"))
	assert.Equal(t, false, ipranger.Containstr("123.123.123.123"))
	assert.Equal(t, false, ipranger.Containstr("2620::ffff"))
}

func BenchmarkHitIPv4UsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("52.95.110.1"), NewIPRanger(), 2, 4, true)
}
func BenchmarkHitIPv6UsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("2620:107:300f::36b7:ff81"), NewIPRanger(), 2, 4, true)
}
func BenchmarkMissIPv4UsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("123.123.123.123"), NewIPRanger(), 2, 4, true)
}
func BenchmarkMissIPv6UsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("2620::ffff"), NewIPRanger(), 2, 4, true)
}

func BenchmarkHitIPv4UsingAWSRangesOverlap(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("52.95.110.1"), NewIPRanger(), 2, 4, true)
}
func BenchmarkHitIPv6UsingAWSRangesOverlap(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("2620:107:300f::36b7:ff81"), NewIPRanger(), 2, 4, true)
}
func BenchmarkMissIPv4UsingAWSRangesOverlap(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("123.123.123.123"), NewIPRanger(), 2, 4, true)
}
func BenchmarkMissIPv6UsingAWSRangesOverlap(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("2620::ffff"), NewIPRanger(), 2, 4, true)
}

func BenchmarkHitIPv4UsingAWSRanges1Bucket(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("52.95.110.1"), NewIPRanger(), 1, 1, true)
}
func BenchmarkHitIPv6UsingAWSRanges1Bucket(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("2620:107:300f::36b7:ff81"), NewIPRanger(), 1, 1, true)
}
func BenchmarkMissIPv4UsingAWSRanges1Bucket(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("123.123.123.123"), NewIPRanger(), 1, 1, true)
}
func BenchmarkMissIPv6UsingAWSRanges1Bucket(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("2620::ffff"), NewIPRanger(), 1, 1, true)
}
func BenchmarkHitIPv4UsingAWSRanges8Bucket(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("52.95.110.1"), NewIPRanger(), 8, 8, true)
}
func BenchmarkHitIPv6UsingAWSRanges8Bucket(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("2620:107:300f::36b7:ff81"), NewIPRanger(), 8, 8, true)
}
func BenchmarkMissIPv4UsingAWSRanges8Bucket(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("123.123.123.123"), NewIPRanger(), 8, 8, true)
}
func BenchmarkMissIPv6UsingAWSRanges8Bucket(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("2620::ffff"), NewIPRanger(), 8, 8, true)
}
func BenchmarkHitIPv4UsingSmallRanges(b *testing.B) {
	ipranger := NewIPRanger()
	ipranger.InsertCIDRStr("192.168.1.0/24")
	ipranger.InsertCIDRStr("128.168.1.0/16")
	ipranger.GenTree(1, 1)
	for n := 0; n < b.N; n++ {
		ipranger.Containstr("128.168.1.0")
	}
}
func BenchmarkMissIPv4UsingSmallRanges(b *testing.B) {
	ipranger := NewIPRanger()
	ipranger.InsertCIDRStr("192.168.1.0/24")
	ipranger.InsertCIDRStr("128.168.1.0/16")
	ipranger.GenTree(1, 1)
	for n := 0; n < b.N; n++ {
		ipranger.Containstr("192.168.2.0")
	}
}

func benchmarkContainsUsingAWSRanges(tb testing.TB, target net.IP, ipranger *IPRanger, v4bucket, v6bucket int, isNonOverlap bool) {
	configureRangerWithAWSRanges(tb, ipranger, v4bucket, v6bucket)
	if isNonOverlap {
		for n := 0; n < tb.(*testing.B).N; n++ {
			ipranger.Contains(target)
		}
	} else {
		for n := 0; n < tb.(*testing.B).N; n++ {
			ipranger.OverlapContains(target)
		}
	}
}

func configureRangerWithAWSRanges(tb testing.TB, ipranger *IPRanger, v4bucket, v6bucket int) {
	for _, prefix := range awsRanges.Prefixes {
		_, network, err := net.ParseCIDR(prefix.IPPrefix)
		assert.NoError(tb, err)
		ipranger.InsertCIDR(network)
	}
	for _, prefix := range awsRanges.IPv6Prefixes {
		_, network, err := net.ParseCIDR(prefix.IPPrefix)
		assert.NoError(tb, err)
		ipranger.InsertCIDR(network)
	}
	ipranger.GenTree(v4bucket, v6bucket)
}

func randIPv4Gen() net.IP {
	buf := make([]byte, 4)
	ip := rand.Uint32()
	binary.LittleEndian.PutUint32(buf, ip)
	return net.IP(buf)
}
func randIPv6Gen() net.IP {
	buf := make([]byte, 8)
	ip := rand.Uint64()
	binary.LittleEndian.PutUint64(buf, ip)
	return net.IP(buf)
}
type AWSRanges struct {
	Prefixes     []Prefix     `json:"prefixes"`
	IPv6Prefixes []IPv6Prefix `json:"ipv6_prefixes"`
}

type Prefix struct {
	IPPrefix string `json:"ip_prefix"`
	Region   string `json:"region"`
	Service  string `json:"service"`
}

type IPv6Prefix struct {
	IPPrefix string `json:"ipv6_prefix"`
	Region   string `json:"region"`
	Service  string `json:"service"`
}

var awsRanges *AWSRanges
var ipV4AWSRangesIPNets []*net.IPNet
var ipV6AWSRangesIPNets []*net.IPNet

func loadAWSRanges() *AWSRanges {
	file, err := os.ReadFile("./testdata/aws_ip_ranges.json")
	if err != nil {
		panic(err)
	}
	var ranges AWSRanges
	err = json.Unmarshal(file, &ranges)
	if err != nil {
		panic(err)
	}
	return &ranges
}

func init() {
	awsRanges = loadAWSRanges()
	for _, prefix := range awsRanges.IPv6Prefixes {
		_, network, _ := net.ParseCIDR(prefix.IPPrefix)
		ipV6AWSRangesIPNets = append(ipV6AWSRangesIPNets, network)
	}
	for _, prefix := range awsRanges.Prefixes {
		_, network, _ := net.ParseCIDR(prefix.IPPrefix)
		ipV4AWSRangesIPNets = append(ipV4AWSRangesIPNets, network)
	}
	rand.Seed(time.Now().Unix())
}
