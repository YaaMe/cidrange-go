package cidrange

import (
	"net"
	"sort"
)

type IPRanger struct {
	V4NetTree *IPNetTree
	V6NetTree *IPNetTree
}

type IPNetTree struct {
	cidrs []*net.IPNet
	maskKeyList []net.IPMask
	maskTree map[string][]net.IPNet
}

func NewIPRanger() *IPRanger {
	return &IPRanger{
		V4NetTree: newIPNetTree(),
		V6NetTree: newIPNetTree(),
	}
}
func (ranger *IPRanger) InsertCIDRStr(cidr string) {
	_, network, _ := net.ParseCIDR(cidr)
	ranger.InsertCIDR(network)
}

func (ranger *IPRanger) InsertCIDR(cidr *net.IPNet) {
	if cidr.IP.To4() != nil {
		ranger.V4NetTree.insertCIDR(cidr)
	} else {
		ranger.V6NetTree.insertCIDR(cidr)
	}
}
func (ranger *IPRanger) GenTree(v4bucket, v6bucket int) {
	if v4bucket <= 0 {
		v4bucket = 2
	}
	if v6bucket <= 0 {
		v6bucket = 4
	}
	ranger.V4NetTree.genTree(v4bucket)
	ranger.V6NetTree.genTree(v6bucket)
}

func (ranger *IPRanger) Containstr(ip string) bool {
	return ranger.Contains(net.ParseIP(ip))
}
func (ranger *IPRanger) Contains(ip net.IP) bool {
	if ip.To4() != nil {
		return ranger.V4NetTree.Contains(ip)
	}
	return ranger.V6NetTree.Contains(ip)
}

func (ranger *IPRanger) ViewMaskKeyList() ([]net.IPMask, []net.IPMask) {
	return ranger.V4NetTree.maskKeyList, ranger.V6NetTree.maskKeyList
}

func newIPNetTree() *IPNetTree {
	return &IPNetTree{
		cidrs: make([]*net.IPNet, 0),
		maskTree: make(map[string][]net.IPNet),
	}
}
func (self *IPNetTree) Contains(ip net.IP) bool {
	for _, mask := range self.maskKeyList {
		ipkey := ip.Mask(mask)
		cidrs, exists := self.maskTree[ipkey.String()]
		if exists {
			for _, cidr := range cidrs {
				if cidr.Contains(ip) {
					return true
				}
			}
			return false
		}
	}
	return false
}
func (self *IPNetTree) insertCIDR(cidr *net.IPNet) {
	self.cidrs = append(self.cidrs, cidr)
}

func (self *IPNetTree) genTree(buckets int) {
	self.sortCIDR()
	if len(self.cidrs) == 0 {
		return
	}
	cidrs := self.cidrs
	bucketSize := len(cidrs) / buckets
	if len(cidrs) % buckets != 0 {
		bucketSize += 1
	}
	chunks := make([]*net.IPNet, 0)
	lastOne, _ := cidrs[0].Mask.Size()
	for _, cidr := range cidrs {
		one, _ := cidr.Mask.Size()
		if one == lastOne {
			chunks = append(chunks, cidr)
		} else {
			if len(chunks) >= bucketSize {
				self.solveChunks(chunks)
				chunks = make([]*net.IPNet, 0)
			}
			lastOne = one
		}
	}
	if len(chunks) > 0 {
		self.solveChunks(chunks)
	}
}


func (self *IPNetTree) solveChunks(targets []*net.IPNet) int {
	one, size := targets[len(targets)-1].Mask.Size()
	mask := net.CIDRMask(one, size)
	self.maskKeyList = append(self.maskKeyList, mask)
	for _, target := range targets {
		ipkey := target.IP.Mask(mask)
		self.insertNode(ipkey, *target)
	}
	return one
}
func (self *IPNetTree) sortCIDR() {
	sort.Slice(self.cidrs, func(i, j int) bool {
		a, _ := self.cidrs[i].Mask.Size()
		b, _ := self.cidrs[j].Mask.Size()
		return a > b
	})
}
func (self *IPNetTree) insertNode(ipkey net.IP, ipnet net.IPNet) {
	key := ipkey.String()
	cidrSet, exists := self.maskTree[key]
	if !exists {
		cidrSet = make([]net.IPNet, 0)
	}
	self.maskTree[key] = append(cidrSet, ipnet)
}
