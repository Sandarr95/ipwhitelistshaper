package ipwhitelistshaper

import (
	"fmt"
	"net"
	"strings"
)


type SourceRangeChecker struct {
	ranges []net.IPNet
}

func NewSourceRangeChecker(sourceRanges []string) (*SourceRangeChecker, error) {
	checker := &SourceRangeChecker{ ranges: make([]net.IPNet, 0, len(sourceRanges)) }
	for _, cidr := range sourceRanges {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" { continue }
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil { checker.ranges = append(checker.ranges, *ipNet); continue }
		ip := net.ParseIP(cidr)
		if ip != nil {
			var mask net.IPMask
			if ip.To4() != nil { mask = net.CIDRMask(32, 32) } else { mask = net.CIDRMask(128, 128) }
			checker.ranges = append(checker.ranges, net.IPNet{IP: ip, Mask: mask})
			continue
		}
		return nil, fmt.Errorf("invalid CIDR or IP address: %s", cidr)
	}
	return checker, nil
}

func (s *SourceRangeChecker) Contains(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil { return false }
	for _, ipNet := range s.ranges { if ipNet.Contains(ip) { return true } }
	return false
}
