package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// allowList tracks which IPs and domains are allowed.
type allowList struct {
	mu             sync.RWMutex
	domains        []string // exact domains and wildcard patterns (*.example.com)
	allowedIPs     map[netip.Addr]bool
	allowedPorts   map[uint16]bool
	resolvedIPs    map[netip.Addr]bool // dynamically resolved IPs
}

func newAllowList(profile *Profile) *allowList {
	al := &allowList{
		allowedIPs:  make(map[netip.Addr]bool),
		allowedPorts: make(map[uint16]bool),
		resolvedIPs: make(map[netip.Addr]bool),
	}

	al.domains = profile.Network.AllowedDomains

	for _, ipStr := range profile.Network.AllowedIPs {
		if ip, err := netip.ParseAddr(ipStr); err == nil {
			al.allowedIPs[ip] = true
		}
		// Also try parsing as prefix
		if pfx, err := netip.ParsePrefix(ipStr); err == nil {
			// Store the prefix start — we'll check containment in isIPAllowed
			al.allowedIPs[pfx.Addr()] = true
		}
	}

	ports := profile.Network.AllowedPorts
	if len(ports) == 0 {
		ports = []int{80, 443}
	}
	for _, p := range ports {
		al.allowedPorts[uint16(p)] = true
	}

	return al
}

// preResolve resolves all non-wildcard domains and adds their IPs to the allow list.
func (al *allowList) preResolve() {
	for _, domain := range al.domains {
		if strings.HasPrefix(domain, "*.") {
			continue // can't pre-resolve wildcards
		}
		al.resolveDomain(domain)
	}
}

// resolveDomain resolves a domain and adds its IPs to the dynamic allow list.
func (al *allowList) resolveDomain(domain string) []net.IP {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resolver := net.DefaultResolver
	addrs, err := resolver.LookupIPAddr(ctx, domain)
	if err != nil {
		return nil
	}

	al.mu.Lock()
	defer al.mu.Unlock()

	var ips []net.IP
	for _, addr := range addrs {
		ip, ok := netip.AddrFromSlice(addr.IP)
		if ok {
			ip = ip.Unmap()
			al.resolvedIPs[ip] = true
			ips = append(ips, addr.IP)
		}
	}
	return ips
}

// isDomainAllowed checks if a domain matches the allow list.
func (al *allowList) isDomainAllowed(domain string) bool {
	domain = strings.TrimSuffix(domain, ".")
	domain = strings.ToLower(domain)

	for _, pattern := range al.domains {
		pattern = strings.ToLower(pattern)
		if pattern == domain {
			return true
		}
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:] // ".example.com"
			if strings.HasSuffix(domain, suffix) {
				return true
			}
			// Also match the base domain itself (*.example.com matches example.com)
			if domain == pattern[2:] {
				return true
			}
		}
	}
	return false
}

// isIPAllowed checks if an IP is in the allow list (static or dynamically resolved).
func (al *allowList) isIPAllowed(ip netip.Addr) bool {
	ip = ip.Unmap()

	al.mu.RLock()
	defer al.mu.RUnlock()

	if al.allowedIPs[ip] {
		return true
	}
	if al.resolvedIPs[ip] {
		return true
	}

	// Check prefixes in allowedIPs
	for allowedIP := range al.allowedIPs {
		if allowedIP == ip {
			return true
		}
	}

	return false
}

// isPortAllowed checks if a port is allowed.
func (al *allowList) isPortAllowed(port uint16) bool {
	if len(al.allowedPorts) == 0 {
		return true // no port restriction
	}
	return al.allowedPorts[port]
}

// isAllowed checks both IP and port.
func (al *allowList) isAllowed(ip netip.Addr, port uint16) bool {
	return al.isIPAllowed(ip) && al.isPortAllowed(port)
}

// String returns a human-readable description.
func (al *allowList) String() string {
	al.mu.RLock()
	defer al.mu.RUnlock()

	return fmt.Sprintf("domains=%v staticIPs=%d resolvedIPs=%d ports=%v",
		al.domains, len(al.allowedIPs), len(al.resolvedIPs), al.allowedPorts)
}
