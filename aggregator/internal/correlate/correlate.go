// Package correlate implements the double-verification engine, C2/IOC
// extractor, researcher allowlist, and TTL decay policy.
package correlate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// CorrelationResult is the output of double-verification correlation.
type CorrelationResult struct {
	IsHighConfidence bool
	ReconSeen        bool
	ExploitSeen      bool
	SameSubnet       bool
	RiskMultiplier   float64
	TTL              time.Duration
}

// Engine correlates Widenet port sweeps with domain-specific trap hits.
type Engine struct {
	mu     sync.RWMutex
	sweeps map[string][]time.Time // IP -> sweep timestamps
	hits   map[string][]time.Time // IP -> hit timestamps
	ttlMap map[string]time.Duration
}

// NewEngine creates a correlation engine.
func NewEngine() *Engine {
	return &Engine{
		sweeps: make(map[string][]time.Time),
		hits:   make(map[string][]time.Time),
		ttlMap: make(map[string]time.Duration),
	}
}

// RecordSweep records a Widenet port sweep from an IP.
func (e *Engine) RecordSweep(ip string, ts time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sweeps[ip] = append(e.sweeps[ip], ts)
	e.pruneMap(e.sweeps, ip)
}

// RecordHit records a domain-specific trap hit from an IP.
func (e *Engine) RecordHit(ip string, ts time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.hits[ip] = append(e.hits[ip], ts)
	e.pruneMap(e.hits, ip)
}

// Correlate performs double-verification: recon + exploit from same IP/subnet.
func (e *Engine) Correlate(ip string, ts time.Time) CorrelationResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	sweepTimes, hasSweep := e.sweeps[ip]
	hitTimes, hasHit := e.hits[ip]

	result := CorrelationResult{
		ReconSeen:   hasSweep,
		ExploitSeen: hasHit,
	}

	if hasSweep && hasHit {
		// Check if any hit follows a sweep within the same IP (double verification)
		for _, st := range sweepTimes {
			for _, ht := range hitTimes {
				if ht.After(st) && ht.Sub(st) <= 24*time.Hour {
					result.IsHighConfidence = true
					result.RiskMultiplier = 10.0
					result.TTL = 7 * 24 * time.Hour // long TTL for confirmed attackers
					result.SameSubnet = true
					return result
				}
			}
		}
	}

	if hasSweep && !hasHit {
		result.TTL = 6 * time.Hour // short TTL for sweep-only IPs
		return result
	}

	if hasHit && !hasSweep {
		result.TTL = 24 * time.Hour
		return result
	}

	result.TTL = 1 * time.Hour
	return result
}

func (e *Engine) pruneMap(m map[string][]time.Time, ip string) {
	cutoff := time.Now().Add(-24 * time.Hour)
	times := m[ip]
	var valid []time.Time
	for _, t := range times {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	if len(valid) == 0 {
		delete(m, ip)
	} else {
		m[ip] = valid
	}
}

// --- C2/IOC Extractor ---

var (
	urlRegex    = regexp.MustCompile(`https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+`)
	domainRegex = regexp.MustCompile(`([a-zA-Z0-9\-]+\.[a-zA-Z]{2,})`)
	ipv4Regex   = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)
)

// ExtractedIOC is a single extracted indicator of compromise.
type ExtractedIOC struct {
	Type  string `json:"type"` // url, domain, ip, c2_domain
	Value string `json:"value"`
}

// C2Extractor extracts C2 domains, URLs, and callback targets from captured
// commands/prompts.
type C2Extractor struct{}

// NewC2Extractor creates an extractor.
func NewC2Extractor() *C2Extractor {
	return &C2Extractor{}
}

// Extract parses content and returns extracted IOCs.
func (x *C2Extractor) Extract(content string) []ExtractedIOC {
	var iocs []ExtractedIOC
	seen := make(map[string]bool)

	// Extract URLs
	for _, m := range urlRegex.FindAllString(content, -1) {
		if !seen[m] {
			seen[m] = true
			iocs = append(iocs, ExtractedIOC{Type: "url", Value: m})
		}
	}

	// Extract domains from URLs and standalone
	for _, m := range domainRegex.FindAllString(content, -1) {
		if !seen[m] {
			seen[m] = true
			iocs = append(iocs, ExtractedIOC{Type: "domain", Value: m})
		}
	}

	// Extract IPs
	for _, m := range ipv4Regex.FindAllString(content, -1) {
		if !seen[m] && isValidIPv4(m) {
			seen[m] = true
			iocs = append(iocs, ExtractedIOC{Type: "ip", Value: m})
		}
	}

	return iocs
}

func isValidIPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

// ScoreASN returns a risk multiplier for an ASN. Confirmed C2/malware
// hosting ASNs score 10x higher than disposable residential scanner IPs.
func ScoreASN(asn string, isConfirmedC2 bool) float64 {
	if isConfirmedC2 {
		return 10.0
	}
	return 1.0
}

// --- Researcher Allowlist ---

var researcherPatterns = []string{
	"shodan", "censys", "shadowserver", "googlebot", "bingbot",
	"applebot", "slackbot", "discordbot", "facebookexternalhit",
}

// Allowlist checks if an IP belongs to a known benign researcher/scanner.
type Allowlist struct {
	mu       sync.RWMutex
	networks []*net.IPNet
}

// NewAllowlist creates an empty allowlist.
func NewAllowlist() *Allowlist {
	return &Allowlist{}
}

// AddNetwork adds a CIDR range to the allowlist.
func (a *Allowlist) AddNetwork(cidr string) error {
	_, netw, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse CIDR %s: %w", cidr, err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.networks = append(a.networks, netw)
	return nil
}

// IsAllowed returns true if the IP is in the allowlist.
func (a *Allowlist) IsAllowed(ip string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, netw := range a.networks {
		if netw.Contains(parsed) {
			return true
		}
	}
	return false
}

// IsResearcher checks reverse-DNS/ASN patterns for known benign scanners.
func IsResearcher(reverseDNS, asnOrg string) bool {
	combined := strings.ToLower(reverseDNS + " " + asnOrg)
	for _, p := range researcherPatterns {
		if strings.Contains(combined, p) {
			return true
		}
	}
	return false
}

// --- TTL Decay ---

// TTLPolicy assigns TTLs based on confidence and infrastructure type.
type TTLPolicy struct{}

// NewTTLPolicy creates a TTL policy.
func NewTTLPolicy() *TTLPolicy {
	return &TTLPolicy{}
}

// TTLFor returns the TTL for an IP based on its classification.
func (p *TTLPolicy) TTLFor(isConfirmedC2, isResidentialVPS bool) time.Duration {
	if isConfirmedC2 {
		// Long TTL: 7-30 days for confirmed C2/malware staging
		return 14 * 24 * time.Hour
	}
	if isResidentialVPS {
		// Short TTL: 6-24 hours for compromised residential/VPS scanner IPs
		return 12 * time.Hour
	}
	return 6 * time.Hour
}

// FingerprintHash returns a SHA-256 hash of input for fingerprinting.
func FingerprintHash(input string) string {
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])
}

// SortIOCs sorts extracted IOCs by type then value for deterministic output.
func SortIOCs(iocs []ExtractedIOC) {
	sort.Slice(iocs, func(i, j int) bool {
		if iocs[i].Type != iocs[j].Type {
			return iocs[i].Type < iocs[j].Type
		}
		return iocs[i].Value < iocs[j].Value
	})
}
