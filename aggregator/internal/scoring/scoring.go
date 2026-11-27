// Package scoring implements the in-memory IP prefix + MaxMind GeoIP/ASN
// risk scorer for zero-allocation IP/ASN enrichment.
package scoring

import (
	"fmt"
	"net"
	"sort"
	"sync"
)

// MMDBReader is the interface for MaxMind mmdb lookups.
// Implementations can use github.com/oschwald/geoip2-golang or a stub.
type MMDBReader interface {
	// Lookup returns country, city, ASN, and organization for an IP.
	Lookup(ip net.IP) (country string, city string, asn string, org string, err error)
}

// prefixEntry is a CIDR prefix with a score modifier.
type prefixEntry struct {
	network *net.IPNet
	score   float64
}

// PrefixTable holds IP prefix -> score modifier mappings.
type PrefixTable struct {
	ipv4 []prefixEntry
	ipv6 []prefixEntry
	mu   sync.RWMutex
}

// NewPrefixTable creates an empty prefix table.
func NewPrefixTable() *PrefixTable {
	return &PrefixTable{}
}

// Insert adds a CIDR prefix with a score modifier.
func (pt *PrefixTable) Insert(cidr string, score float64) error {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	_, netw, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse CIDR %s: %w", cidr, err)
	}
	entry := prefixEntry{network: netw, score: score}
	if ipv4 := netw.IP.To4(); ipv4 != nil {
		pt.ipv4 = append(pt.ipv4, entry)
		// Sort by prefix length descending (most specific first)
		sort.Slice(pt.ipv4, func(i, j int) bool {
			bi, _ := pt.ipv4[i].network.Mask.Size()
			bj, _ := pt.ipv4[j].network.Mask.Size()
			return bi > bj
		})
	} else {
		pt.ipv6 = append(pt.ipv6, entry)
		sort.Slice(pt.ipv6, func(i, j int) bool {
			bi, _ := pt.ipv6[i].network.Mask.Size()
			bj, _ := pt.ipv6[j].network.Mask.Size()
			return bi > bj
		})
	}
	return nil
}

// Lookup returns the score modifier for the most specific matching prefix.
func (pt *PrefixTable) Lookup(ip string) (float64, bool) {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return 0, false
	}
	if ipv4 := parsed.To4(); ipv4 != nil {
		for _, entry := range pt.ipv4 {
			if entry.network.Contains(parsed) {
				return entry.score, true
			}
		}
	} else {
		for _, entry := range pt.ipv6 {
			if entry.network.Contains(parsed) {
				return entry.score, true
			}
		}
	}
	return 0, false
}

// RiskInputs contains all inputs for risk scoring.
type RiskInputs struct {
	IP               string
	Correlation      CorrelationResult
	Geo              GeoInfo
	IsConfirmedC2    bool
	IsResidentialVPS bool
	ExtractedIOCs    []string
}

// CorrelationResult is the output from the correlation engine.
type CorrelationResult struct {
	IsHighConfidence bool
	ReconSeen        bool
	ExploitSeen      bool
	RiskMultiplier   float64
	TTL              int // hours
}

// GeoInfo contains GeoIP/ASN enrichment data.
type GeoInfo struct {
	Country string
	City    string
	ASN     string
	Org     string
}

// RiskScore is the output of risk scoring.
type RiskScore struct {
	Score         float64 // 0-100
	RiskLevel     string  // low, medium, high, critical
	TTLHours      int
	Geo           GeoInfo
	Factors       []string
	ExtractedIOCs []string
}

// Scorer combines correlation, GeoIP/ASN, and prefix data into a risk score.
type Scorer struct {
	prefixTable *PrefixTable
	mmdb        MMDBReader
	mu          sync.RWMutex
}

// NewScorer creates a risk scorer.
func NewScorer(mmdb MMDBReader) *Scorer {
	return &Scorer{
		prefixTable: NewPrefixTable(),
		mmdb:        mmdb,
	}
}

// InsertPrefix adds a prefix/score to the prefix table.
func (s *Scorer) InsertPrefix(cidr string, score float64) error {
	return s.prefixTable.Insert(cidr, score)
}

// Score computes a risk score for the given inputs.
func (s *Scorer) Score(inputs RiskInputs) RiskScore {
	s.mu.RLock()
	prefixScore, hasPrefix := s.prefixTable.Lookup(inputs.IP)
	mmdb := s.mmdb
	s.mu.RUnlock()

	var geo GeoInfo
	var err error
	if mmdb != nil {
		geo.Country, geo.City, geo.ASN, geo.Org, err = mmdb.Lookup(net.ParseIP(inputs.IP))
	}
	if err != nil {
		geo = GeoInfo{}
	}

	score := 0.0
	var factors []string

	if hasPrefix {
		score += prefixScore * 10
		factors = append(factors, fmt.Sprintf("prefix_match:%.1f", prefixScore))
	}

	if inputs.Correlation.IsHighConfidence {
		score += 40 * inputs.Correlation.RiskMultiplier
		factors = append(factors, "high_confidence_correlation")
	} else if inputs.Correlation.ReconSeen {
		score += 10
		factors = append(factors, "recon_only")
	} else if inputs.Correlation.ExploitSeen {
		score += 25
		factors = append(factors, "exploit_only")
	}

	if inputs.IsConfirmedC2 {
		score += 30
		factors = append(factors, "confirmed_c2")
	}

	if inputs.IsResidentialVPS {
		score += 15
		factors = append(factors, "residential_vps")
	}

	if geo.ASN != "" {
		score += 5
		factors = append(factors, fmt.Sprintf("asn:%s", geo.ASN))
	}

	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}

	riskLevel := riskLevel(score)

	ttl := inputs.Correlation.TTL
	if ttl == 0 {
		if inputs.IsConfirmedC2 {
			ttl = 14 * 24
		} else if inputs.IsResidentialVPS {
			ttl = 12
		} else {
			ttl = 6
		}
	}

	return RiskScore{
		Score:         score,
		RiskLevel:     riskLevel,
		TTLHours:      ttl,
		Geo:           geo,
		Factors:       factors,
		ExtractedIOCs: inputs.ExtractedIOCs,
	}
}

func riskLevel(score float64) string {
	switch {
	case score >= 75:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 25:
		return "medium"
	default:
		return "low"
	}
}

// StubMMDB is a no-op MMDBReader for testing without MaxMind data.
type StubMMDB struct{}

// Lookup returns empty values.
func (s *StubMMDB) Lookup(ip net.IP) (string, string, string, string, error) {
	return "", "", "", "", nil
}
