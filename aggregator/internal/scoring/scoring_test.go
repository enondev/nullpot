package scoring

import (
	"net"
	"testing"
)

func TestPrefixTableInsertLookup(t *testing.T) {
	pt := NewPrefixTable()
	if err := pt.Insert("203.0.113.0/24", 0.5); err != nil {
		t.Fatalf("insert: %v", err)
	}

	score, found := pt.Lookup("203.0.113.45")
	if !found || score != 0.5 {
		t.Fatalf("expected score 0.5, got %v, found %v", score, found)
	}

	score, found = pt.Lookup("198.51.100.1")
	if found {
		t.Fatal("expected no match for non-prefix IP")
	}
}

func TestPrefixTableMostSpecific(t *testing.T) {
	pt := NewPrefixTable()
	pt.Insert("203.0.113.0/24", 0.5)
	pt.Insert("203.0.113.45/32", 1.0)

	score, _ := pt.Lookup("203.0.113.45")
	if score != 1.0 {
		t.Fatalf("expected most specific prefix score 1.0, got %f", score)
	}
}

func TestPrefixTableInvalidCIDR(t *testing.T) {
	pt := NewPrefixTable()
	if err := pt.Insert("not-a-cidr", 0.5); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestScorerBasics(t *testing.T) {
	s := NewScorer(&StubMMDB{})

	inputs := RiskInputs{
		IP: "203.0.113.45",
		Correlation: CorrelationResult{
			IsHighConfidence: false,
			ReconSeen:        true,
			ExploitSeen:      false,
			RiskMultiplier:   1.0,
			TTL:              6,
		},
	}

	score := s.Score(inputs)
	if score.RiskLevel != "low" {
		t.Fatalf("expected low risk for recon-only, got %s", score.RiskLevel)
	}
	if score.Score != 10 {
		t.Fatalf("expected score 10 for recon, got %f", score.Score)
	}
}

func TestScorerHighConfidence(t *testing.T) {
	s := NewScorer(&StubMMDB{})

	inputs := RiskInputs{
		IP: "203.0.113.45",
		Correlation: CorrelationResult{
			IsHighConfidence: true,
			ReconSeen:        true,
			ExploitSeen:      true,
			RiskMultiplier:   10.0,
			TTL:              168, // 7 days
		},
		IsConfirmedC2: true,
	}

	score := s.Score(inputs)
	if score.RiskLevel != "critical" {
		t.Fatalf("expected critical risk for confirmed C2 + high confidence, got %s", score.RiskLevel)
	}
	if score.Score < 75 {
		t.Fatalf("expected score >= 75 for critical, got %f", score.Score)
	}
	if score.TTLHours != 168 {
		t.Fatalf("expected TTL 168h, got %d", score.TTLHours)
	}
}

func TestScorerDefaultTTL(t *testing.T) {
	s := NewScorer(&StubMMDB{})

	// Confirmed C2 default TTL
	inputs := RiskInputs{
		IP:            "203.0.113.45",
		IsConfirmedC2: true,
		Correlation:   CorrelationResult{TTL: 0},
	}
	score := s.Score(inputs)
	if score.TTLHours != 14*24 {
		t.Fatalf("expected C2 default TTL 336h, got %d", score.TTLHours)
	}

	// Residential VPS default TTL
	inputs = RiskInputs{
		IP:               "203.0.113.45",
		IsResidentialVPS: true,
		Correlation:      CorrelationResult{TTL: 0},
	}
	score = s.Score(inputs)
	if score.TTLHours != 12 {
		t.Fatalf("expected residential default TTL 12h, got %d", score.TTLHours)
	}

	// Default TTL
	inputs = RiskInputs{
		IP:          "203.0.113.45",
		Correlation: CorrelationResult{TTL: 0},
	}
	score = s.Score(inputs)
	if score.TTLHours != 6 {
		t.Fatalf("expected default TTL 6h, got %d", score.TTLHours)
	}
}

func TestRiskLevel(t *testing.T) {
	cases := []struct {
		score float64
		level string
	}{
		{0, "low"},
		{10, "low"},
		{24, "low"},
		{25, "medium"},
		{49, "medium"},
		{50, "high"},
		{74, "high"},
		{75, "critical"},
		{100, "critical"},
	}
	for _, c := range cases {
		if got := riskLevel(c.score); got != c.level {
			t.Fatalf("riskLevel(%f) = %s, want %s", c.score, got, c.level)
		}
	}
}

func TestScoreClamps(t *testing.T) {
	s := NewScorer(&StubMMDB{})

	// High score should clamp to 100
	inputs := RiskInputs{
		IP: "203.0.113.45",
		Correlation: CorrelationResult{
			IsHighConfidence: true,
			RiskMultiplier:   10.0,
		},
		IsConfirmedC2: true,
	}
	if err := s.InsertPrefix("203.0.113.0/24", 10.0); err != nil {
		t.Fatalf("insert: %v", err)
	}
	score := s.Score(inputs)
	if score.Score > 100 {
		t.Fatalf("score should clamp to 100, got %f", score.Score)
	}

	// Negative should clamp to 0
	inputs2 := RiskInputs{
		IP: "198.51.100.1",
		Correlation: CorrelationResult{
			IsHighConfidence: false,
			ReconSeen:        false,
			ExploitSeen:      false,
		},
	}
	score2 := s.Score(inputs2)
	if score2.Score < 0 {
		t.Fatalf("score should clamp to 0, got %f", score2.Score)
	}
}

func TestStubMMDB(t *testing.T) {
	stub := &StubMMDB{}
	country, city, asn, org, err := stub.Lookup(net.ParseIP("203.0.113.45"))
	if err != nil {
		t.Fatalf("stub lookup: %v", err)
	}
	if country != "" || city != "" || asn != "" || org != "" {
		t.Fatal("stub should return empty values")
	}
}
