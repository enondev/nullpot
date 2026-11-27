package specs

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestThreatEventRoundTrip(t *testing.T) {
	ev := ThreatEvent{
		ClassUID:    2004,
		CategoryUID: 2,
		ActivityID:  1,
		Time:        time.Date(2026, 11, 27, 3, 56, 0, 0, time.UTC),
		Metadata: Metadata{
			Version: "1.3.0",
			Product: Product{Name: "EdgeTrapSensor", UID: "edge-01", Region: "eu-central"},
		},
		SrcEndpoint: Endpoint{IP: "203.0.113.45", Port: 54321},
		DstEndpoint: Endpoint{Port: 11434},
		FindingInfo: FindingInfo{
			UID:   "evt_01jf9x8z7y6w5v4u3t2s1r",
			Title: "LLM Inference Prompt Injection",
			Types: []string{"exploit_attempt"},
		},
		Enrichment: Enrichment{
			Module:         "http_persona",
			PersonaID:      "llm-ollama-v0.5",
			Fingerprint:    "ja4_or_client_banner",
			CanaryID:       "cnry_9f8a7b6c5d4e",
			PayloadPreview: "POST /api/generate ...",
			PayloadSHA256:  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			ExtractedIOCs:  []string{"http://198.51.100.1"},
		},
	}

	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded ThreatEvent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !reflect.DeepEqual(ev, decoded) {
		t.Fatalf("round trip mismatch:\n got=%+v\n want=%+v", decoded, ev)
	}
}

func TestThreatEventValidate(t *testing.T) {
	valid := &ThreatEvent{
		ClassUID:    2004,
		CategoryUID: 2,
		ActivityID:  1,
		Time:        time.Now(),
		Metadata:    Metadata{Version: "1.3.0", Product: Product{Name: "x", UID: "y"}},
		FindingInfo: FindingInfo{UID: "uid", Title: "t", Types: []string{"exploit_attempt"}},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid event should validate: %v", err)
	}

	cases := []struct {
		name string
		ev   *ThreatEvent
	}{
		{"zero class_uid", &ThreatEvent{CategoryUID: 2, ActivityID: 1, Time: time.Now(), Metadata: Metadata{Product: Product{Name: "x", UID: "y"}}, FindingInfo: FindingInfo{UID: "u", Title: "t", Types: []string{"x"}}}},
		{"missing product name", &ThreatEvent{ClassUID: 2004, CategoryUID: 2, ActivityID: 1, Time: time.Now(), Metadata: Metadata{Product: Product{UID: "y"}}, FindingInfo: FindingInfo{UID: "u", Title: "t", Types: []string{"x"}}}},
		{"empty finding uid", &ThreatEvent{ClassUID: 2004, CategoryUID: 2, ActivityID: 1, Time: time.Now(), Metadata: Metadata{Product: Product{Name: "x", UID: "y"}}, FindingInfo: FindingInfo{Title: "t", Types: []string{"x"}}}},
		{"empty types", &ThreatEvent{ClassUID: 2004, CategoryUID: 2, ActivityID: 1, Time: time.Now(), Metadata: Metadata{Product: Product{Name: "x", UID: "y"}}, FindingInfo: FindingInfo{UID: "u", Title: "t"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.ev.Validate(); err == nil {
				t.Fatalf("expected validation error")
			}
		})
	}
}

func TestConstants(t *testing.T) {
	if ClassUIDNetworkActivity != 2004 {
		t.Errorf("ClassUIDNetworkActivity = %d, want 2004", ClassUIDNetworkActivity)
	}
	if CategoryUIDPotentialSecurityIssue != 2 {
		t.Errorf("CategoryUIDPotentialSecurityIssue = %d, want 2", CategoryUIDPotentialSecurityIssue)
	}
	if ActivityIDCreate != 1 {
		t.Errorf("ActivityIDCreate = %d, want 1", ActivityIDCreate)
	}
}
