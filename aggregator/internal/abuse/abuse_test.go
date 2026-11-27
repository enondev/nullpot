package abuse

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/enondev/nullpot/specs"
)

func TestShouldDispatchPortScanExcluded(t *testing.T) {
	ev := specs.ThreatEvent{
		Enrichment: specs.Enrichment{
			Module:        "widenet",
			PayloadSHA256: "abc",
			ExtractedIOCs: []string{"http://x"},
			CanaryID:      "cnry_123",
		},
		FindingInfo: specs.FindingInfo{
			Types: []string{"port_scan"},
		},
	}
	if ShouldDispatch(ev) {
		t.Fatal("port scan should never be dispatched")
	}
}

func TestShouldDispatchSSHWithEvidence(t *testing.T) {
	ev := specs.ThreatEvent{
		Enrichment: specs.Enrichment{
			Module:        "ssh",
			PayloadSHA256: "abc123",
			ExtractedIOCs: []string{"http://evil.com"},
			CanaryID:      "cnry_123",
		},
		FindingInfo: specs.FindingInfo{
			Types: []string{"exploit_attempt"},
		},
	}
	if !ShouldDispatch(ev) {
		t.Fatal("SSH exploit with evidence should be dispatched")
	}
}

func TestShouldDispatchHTTPWithCanary(t *testing.T) {
	ev := specs.ThreatEvent{
		Enrichment: specs.Enrichment{
			Module:   "http_persona",
			CanaryID: "cnry_123",
		},
		FindingInfo: specs.FindingInfo{
			Types: []string{"exploit_attempt"},
		},
	}
	if !ShouldDispatch(ev) {
		t.Fatal("HTTP persona with canary token should be dispatched")
	}
}

func TestShouldDispatchNoEvidence(t *testing.T) {
	ev := specs.ThreatEvent{
		Enrichment: specs.Enrichment{
			Module: "ssh",
		},
		FindingInfo: specs.FindingInfo{
			Types: []string{"exploit_attempt"},
		},
	}
	if ShouldDispatch(ev) {
		t.Fatal("SSH exploit without evidence should not be dispatched")
	}
}

func TestShouldDispatchWidenetExcluded(t *testing.T) {
	ev := specs.ThreatEvent{
		Enrichment: specs.Enrichment{
			Module:        "widenet",
			PayloadSHA256: "abc",
		},
		FindingInfo: specs.FindingInfo{
			Types: []string{"port_scan"},
		},
	}
	if ShouldDispatch(ev) {
		t.Fatal("widenet should not be dispatched")
	}
}

func TestBuildReport(t *testing.T) {
	ev := specs.ThreatEvent{
		ClassUID:    2004,
		CategoryUID: 2,
		ActivityID:  1,
		Time:        time.Now().UTC(),
		Metadata: specs.Metadata{
			Version: "1.3.0",
			Product: specs.Product{Name: "sensor", UID: "s1"},
		},
		SrcEndpoint: specs.Endpoint{IP: "203.0.113.45", Port: 54321},
		DstEndpoint: specs.Endpoint{IP: "198.51.100.1", Port: 22},
		FindingInfo: specs.FindingInfo{
			UID:   "evt-123",
			Title: "SSH dropper attempt",
			Types: []string{"exploit_attempt", "malware_drop"},
		},
		Enrichment: specs.Enrichment{
			Module:        "ssh",
			PayloadSHA256: "sha256hash",
			ExtractedIOCs: []string{"http://evil.com/payload"},
			CanaryID:      "cnry_abc",
		},
	}
	reporter := XARFReporter{Name: "nullpot", Contact: "abuse@nullpot.internal"}
	report := BuildReport(ev, reporter)

	if report.Version != "1.0" {
		t.Fatalf("expected version 1.0, got %s", report.Version)
	}
	if report.Incident.Title != "SSH dropper attempt" {
		t.Fatalf("unexpected title: %s", report.Incident.Title)
	}
	if report.Incident.SourceIP != "203.0.113.45" {
		t.Fatalf("unexpected source IP: %s", report.Incident.SourceIP)
	}
	if report.Incident.TargetIP != "198.51.100.1" {
		t.Fatalf("unexpected target IP: %s", report.Incident.TargetIP)
	}
	if report.Incident.TargetPort != 22 {
		t.Fatalf("unexpected target port: %d", report.Incident.TargetPort)
	}
	if report.Evidence.PayloadSHA256 != "sha256hash" {
		t.Fatalf("unexpected payload hash: %s", report.Evidence.PayloadSHA256)
	}
	if len(report.Evidence.ExtractedIOCs) != 1 || report.Evidence.ExtractedIOCs[0] != "http://evil.com/payload" {
		t.Fatalf("unexpected IOCs: %v", report.Evidence.ExtractedIOCs)
	}
	if len(report.Evidence.CanaryTokens) != 1 || report.Evidence.CanaryTokens[0] != "cnry_abc" {
		t.Fatalf("unexpected canary tokens: %v", report.Evidence.CanaryTokens)
	}
	if report.Reporter.Name != "nullpot" {
		t.Fatalf("unexpected reporter: %s", report.Reporter.Name)
	}
}

func TestBuildReportNoCanary(t *testing.T) {
	ev := specs.ThreatEvent{
		Enrichment: specs.Enrichment{
			Module:        "ssh",
			PayloadSHA256: "hash",
			CanaryID:      "",
		},
		FindingInfo: specs.FindingInfo{
			UID:   "evt-1",
			Title: "test",
			Types: []string{"exploit_attempt"},
		},
	}
	report := BuildReport(ev, XARFReporter{Name: "x"})
	if len(report.Evidence.CanaryTokens) != 0 {
		t.Fatal("expected no canary tokens when CanaryID is empty")
	}
}

func TestDispatcherDispatch(t *testing.T) {
	var received []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		r.Body.Read(body)
		received = append(received, string(body))
		w.WriteHeader(200)
	}))
	defer server.Close()

	d := NewDispatcher(map[string]string{"test": server.URL}, XARFReporter{Name: "test"})
	report := XARFReport{UUID: "xarf-1"}

	if err := d.Dispatch(report); err != nil {
		t.Fatalf("dispatch: %v", err)
	}

	if len(received) != 1 {
		t.Fatalf("expected 1 report, got %d", len(received))
	}
	if d.DispatchCount() != 1 {
		t.Fatalf("expected dispatch count 1, got %d", d.DispatchCount())
	}
}

func TestDispatcherDispatchFailure(t *testing.T) {
	d := NewDispatcher(map[string]string{"bad": "http://127.0.0.1:1/xarf"}, XARFReporter{Name: "test"})
	report := XARFReport{UUID: "xarf-2"}

	err := d.Dispatch(report)
	if err == nil {
		t.Fatal("expected error for unreachable endpoint")
	}
}

func TestDispatcherGetDispatched(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer server.Close()

	d := NewDispatcher(map[string]string{"test": server.URL}, XARFReporter{Name: "test"})
	d.Dispatch(XARFReport{UUID: "xarf-1"})
	d.Dispatch(XARFReport{UUID: "xarf-2"})

	reports := d.GetDispatched()
	if len(reports) != 2 {
		t.Fatalf("expected 2 reports, got %d", len(reports))
	}
	if reports[0].UUID != "xarf-1" || reports[1].UUID != "xarf-2" {
		t.Fatalf("unexpected report order: %+v", reports)
	}
}
