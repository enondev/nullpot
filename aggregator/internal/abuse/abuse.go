// Package abuse implements the automated XARF report dispatcher for confirmed
// compromised hosts. Reports are only dispatched for high-confidence,
// evidence-backed exploitation/malware drops — never for single-packet port
// scans.
package abuse

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/enondev/nullpot/specs"
)

// XARFReport is an eXtended Abuse Reporting Format abuse report.
type XARFReport struct {
	Version   string       `json:"version"`
	UUID      string       `json:"uuid"`
	Generated string       `json:"generated"`
	Reporter  XARFReporter `json:"reporter"`
	Incident  XARFIncident `json:"incident"`
	Evidence  XARFEvidence `json:"evidence"`
}

// XARFReporter is the entity filing the report.
type XARFReporter struct {
	Name    string `json:"name"`
	Contact string `json:"contact"`
}

// XARFIncident describes the abuse incident.
type XARFIncident struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	StartTime   string `json:"start_time"`
	EndTime     string `json:"end_time"`
	SourceIP    string `json:"source_ip"`
	TargetIP    string `json:"target_ip,omitempty"`
	TargetPort  uint16 `json:"target_port,omitempty"`
	ASN         string `json:"asn,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
	AbuseType   string `json:"abuse_type"`
}

// XARFEvidence holds supporting evidence.
type XARFEvidence struct {
	PayloadSHA256 string   `json:"payload_sha256,omitempty"`
	ExtractedIOCs []string `json:"extracted_iocs,omitempty"`
	CanaryTokens  []string `json:"canary_tokens,omitempty"`
	RawLogsRef    string   `json:"raw_logs_ref,omitempty"`
}

// Dispatcher sends XARF reports to hosting/cloud Trust & Safety teams.
type Dispatcher struct {
	client     *http.Client
	endpoints  map[string]string // provider name -> webhook URL
	reporter   XARFReporter
	mu         sync.Mutex
	dispatched []XARFReport // in-memory record of dispatched reports
}

// NewDispatcher creates a XARF dispatcher.
func NewDispatcher(endpoints map[string]string, reporter XARFReporter) *Dispatcher {
	return &Dispatcher{
		client:    &http.Client{Timeout: 10 * time.Second},
		endpoints: endpoints,
		reporter:  reporter,
	}
}

// ShouldDispatch returns true if the event warrants a XARF report.
// Single-packet port scans are explicitly excluded.
func ShouldDispatch(ev specs.ThreatEvent) bool {
	module := ev.Enrichment.Module

	// Only dispatch for exploitation/malware drop modules
	if module != "ssh" && module != "http_persona" && module != "raw_tcp" {
		return false
	}

	// Never for single-packet port scans
	for _, t := range ev.FindingInfo.Types {
		if t == "port_scan" {
			return false
		}
	}

	// Must have evidence (payload hash or IOCs or canary token)
	if ev.Enrichment.PayloadSHA256 == "" && len(ev.Enrichment.ExtractedIOCs) == 0 && ev.Enrichment.CanaryID == "" {
		return false
	}

	return true
}

// BuildReport creates a XARF report from a ThreatEvent.
func BuildReport(ev specs.ThreatEvent, reporter XARFReporter) XARFReport {
	report := XARFReport{
		Version:   "1.0",
		UUID:      "xarf_" + ev.FindingInfo.UID,
		Generated: time.Now().UTC().Format(time.RFC3339),
		Reporter:  reporter,
		Incident: XARFIncident{
			Title:       ev.FindingInfo.Title,
			Description: fmt.Sprintf("Automated abuse report from %s sensor", ev.Enrichment.Module),
			StartTime:   ev.Time.Format(time.RFC3339),
			EndTime:     ev.Time.Format(time.RFC3339),
			SourceIP:    ev.SrcEndpoint.IP,
			TargetPort:  ev.DstEndpoint.Port,
			AbuseType:   strings.Join(ev.FindingInfo.Types, ","),
		},
		Evidence: XARFEvidence{
			PayloadSHA256: ev.Enrichment.PayloadSHA256,
			ExtractedIOCs: ev.Enrichment.ExtractedIOCs,
			CanaryTokens:  []string{ev.Enrichment.CanaryID},
		},
	}
	if ev.DstEndpoint.IP != "" {
		report.Incident.TargetIP = ev.DstEndpoint.IP
	}
	if ev.Enrichment.CanaryID == "" {
		report.Evidence.CanaryTokens = nil
	}
	return report
}

// Dispatch sends a XARF report to all configured endpoints.
func (d *Dispatcher) Dispatch(report XARFReport) error {
	payload, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}

	var firstErr error
	for provider, url := range d.endpoints {
		if err := d.post(url, payload); err != nil {
			firstErr = fmt.Errorf("%s: %w", provider, err)
		}
	}

	d.mu.Lock()
	d.dispatched = append(d.dispatched, report)
	d.mu.Unlock()

	return firstErr
}

func (d *Dispatcher) post(url string, payload []byte) error {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-XARF-Version", "1.0")

	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("provider returned %d", resp.StatusCode)
	}
	return nil
}

// DispatchCount returns the number of reports dispatched.
func (d *Dispatcher) DispatchCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.dispatched)
}

// GetDispatched returns a copy of all dispatched reports.
func (d *Dispatcher) GetDispatched() []XARFReport {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]XARFReport, len(d.dispatched))
	copy(out, d.dispatched)
	return out
}
