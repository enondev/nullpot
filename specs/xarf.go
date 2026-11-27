// Package specs provides XARF automated abuse report generator models.
// Reports are dispatched to hosting/cloud Trust & Safety teams (AWS, Hetzner,
// DigitalOcean, Cloudflare).
package specs

import (
	"encoding/json"
	"time"
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

// XARFEvidence holds supporting evidence (hashes, IOCs, canary tokens).
type XARFEvidence struct {
	PayloadSHA256 string   `json:"payload_sha256,omitempty"`
	ExtractedIOCs []string `json:"extracted_iocs,omitempty"`
	CanaryTokens  []string `json:"canary_tokens,omitempty"`
	RawLogsRef    string   `json:"raw_logs_ref,omitempty"`
}

// NewXARFReport creates a new XARF report.
func NewXARFReport(uuid string) XARFReport {
	return XARFReport{
		Version:   "1.0",
		UUID:      uuid,
		Generated: time.Now().UTC().Format(time.RFC3339),
		Reporter: XARFReporter{
			Name:    "nullpot",
			Contact: "abuse@nullpot.internal",
		},
	}
}

// MarshalJSON serializes a XARFReport.
func (r XARFReport) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Version   string       `json:"version"`
		UUID      string       `json:"uuid"`
		Generated string       `json:"generated"`
		Reporter  XARFReporter `json:"reporter"`
		Incident  XARFIncident `json:"incident"`
		Evidence  XARFEvidence `json:"evidence"`
	}{
		Version:   r.Version,
		UUID:      r.UUID,
		Generated: r.Generated,
		Reporter:  r.Reporter,
		Incident:  r.Incident,
		Evidence:  r.Evidence,
	})
}
