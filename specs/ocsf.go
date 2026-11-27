// Package specs provides OCSF-aligned ThreatEvent normalization structs and
// serialization models for STIX 2.1, MISP Core Format, and XARF.
//
// All sensor modules emit standardized OCSF-mapped JSON payloads governed by
// specs/openapi.yaml. See docs/adr/0002-ocsf-schema.md for the field mapping
// rationale.
package specs

import (
	"encoding/json"
	"fmt"
	"time"
)

// ThreatEvent is the canonical OCSF-aligned internal schema for all sensor
// telemetry (Network Activity / Detection Finding).
type ThreatEvent struct {
	ClassUID    uint16      `json:"class_uid"`
	CategoryUID uint8       `json:"category_uid"`
	ActivityID  uint8       `json:"activity_id"`
	Time        time.Time   `json:"time"`
	Metadata    Metadata    `json:"metadata"`
	SrcEndpoint Endpoint    `json:"src_endpoint"`
	DstEndpoint Endpoint    `json:"dst_endpoint"`
	FindingInfo FindingInfo `json:"finding_info"`
	Enrichment  Enrichment  `json:"enrichment"`
}

// Metadata describes the sensor product that produced the event.
type Metadata struct {
	Version string  `json:"version"`
	Product Product `json:"product"`
}

// Product identifies the emitting sensor.
type Product struct {
	Name   string `json:"name"`
	UID    string `json:"uid"`
	Region string `json:"region"`
}

// Endpoint describes a network endpoint.
type Endpoint struct {
	IP   string `json:"ip,omitempty"`
	Port uint16 `json:"port,omitempty"`
}

// FindingInfo describes the detection finding.
type FindingInfo struct {
	UID   string   `json:"uid"`
	Title string   `json:"title"`
	Types []string `json:"types"`
}

// Enrichment holds module-specific enrichment captured by the sensor.
type Enrichment struct {
	Module         string   `json:"module"`
	PersonaID      string   `json:"persona_id,omitempty"`
	Fingerprint    string   `json:"fingerprint,omitempty"`
	CanaryID       string   `json:"canary_id,omitempty"`
	PayloadPreview string   `json:"payload_preview,omitempty"`
	PayloadSHA256  string   `json:"payload_sha256,omitempty"`
	ExtractedIOCs  []string `json:"extracted_iocs,omitempty"`
}

// MarshalJSON produces deterministic JSON for a ThreatEvent.
func (e ThreatEvent) MarshalJSON() ([]byte, error) {
	type alias ThreatEvent
	return json.Marshal(alias(e))
}

// UnmarshalJSON populates a ThreatEvent from JSON.
func (e *ThreatEvent) UnmarshalJSON(data []byte) error {
	type alias ThreatEvent
	return json.Unmarshal(data, (*alias)(e))
}

// Validate returns an error if required ThreatEvent fields are missing or
// malformed.
func (e *ThreatEvent) Validate() error {
	if e.ClassUID == 0 {
		return fmt.Errorf("class_uid is required")
	}
	if e.CategoryUID == 0 {
		return fmt.Errorf("category_uid is required")
	}
	if e.ActivityID == 0 {
		return fmt.Errorf("activity_id is required")
	}
	if e.Time.IsZero() {
		return fmt.Errorf("time is required")
	}
	if e.Metadata.Product.Name == "" {
		return fmt.Errorf("metadata.product.name is required")
	}
	if e.Metadata.Product.UID == "" {
		return fmt.Errorf("metadata.product.uid is required")
	}
	if e.FindingInfo.UID == "" {
		return fmt.Errorf("finding_info.uid is required")
	}
	if e.FindingInfo.Title == "" {
		return fmt.Errorf("finding_info.title is required")
	}
	if len(e.FindingInfo.Types) == 0 {
		return fmt.Errorf("finding_info.types is required")
	}
	return nil
}

// ClassUID constants for OCSF.
const (
	// ClassUIDDiscovery (2004) - Network Activity / Detection Finding.
	ClassUIDNetworkActivity = 2004
)

// CategoryUID constants for OCSF.
const (
	// CategoryUIDPotentialSecurityIssue (2) - potential security issue.
	CategoryUIDPotentialSecurityIssue = 2
)

// ActivityID constants for OCSF.
const (
	// ActivityIDCreate (1) - create.
	ActivityIDCreate = 1
)
