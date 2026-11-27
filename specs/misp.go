// Package specs provides MISP Core Format event/attribute export models.
// Exported as GET /v1/misp/manifest.json for CERTs, ISACs, and threat
// intelligence sharing communities.
package specs

import (
	"encoding/json"
	"time"
)

// MISPEvent is a MISP Core Format event.
type MISPEvent struct {
	Event struct {
		ID        string     `json:"id"`
		UUID      string     `json:"uuid"`
		Publisher string     `json:"publisher"`
		OrgID     string     `json:"org_id"`
		OrgName   string     `json:"org_name"`
		Date      string     `json:"date"`
		Info      string     `json:"info"`
		Published bool       `json:"published"`
		Attribute []MISPAttr `json:"Attribute"`
	} `json:"Event"`
}

// MISPAttr is a MISP attribute.
type MISPAttr struct {
	UUID      string `json:"uuid"`
	Type      string `json:"type"`
	Category  string `json:"category"`
	ToIDs     bool   `json:"to_ids"`
	Value     string `json:"value"`
	Comment   string `json:"comment"`
	Timestamp string `json:"timestamp"`
}

// MISPManifest is a MISP manifest wrapper.
type MISPManifest struct {
	Events []MISPEvent `json:"events"`
}

// NewMISPEvent creates a MISP event.
func NewMISPEvent(id, uuid, info string) MISPEvent {
	e := MISPEvent{}
	e.Event.ID = id
	e.Event.UUID = uuid
	e.Event.Publisher = "nullpot"
	e.Event.OrgName = "nullpot"
	e.Event.Date = time.Now().Format("2006-01-02")
	e.Event.Info = info
	e.Event.Published = true
	return e
}

// MarshalJSON serializes a MISPManifest.
func (m MISPManifest) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string][]MISPEvent{"events": m.Events})
}
