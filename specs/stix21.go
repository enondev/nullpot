// Package specs provides STIX 2.1 Bundle/Indicator/Sighting serialization
// models. Served as cached static JSON bundles (GET /v1/stix/bundle.json).
package specs

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"
)

// STIXBundle is a STIX 2.1 Bundle object.
type STIXBundle struct {
	Type        string       `json:"type"`
	ID          string       `json:"id"`
	SpecVersion string       `json:"spec_version"`
	Objects     []STIXObject `json:"objects"`
}

// STIXObject is a STIX 2.1 domain or cyber observable object.
type STIXObject interface {
	STIXType() string
}

// STIXIndicator is a STIX 2.1 Indicator.
type STIXIndicator struct {
	Type           string    `json:"type"`
	ID             string    `json:"id"`
	SpecVersion    string    `json:"spec_version"`
	Created        time.Time `json:"created"`
	Modified       time.Time `json:"modified"`
	Name           string    `json:"name"`
	Pattern        string    `json:"pattern"`
	PatternType    string    `json:"pattern_type"`
	PatternVersion string    `json:"pattern_version"`
	ValidFrom      time.Time `json:"valid_from"`
}

// STIXSighting is a STIX 2.1 Sighting.
type STIXSighting struct {
	Type          string    `json:"type"`
	ID            string    `json:"id"`
	SpecVersion   string    `json:"spec_version"`
	Created       time.Time `json:"created"`
	SightingOfRef string    `json:"sighting_of_ref"`
}

// MarshalJSON serializes a STIXBundle.
func (b STIXBundle) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type        string       `json:"type"`
		ID          string       `json:"id"`
		SpecVersion string       `json:"spec_version"`
		Objects     []STIXObject `json:"objects"`
	}{
		Type:        b.Type,
		ID:          b.ID,
		SpecVersion: b.SpecVersion,
		Objects:     b.Objects,
	})
}

// NewBundle creates a STIX 2.1 bundle with the given objects.
func NewBundle(objects []STIXObject) STIXBundle {
	return STIXBundle{
		Type:        "bundle",
		ID:          "bundle--" + mustUUID(),
		SpecVersion: "2.1",
		Objects:     objects,
	}
}

// NewIndicator creates a STIX 2.1 indicator.
func NewIndicator(id, name, pattern, patternType string, validFrom time.Time) STIXIndicator {
	return STIXIndicator{
		Type:           "indicator",
		ID:             "indicator--" + id,
		SpecVersion:    "2.1",
		Created:        time.Now(),
		Modified:       time.Now(),
		Name:           name,
		Pattern:        pattern,
		PatternType:    patternType,
		PatternVersion: "2.1",
		ValidFrom:      validFrom,
	}
}

// mustUUID returns a random UUIDv4 string.
func mustUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
