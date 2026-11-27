// Package cloudflare implements the batched KV snapshot uploader and D1 event
// writer, respecting Cloudflare free-tier guardrails.
package cloudflare

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// KVUploader uploads snapshots to Cloudflare KV with daily write caps.
type KVUploader struct {
	client      *http.Client
	baseURL     string
	accountID   string
	apiToken    string
	namespaceID string

	mu          sync.Mutex
	writesToday int
	dayStart    time.Time
	maxWrites   int
}

// NewKVUploader creates a KV uploader.
func NewKVUploader(accountID, apiToken, namespaceID string) *KVUploader {
	return &KVUploader{
		client:      &http.Client{Timeout: 10 * time.Second},
		baseURL:     "https://api.cloudflare.com/client/v4",
		accountID:   accountID,
		apiToken:    apiToken,
		namespaceID: namespaceID,
		maxWrites:   1000,
		dayStart:    time.Now().UTC().Truncate(24 * time.Hour),
	}
}

// WriteBatch uploads a batch of key-value pairs to KV, respecting daily caps.
func (k *KVUploader) WriteBatch(pairs []KVPair) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	k.resetDayIfNeeded()

	if k.writesToday+len(pairs) > k.maxWrites {
		return fmt.Errorf("daily KV write cap would be exceeded: %d + %d > %d", k.writesToday, len(pairs), k.maxWrites)
	}

	for _, p := range pairs {
		if err := k.writeKV(p.Key, p.Value); err != nil {
			return err
		}
		k.writesToday++
	}
	return nil
}

func (k *KVUploader) resetDayIfNeeded() {
	now := time.Now().UTC().Truncate(24 * time.Hour)
	if now.After(k.dayStart) {
		k.writesToday = 0
		k.dayStart = now
	}
}

func (k *KVUploader) writeKV(key, value string) error {
	url := fmt.Sprintf("%s/accounts/%s/storage/kv/namespaces/%s/values/%s",
		k.baseURL, k.accountID, k.namespaceID, key)

	body := bytes.NewReader([]byte(value))
	req, err := http.NewRequest(http.MethodPut, url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+k.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := k.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("KV write returned %d", resp.StatusCode)
	}
	return nil
}

// WritesToday returns the number of KV writes today.
func (k *KVUploader) WritesToday() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.resetDayIfNeeded()
	return k.writesToday
}

// KVPair is a key-value pair for KV storage.
type KVPair struct {
	Key   string
	Value string
}

// D1Writer writes events to Cloudflare D1 with daily row caps.
type D1Writer struct {
	client     *http.Client
	baseURL    string
	accountID  string
	databaseID string
	apiToken   string

	mu        sync.Mutex
	rowsToday int
	dayStart  time.Time
	maxRows   int
}

// NewD1Writer creates a D1 writer.
func NewD1Writer(accountID, databaseID, apiToken string) *D1Writer {
	return &D1Writer{
		client:     &http.Client{Timeout: 10 * time.Second},
		baseURL:    "https://api.cloudflare.com/client/v4",
		accountID:  accountID,
		databaseID: databaseID,
		apiToken:   apiToken,
		maxRows:    100000,
		dayStart:   time.Now().UTC().Truncate(24 * time.Hour),
	}
}

// WriteBatch inserts a batch of rows into D1, respecting daily caps.
func (d *D1Writer) WriteBatch(rows []D1Row) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.resetDayIfNeeded()

	if d.rowsToday+len(rows) > d.maxRows {
		return fmt.Errorf("daily D1 row cap would be exceeded: %d + %d > %d", d.rowsToday, len(rows), d.maxRows)
	}

	for _, r := range rows {
		if err := d.writeRow(r); err != nil {
			return err
		}
		d.rowsToday++
	}
	return nil
}

func (d *D1Writer) resetDayIfNeeded() {
	now := time.Now().UTC().Truncate(24 * time.Hour)
	if now.After(d.dayStart) {
		d.rowsToday = 0
		d.dayStart = now
	}
}

func (d *D1Writer) writeRow(row D1Row) error {
	url := fmt.Sprintf("%s/accounts/%s/d1/database/%s/query",
		d.baseURL, d.accountID, d.databaseID)

	payload := map[string]interface{}{
		"sql":    row.SQL,
		"params": row.Params,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+d.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("D1 write returned %d", resp.StatusCode)
	}
	return nil
}

// RowsToday returns the number of D1 rows written today.
func (d *D1Writer) RowsToday() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.resetDayIfNeeded()
	return d.rowsToday
}

// D1Row is a row to insert into D1.
type D1Row struct {
	SQL    string
	Params []interface{}
}

// SyncResult is the result of a Cloudflare sync operation.
type SyncResult struct {
	KVWrites int
	D1Rows   int
	Errors   []error
}

// Sync pushes snapshots to KV and events to D1.
type Sync struct {
	kvu *KVUploader
	d1w *D1Writer
}

// NewSync creates a Cloudflare sync.
func NewSync(kvu *KVUploader, d1w *D1Writer) *Sync {
	return &Sync{kvu: kvu, d1w: d1w}
}

// Run performs a sync cycle, returning results.
func (s *Sync) Run(kvPairs []KVPair, d1Rows []D1Row) SyncResult {
	result := SyncResult{}

	if s.kvu != nil {
		if err := s.kvu.WriteBatch(kvPairs); err != nil {
			result.Errors = append(result.Errors, err)
		} else {
			result.KVWrites = len(kvPairs)
		}
	}

	if s.d1w != nil {
		if err := s.d1w.WriteBatch(d1Rows); err != nil {
			result.Errors = append(result.Errors, err)
		} else {
			result.D1Rows = len(d1Rows)
		}
	}

	return result
}
