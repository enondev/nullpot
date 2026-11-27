package cloudflare

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestKVUploader(t *testing.T, maxWrites int) (*KVUploader, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	ku := &KVUploader{
		client:      server.Client(),
		baseURL:     server.URL,
		accountID:   "acc",
		apiToken:    "tok",
		namespaceID: "ns",
		maxWrites:   maxWrites,
		dayStart:    time.Now().UTC().Truncate(24 * time.Hour),
	}
	return ku, server
}

func newTestD1Writer(t *testing.T, maxRows int) (*D1Writer, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	dw := &D1Writer{
		client:     server.Client(),
		baseURL:    server.URL,
		accountID:  "acc",
		databaseID: "db",
		apiToken:   "tok",
		maxRows:    maxRows,
		dayStart:   time.Now().UTC().Truncate(24 * time.Hour),
	}
	return dw, server
}

func TestKVUploaderBatchWithinCap(t *testing.T) {
	ku, _ := newTestKVUploader(t, 1000)

	pairs := []KVPair{
		{Key: "key1", Value: "value1"},
		{Key: "key2", Value: "value2"},
	}

	if err := ku.WriteBatch(pairs); err != nil {
		t.Fatalf("write batch: %v", err)
	}
	if ku.WritesToday() != 2 {
		t.Fatalf("expected 2 writes today, got %d", ku.WritesToday())
	}
}

func TestKVUploaderDailyCap(t *testing.T) {
	ku, _ := newTestKVUploader(t, 3)

	for i := 0; i < 3; i++ {
		if err := ku.WriteBatch([]KVPair{{Key: "k", Value: "v"}}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	err := ku.WriteBatch([]KVPair{{Key: "k4", Value: "v4"}})
	if err == nil {
		t.Fatal("expected error when exceeding daily cap")
	}
}

func TestKVUploaderResetDay(t *testing.T) {
	ku, _ := newTestKVUploader(t, 1)
	ku.dayStart = time.Now().Add(-25 * time.Hour).UTC().Truncate(24 * time.Hour)

	if err := ku.WriteBatch([]KVPair{{Key: "k", Value: "v"}}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if ku.WritesToday() != 1 {
		t.Fatalf("expected 1 write after day reset, got %d", ku.WritesToday())
	}
}

func TestD1WriterBatchWithinCap(t *testing.T) {
	dw, _ := newTestD1Writer(t, 100000)

	rows := []D1Row{
		{SQL: "INSERT INTO events VALUES (?, ?)", Params: []interface{}{"ip", "score"}},
	}

	if err := dw.WriteBatch(rows); err != nil {
		t.Fatalf("write batch: %v", err)
	}
	if dw.RowsToday() != 1 {
		t.Fatalf("expected 1 row today, got %d", dw.RowsToday())
	}
}

func TestD1WriterDailyCap(t *testing.T) {
	dw, _ := newTestD1Writer(t, 2)

	for i := 0; i < 2; i++ {
		if err := dw.WriteBatch([]D1Row{{SQL: "INSERT INTO events VALUES (?)", Params: []interface{}{i}}}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	err := dw.WriteBatch([]D1Row{{SQL: "INSERT INTO events VALUES (?)", Params: []interface{}{3}}})
	if err == nil {
		t.Fatal("expected error when exceeding daily row cap")
	}
}

func TestSyncRun(t *testing.T) {
	ku, _ := newTestKVUploader(t, 1000)
	dw, _ := newTestD1Writer(t, 100000)
	sync := NewSync(ku, dw)

	kvPairs := []KVPair{{Key: "k1", Value: "v1"}}
	d1Rows := []D1Row{{SQL: "INSERT INTO events VALUES (?)", Params: []interface{}{1}}}

	result := sync.Run(kvPairs, d1Rows)
	if result.KVWrites != 1 {
		t.Fatalf("expected 1 KV write, got %d", result.KVWrites)
	}
	if result.D1Rows != 1 {
		t.Fatalf("expected 1 D1 row, got %d", result.D1Rows)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("expected no errors, got %v", result.Errors)
	}
}

func TestSyncRunNil(t *testing.T) {
	sync := NewSync(nil, nil)
	result := sync.Run(nil, nil)
	if result.KVWrites != 0 || result.D1Rows != 0 {
		t.Fatal("expected zero writes with nil components")
	}
}

func TestKVPair(t *testing.T) {
	p := KVPair{Key: "k", Value: "v"}
	if p.Key != "k" || p.Value != "v" {
		t.Fatal("unexpected KVPair values")
	}
}

func TestD1Row(t *testing.T) {
	r := D1Row{SQL: "SELECT 1", Params: []interface{}{}}
	if r.SQL != "SELECT 1" {
		t.Fatal("unexpected D1Row SQL")
	}
}
