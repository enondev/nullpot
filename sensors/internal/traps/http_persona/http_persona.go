// Package http_persona implements the OpenAPI/YAML-driven HTTP/HTTPS trap.
package http_persona

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/enondev/nullpot/sensors/internal/core"
	"github.com/enondev/nullpot/specs"
)

// maxBodySize caps request body reads to prevent memory DoS.
const maxBodySize int64 = 1 << 20 // 1 MB

// rateLimiter is a simple token bucket per source IP.
type rateLimiter struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
	rate   float64 // tokens per second
	burst  float64
}

func newRateLimiter(rate, burst float64) *rateLimiter {
	return &rateLimiter{
		tokens: burst,
		last:   time.Now(),
		rate:   rate,
		burst:  burst,
	}
}

func (rl *rateLimiter) allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(rl.last).Seconds()
	rl.last = now
	rl.tokens += elapsed * rl.rate
	if rl.tokens > rl.burst {
		rl.tokens = rl.burst
	}
	if rl.tokens < 1.0 {
		return false
	}
	rl.tokens--
	return true
}

// TrapModule serves decoy HTTP routes from persona specs and emits OCSF
// events for captured requests.
type TrapModule struct {
	loader       *core.Loader
	canary       *core.Generator
	server       *http.Server
	events       chan<- specs.ThreatEvent
	listenAddr   string
	product      specs.Product
	rateLimiters map[string]*rateLimiter
	rlMu         sync.Mutex
	maxBodySize  int64
}

// New creates an HTTP persona trap bound to listenAddr.
func New(loader *core.Loader, canary *core.Generator, listenAddr string, events chan<- specs.ThreatEvent, product specs.Product) *TrapModule {
	return &TrapModule{
		loader:       loader,
		canary:       canary,
		events:       events,
		listenAddr:   listenAddr,
		product:      product,
		rateLimiters: make(map[string]*rateLimiter),
		maxBodySize:  maxBodySize,
	}
}

// Name returns the module identifier.
func (t *TrapModule) Name() string { return "http_persona" }

// Start runs the HTTP server, registering routes from all loaded personas.
func (t *TrapModule) Start(ctx context.Context, _ chan<- specs.ThreatEvent) error {
	mux := http.NewServeMux()
	for _, id := range t.loader.IDs() {
		spec := t.loader.Get(id)
		if spec == nil {
			continue
		}
		for _, route := range spec.Routes {
			path := route.Path
			method := route.Method
			if method == "" {
				method = "GET"
			}
			handler := t.makeHandler(spec, route)
			switch method {
			case "GET":
				mux.HandleFunc(path, handler)
			case "POST":
				mux.HandleFunc(path, handler)
			case "PUT":
				mux.HandleFunc(path, handler)
			case "DELETE":
				mux.HandleFunc(path, handler)
			default:
				mux.HandleFunc(path, handler)
			}
		}
	}

	t.server = &http.Server{
		Addr:    t.listenAddr,
		Handler: mux,
	}

	go func() {
		if err := t.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			// ListenAndServe error; server is shutting down.
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return t.server.Shutdown(shutdownCtx)
}

func (t *TrapModule) allowRate(ip string) bool {
	t.rlMu.Lock()
	defer t.rlMu.Unlock()
	rl, ok := t.rateLimiters[ip]
	if !ok {
		rl = newRateLimiter(10, 20) // 10 req/s, burst 20
		t.rateLimiters[ip] = rl
	}
	return rl.allow()
}

func (t *TrapModule) makeHandler(spec *core.PersonaSpec, route core.Route) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := srcIP(r.RemoteAddr)

		// Rate limit per source IP.
		if !t.allowRate(ip) {
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}

		sessionID := r.RemoteAddr

		// Generate one canary token per request if injection is enabled.
		var canaryTok *core.CanaryToken
		if spec.CanaryInject {
			tok, err := t.canary.Generate(sessionID, core.CanaryTokenURL, spec.ID+"::"+route.Path)
			if err == nil {
				canaryTok = tok
				w.Header().Set("X-Canary-Token", tok.ID)
				w.Header().Set("X-Canary-Value", tok.Token)
			}
		}

		// Capture request body with max size limit.
		body := http.MaxBytesReader(w, r.Body, t.maxBodySize)
		bodyBytes, err := io.ReadAll(body)
		if err != nil {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		sum := sha256.Sum256(bodyBytes)
		payloadSHA := hex.EncodeToString(sum[:])

		// Emit OCSF event.
		ev := specs.ThreatEvent{
			ClassUID:    specs.ClassUIDNetworkActivity,
			CategoryUID: specs.CategoryUIDPotentialSecurityIssue,
			ActivityID:  specs.ActivityIDCreate,
			Metadata: specs.Metadata{
				Version: "1.3.0",
				Product: t.product,
			},
			SrcEndpoint: specs.Endpoint{
				IP:   ip,
				Port: 0,
			},
			DstEndpoint: specs.Endpoint{Port: 80},
			FindingInfo: specs.FindingInfo{
				UID:   "evt_http_" + spec.ID,
				Title: "HTTP persona trap hit: " + spec.ID,
				Types: []string{"exploit_attempt"},
			},
			Enrichment: specs.Enrichment{
				Module:         "http_persona",
				PersonaID:      spec.ID,
				Fingerprint:    r.UserAgent(),
				CanaryID:       "",
				PayloadPreview: truncate(string(bodyBytes), 200),
				PayloadSHA256:  payloadSHA,
			},
		}
		if canaryTok != nil {
			ev.Enrichment.CanaryID = canaryTok.ID
		}

		// Emit to channel (non-blocking drop-oldest handled by caller).
		select {
		case t.events <- ev:
		default:
		}

		// Serve decoy response with canary token substituted into body.
		respBody := route.Response.Body
		if canaryTok != nil {
			respBody = strings.ReplaceAll(respBody, "${CANARY_TOKEN}", canaryTok.Token)
		}
		w.WriteHeader(route.Response.Status)
		for k, v := range route.Response.Headers {
			w.Header().Set(k, v)
		}
		w.Write([]byte(respBody))
	}
}

func srcIP(remoteAddr string) string {
	for i := len(remoteAddr) - 1; i >= 0; i-- {
		if remoteAddr[i] == ':' {
			return remoteAddr[:i]
		}
	}
	return remoteAddr
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
