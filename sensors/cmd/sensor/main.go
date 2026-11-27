// Package main is the unified single-binary sensor daemon.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/enondev/nullpot/sensors/internal/core"
	"github.com/enondev/nullpot/sensors/internal/shipper"
	"github.com/enondev/nullpot/sensors/internal/traps/http_persona"
	"github.com/enondev/nullpot/sensors/internal/traps/raw_tcp"
	"github.com/enondev/nullpot/sensors/internal/traps/ssh"
	"github.com/enondev/nullpot/sensors/internal/widenet"
	"github.com/enondev/nullpot/specs"
)

func main() {
	listenAddr := flag.String("listen", getEnv("PORT", ":8080"), "HTTP persona trap listen address")
	aggregatorURL := flag.String("aggregator", getEnv("AGGREGATOR_URL", "http://localhost:8081/v1/ingest"), "Aggregator ingest URL")
	personasDir := flag.String("personas", "sensors/personas", "Persona specs directory")
	sshListen := flag.String("ssh", ":2222", "SSH tarpit listen address")
	rawTCPListen := flag.String("raw-tcp", ":6379", "Raw TCP trap listen address")
	productName := flag.String("product", "EdgeTrapSensor", "Sensor product name")
	productUID := flag.String("uid", "edge-local-01", "Sensor product uid")
	productRegion := flag.String("region", "local", "Sensor product region")
	flag.Parse()

	// Normalize PORT for Render (sets bare number like "10000"; Go needs ":10000")
	if _, err := strconv.Atoi(*listenAddr); err == nil {
		*listenAddr = ":" + *listenAddr
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	loader := core.NewLoader()
	if err := loader.LoadDir(*personasDir); err != nil {
		log.Printf("warning: loading personas: %v", err)
	}

	canary := core.NewGenerator()

	events := make(chan specs.ThreatEvent, 4096)

	modules := []core.TrapModule{}

	// Widenet listener.
	w, err := widenet.NewListener("udp", "0.0.0.0:0", events)
	if err != nil {
		log.Fatalf("widenet: %v", err)
	}
	modules = append(modules, w)

	// HTTP persona trap.
	hp := http_persona.New(loader, canary, *listenAddr, events, specs.Product{
		Name:   *productName,
		UID:    *productUID,
		Region: *productRegion,
	})
	modules = append(modules, hp)

	// SSH tarpit.
	sshm, err := ssh.New(*sshListen, events, specs.Product{
		Name:   *productName,
		UID:    *productUID,
		Region: *productRegion,
	})
	if err != nil {
		log.Fatalf("ssh: %v", err)
	}
	modules = append(modules, sshm)

	// Raw TCP trap (Redis/Docker).
	rt, err := raw_tcp.New(*rawTCPListen, events, specs.Product{
		Name:   *productName,
		UID:    *productUID,
		Region: *productRegion,
	})
	if err != nil {
		log.Fatalf("raw_tcp: %v", err)
	}
	modules = append(modules, rt)

	// Shipper to aggregator.
	sh := shipper.New(shipper.Config{
		AggregatorURL: *aggregatorURL,
		BufferSize:    4096,
		BatchSize:     100,
		BatchTimeout:  5 * time.Second,
		HTTPTimeout:   10 * time.Second,
	})

	// Start modules.
	var moduleWg sync.WaitGroup
	for _, m := range modules {
		moduleWg.Add(1)
		go func(m core.TrapModule) {
			defer moduleWg.Done()
			if err := m.Start(ctx, events); err != nil && err != context.Canceled {
				log.Printf("module %s stopped: %v", m.Name(), err)
			}
		}(m)
	}

	// Start shipper.
	shipperErrCh := make(chan error, 1)
	go func() {
		if err := sh.Start(ctx); err != nil && err != context.Canceled {
			shipperErrCh <- err
		}
	}()

	// Feed events from channel to shipper.
	feedDone := make(chan struct{})
	go func() {
		defer close(feedDone)
		for ev := range events {
			sh.Push(ev)
		}
	}()

	// Health endpoint.
	healthSrv := &http.Server{Addr: ":8090"}
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "ok\n")
	})
	go func() {
		_ = healthSrv.ListenAndServe()
	}()

	<-ctx.Done()
	log.Println("shutting down sensor daemon")

	// Wait for all modules to stop (they return on ctx cancellation).
	moduleWg.Wait()

	// Close events so the feed goroutine can exit after draining.
	close(events)
	<-feedDone

	// Stop the shipper (flushes remaining events).
	if err := sh.Stop(); err != nil {
		log.Printf("shipper stop: %v", err)
	}

	// Shut down the health server.
	healthShutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := healthSrv.Shutdown(healthShutdownCtx); err != nil {
		log.Printf("health server shutdown: %v", err)
	}
}

func stopModules(modules []core.TrapModule) {
	// TrapModule.Start blocks until ctx cancelled; modules return on their own.
	_ = modules
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
