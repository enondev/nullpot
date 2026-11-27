// Package core defines the TrapModule plugin interface, Persona loader, and
// Canary Token generator used by all sensor protocol engines.
package core

import (
	"context"
	"sync"

	"github.com/enondev/nullpot/specs"
)

// TrapModule is the plugin interface every protocol engine must implement.
// Name returns the module identifier. Start runs the module's listener loop,
// pushing telemetry to the provided channel; it must not block on aggregator
// I/O and must return when ctx is cancelled.
type TrapModule interface {
	Name() string
	Start(ctx context.Context, events chan<- specs.ThreatEvent) error
}

// Registry holds registered TrapModules by name.
type Registry struct {
	mu    sync.RWMutex
	mods  map[string]TrapModule
	order []string
}

// NewRegistry creates an empty module registry.
func NewRegistry() *Registry {
	return &Registry{mods: make(map[string]TrapModule)}
}

// Register adds a module to the registry. Returns an error if a module with
// the same name is already registered.
func (r *Registry) Register(m TrapModule) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := m.Name()
	if _, ok := r.mods[name]; ok {
		return &DuplicateModuleError{Name: name}
	}
	r.mods[name] = m
	r.order = append(r.order, name)
	return nil
}

// Get returns the module with the given name, or nil if not found.
func (r *Registry) Get(name string) TrapModule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.mods[name]
}

// Names returns all registered module names in registration order.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, len(r.order))
	copy(out, r.order)
	return out
}

// Len returns the number of registered modules.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.mods)
}

// DuplicateModuleError is returned when registering a module with a duplicate
// name.
type DuplicateModuleError struct {
	Name string
}

func (e *DuplicateModuleError) Error() string {
	return "duplicate module registered: " + e.Name
}
