// Package core defines the TrapModule plugin interface, Persona loader, and
// Canary Token generator used by all sensor protocol engines.
package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// PersonaSpec is a declarative YAML manifest defining a decoy software
// persona: banners, HTTP routes, response schemas, IOC capture rules, and
// canary token injection. Loaded from sensors/personas/*.yaml without
// recompiling Go binaries.
type PersonaSpec struct {
	ID           string   `yaml:"id"`
	Name         string   `yaml:"name"`
	Banner       string   `yaml:"banner"`
	CanaryInject bool     `yaml:"canary_token_inject"`
	Routes       []Route  `yaml:"routes"`
	IOCCapture   []string `yaml:"ioc_capture"`
}

// Route defines a single decoy HTTP route.
type Route struct {
	Path     string   `yaml:"path"`
	Method   string   `yaml:"method"`
	Response Response `yaml:"response"`
	Capture  Capture  `yaml:"capture"`
}

// Response is the decoy response for a route.
type Response struct {
	Status  int               `yaml:"status"`
	Body    string            `yaml:"body"`
	Headers map[string]string `yaml:"headers"`
}

// Capture defines what to capture for a route.
type Capture struct {
	Body    bool `yaml:"body"`
	Headers bool `yaml:"headers"`
}

// Loader reads and validates persona specs from a directory.
type Loader struct {
	specs map[string]*PersonaSpec
}

// NewLoader creates an empty persona loader.
func NewLoader() *Loader {
	return &Loader{specs: make(map[string]*PersonaSpec)}
}

// LoadDir reads all *.yaml/*.yml files in dir and registers their specs.
func (l *Loader) LoadDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		path := filepath.Join(dir, name)
		if err := l.LoadFile(path); err != nil {
			return fmt.Errorf("load %s: %w", path, err)
		}
	}
	return nil
}

// LoadFile reads and validates a single persona spec file.
func (l *Loader) LoadFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var spec PersonaSpec
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return err
	}
	if spec.ID == "" {
		return fmt.Errorf("%s: persona id is required", path)
	}
	if spec.Banner == "" {
		return fmt.Errorf("%s: banner is required", path)
	}
	if len(spec.Routes) == 0 {
		return fmt.Errorf("%s: at least one route is required", path)
	}
	for i, r := range spec.Routes {
		if r.Path == "" {
			return fmt.Errorf("%s: route %d path is required", path, i)
		}
		if r.Method == "" {
			r.Method = "GET"
			spec.Routes[i].Method = r.Method
		}
	}
	l.specs[spec.ID] = &spec
	return nil
}

// Get returns the spec with the given id, or nil if not found.
func (l *Loader) Get(id string) *PersonaSpec {
	return l.specs[id]
}

// IDs returns all loaded persona ids.
func (l *Loader) IDs() []string {
	out := make([]string, 0, len(l.specs))
	for id := range l.specs {
		out = append(out, id)
	}
	return out
}

// Len returns the number of loaded specs.
func (l *Loader) Len() int {
	return len(l.specs)
}
