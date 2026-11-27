package core

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/enondev/nullpot/specs"
	"gopkg.in/yaml.v3"
)

func TestTrapModuleInterface(t *testing.T) {
	var _ TrapModule = (*dummyModule)(nil)
}

type dummyModule struct{}

func (d *dummyModule) Name() string { return "dummy" }
func (d *dummyModule) Start(ctx context.Context, events chan<- specs.ThreatEvent) error {
	<-ctx.Done()
	return nil
}

func TestRegistryRegisterGetNames(t *testing.T) {
	r := NewRegistry()
	if r.Len() != 0 {
		t.Fatalf("expected empty registry, got %d", r.Len())
	}

	m1 := &dummyModule{}
	if err := r.Register(m1); err != nil {
		t.Fatalf("register: %v", err)
	}

	if err := r.Register(&dummyModule{}); err == nil {
		t.Fatalf("expected duplicate module error")
	}

	if got := r.Get("dummy"); got == nil {
		t.Fatal("expected module")
	}
	if got := r.Get("missing"); got != nil {
		t.Fatal("expected nil for missing module")
	}

	names := r.Names()
	if len(names) != 1 || names[0] != "dummy" {
		t.Fatalf("unexpected names: %v", names)
	}
	if r.Len() != 1 {
		t.Fatalf("expected len 1, got %d", r.Len())
	}
}

func TestDuplicateModuleError(t *testing.T) {
	e := &DuplicateModuleError{Name: "foo"}
	if e.Error() != "duplicate module registered: foo" {
		t.Errorf("unexpected error message: %s", e.Error())
	}
}

func TestPersonaLoaderLoadFile(t *testing.T) {
	dir := t.TempDir()
	valid := []byte(`id: test-persona
name: Test Persona
banner: Test Banner
canary_token_inject: true
routes:
  - path: /test
    method: GET
    response:
      status: 200
      body: ok
      headers:
        Content-Type: text/plain
    capture:
      body: true
      headers: true
ioc_capture:
  - http://
`)
	path := filepath.Join(dir, "valid.yaml")
	if err := os.WriteFile(path, valid, 0o644); err != nil {
		t.Fatalf("write valid: %v", err)
	}

	l := NewLoader()
	if err := l.LoadFile(path); err != nil {
		t.Fatalf("load valid: %v", err)
	}
	spec := l.Get("test-persona")
	if spec == nil {
		t.Fatal("expected spec")
	}
	if spec.ID != "test-persona" || spec.Name != "Test Persona" || !spec.CanaryInject {
		t.Fatalf("unexpected spec: %+v", spec)
	}
	if len(spec.Routes) != 1 || spec.Routes[0].Path != "/test" || spec.Routes[0].Method != "GET" {
		t.Fatalf("unexpected route: %+v", spec.Routes)
	}
	if len(spec.IOCCapture) != 1 || spec.IOCCapture[0] != "http://" {
		t.Fatalf("unexpected ioc_capture: %v", spec.IOCCapture)
	}
	if l.Len() != 1 {
		t.Fatalf("expected len 1, got %d", l.Len())
	}
}

func TestPersonaLoaderMissingFields(t *testing.T) {
	l := NewLoader()

	cases := []struct {
		name string
		yaml string
	}{
		{"empty id", `banner: x
routes:
  - path: /test
    method: GET
    response:
      status: 200
      body: ok
`},
		{"empty banner", `id: test
routes:
  - path: /test
    method: GET
    response:
      status: 200
      body: ok
`},
		{"no routes", `id: test
banner: x
`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := l.LoadData([]byte(c.yaml)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestPersonaLoaderMalformedYAML(t *testing.T) {
	l := NewLoader()
	if err := l.LoadData([]byte(`: : : not valid yaml`)); err == nil {
		t.Fatal("expected error for malformed yaml")
	}
}

func TestPersonaLoaderRouteMethodDefault(t *testing.T) {
	l := NewLoader()
	if err := l.LoadData([]byte(`id: test
banner: x
routes:
  - path: /test
    response:
      status: 200
      body: ok
`)); err != nil {
		t.Fatalf("load: %v", err)
	}
	spec := l.Get("test")
	if spec.Routes[0].Method != "GET" {
		t.Fatalf("expected default method GET, got %s", spec.Routes[0].Method)
	}
}

// LoadData loads persona spec from raw YAML bytes.
func (l *Loader) LoadData(data []byte) error {
	var spec PersonaSpec
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return err
	}
	if spec.ID == "" {
		return &loadError{"persona id is required"}
	}
	if spec.Banner == "" {
		return &loadError{"banner is required"}
	}
	if len(spec.Routes) == 0 {
		return &loadError{"at least one route is required"}
	}
	for i, r := range spec.Routes {
		if r.Path == "" {
			return &loadError{"route path is required"}
		}
		if r.Method == "" {
			r.Method = "GET"
			spec.Routes[i].Method = r.Method
		}
	}
	l.specs[spec.ID] = &spec
	return nil
}

type loadError struct{ msg string }

func (e *loadError) Error() string { return e.msg }

var _ = filepath.Join
