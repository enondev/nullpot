package widenet

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/enondev/nullpot/specs"
)

type fakePacketConn struct {
	net.PacketConn
	readCh chan []byte
	err    error
}

func (f *fakePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if f.err != nil {
		return 0, nil, f.err
	}
	data, ok := <-f.readCh
	if !ok {
		return 0, nil, errors.New("channel closed")
	}
	n := copy(b, data)
	return n, &net.UDPAddr{IP: net.ParseIP("203.0.113.45"), Port: 54321}, nil
}

func (f *fakePacketConn) Close() error { return nil }

func (f *fakePacketConn) LocalAddr() net.Addr { return &net.UDPAddr{Port: 0} }

func TestListenerEventFromPacket(t *testing.T) {
	l := &Listener{network: "udp", address: "0.0.0.0:0"}
	ev := l.eventFromPacket([]byte("ping"), &net.UDPAddr{IP: net.ParseIP("203.0.113.45"), Port: 54321})
	if ev == nil {
		t.Fatal("expected event")
	}
	if ev.SrcEndpoint.IP != "203.0.113.45" || ev.SrcEndpoint.Port != 54321 {
		t.Fatalf("unexpected endpoint: %+v", ev.SrcEndpoint)
	}
	if ev.ClassUID != specs.ClassUIDNetworkActivity || ev.CategoryUID != specs.CategoryUIDPotentialSecurityIssue || ev.ActivityID != specs.ActivityIDCreate {
		t.Fatalf("unexpected OCSF fields")
	}
	if len(ev.FindingInfo.Types) == 0 || ev.FindingInfo.Types[0] != "port_scan" {
		t.Fatalf("unexpected finding types: %v", ev.FindingInfo.Types)
	}
	if ev.Enrichment.Module != "widenet" {
		t.Fatalf("unexpected module: %s", ev.Enrichment.Module)
	}
}

func TestListenerEventFromNilAddr(t *testing.T) {
	l := &Listener{}
	if ev := l.eventFromPacket([]byte("x"), nil); ev != nil {
		t.Fatal("expected nil event for nil addr")
	}
	if ev := l.eventFromPacket([]byte("x"), &net.TCPAddr{}); ev != nil {
		t.Fatal("expected nil event for unknown addr type")
	}
}

func TestListenerStartCancels(t *testing.T) {
	l := &Listener{network: "udp", address: "0.0.0.0:0", events: make(chan specs.ThreatEvent, 10)}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { l.Start(ctx, l.events) }()
	cancel()
	// Should return without hanging
}
