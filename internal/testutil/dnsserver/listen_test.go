package dnsserver

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
)

type fakeListener struct {
	net.Listener
	addr   net.Addr
	closed *int
}

func (f fakeListener) Addr() net.Addr { return f.addr }
func (f fakeListener) Close() error   { *f.closed++; return nil }

type fakePacketConn struct{ net.PacketConn }

func tcpAddr(port int) net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port} }

func TestListenBothRetriesOnRandomPortsAndClosesFailedAttempts(t *testing.T) {
	var closed int
	var tried []string
	ports := []int{30001, 30002, 30003}
	f := listeners{
		tcp: func(addr string) (net.Listener, error) {
			tried = append(tried, addr)
			_, p, _ := net.SplitHostPort(addr)
			n := 1234 // the port the OS picked for ":0"
			if p != "0" {
				n, _ = strconv.Atoi(p)
			}
			return fakeListener{addr: tcpAddr(n), closed: &closed}, nil
		},
		udp: func(addr string) (net.PacketConn, error) {
			if addr != "127.0.0.1:30003" {
				return nil, errors.New("access permissions")
			}
			return fakePacketConn{}, nil
		},
		port: func() int { p := ports[0]; ports = ports[1:]; return p },
	}
	l, pc, err := listenBoth(f, 10)
	if err != nil || l == nil || pc == nil {
		t.Fatalf("listenBoth: %v", err)
	}
	if got := strings.Join(tried, " "); got != "127.0.0.1:0 127.0.0.1:30001 127.0.0.1:30002 127.0.0.1:30003" {
		t.Fatalf("tried: %s", got)
	}
	if closed != 3 {
		t.Fatalf("closed %d failed TCP listeners, want 3", closed)
	}
}

func TestListenBothReportsTheLastTwoErrors(t *testing.T) {
	var closed int
	n := 0
	f := listeners{
		tcp: func(string) (net.Listener, error) {
			return fakeListener{addr: tcpAddr(40000), closed: &closed}, nil
		},
		udp: func(string) (net.PacketConn, error) {
			n++
			return nil, fmt.Errorf("udp failure %d", n)
		},
		port: func() int { return 40000 },
	}
	_, _, err := listenBoth(f, 4)
	if err == nil {
		t.Fatal("no error")
	}
	for _, want := range []string{"4 attempts", "udp failure 3", "udp failure 4"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error lacks %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "udp failure 2") {
		t.Fatalf("error keeps more than the last two: %v", err)
	}
	if closed != 4 {
		t.Fatalf("closed %d, want 4", closed)
	}
}

func TestListenBothFirstTryUsesTheOSPort(t *testing.T) {
	l, pc, err := listenBoth(realListeners(), listenAttempts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close(); _ = pc.Close() }()
	if l.Addr().String() != pc.LocalAddr().String() {
		t.Fatalf("tcp %v and udp %v differ", l.Addr(), pc.LocalAddr())
	}
}
