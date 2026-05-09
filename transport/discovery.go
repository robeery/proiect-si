package transport

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	broadcastAddr    = "255.255.255.255:9999"
	discoveryAddr    = "0.0.0.0:9999"
	announceInterval = 2 * time.Second
)

type PeerAnnouncement struct {
	Addr string
	Name string
}

type Announcer struct {
	conn *net.UDPConn
	port int
	name string
	stop chan struct{}
	done chan struct{}
	mu   sync.Mutex
}

func NewAnnouncer(tcpPort int) (*Announcer, error) {
	dst, err := net.ResolveUDPAddr("udp4", broadcastAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp4", nil, dst)
	if err != nil {
		return nil, err
	}
	return &Announcer{
		conn: conn,
		port: tcpPort,
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}, nil
}

func (a *Announcer) SetName(name string) {
	a.mu.Lock()
	a.name = name
	a.mu.Unlock()
}

func (a *Announcer) Start() {
	go func() {
		defer close(a.done)
		ticker := time.NewTicker(announceInterval)
		defer ticker.Stop()
		a.announce()
		for {
			select {
			case <-ticker.C:
				a.announce()
			case <-a.stop:
				return
			}
		}
	}()
}

func (a *Announcer) Stop() {
	close(a.stop)
	<-a.done
	a.conn.Close()
}

func (a *Announcer) announce() {
	ip, err := lanIP()
	if err != nil {
		return
	}
	a.mu.Lock()
	name := a.name
	a.mu.Unlock()
	msg := fmt.Sprintf("%s:%d:%s", ip, a.port, name)
	a.conn.Write([]byte(msg))
}

type Discovery struct {
	conn     *net.UDPConn
	peers    chan PeerAnnouncement
	stop     chan struct{}
	done     chan struct{}
	seen     map[string]bool
	seenLock sync.Mutex
}

func NewDiscovery() (*Discovery, error) {
	addr, err := net.ResolveUDPAddr("udp4", discoveryAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return nil, err
	}
	return &Discovery{
		conn:  conn,
		peers: make(chan PeerAnnouncement, 16),
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
		seen:  make(map[string]bool),
	}, nil
}

func (d *Discovery) Peers() <-chan PeerAnnouncement { return d.peers }

func (d *Discovery) Start() {
	go func() {
		defer close(d.done)
		buf := make([]byte, 512)
		for {
			select {
			case <-d.stop:
				return
			default:
			}
			d.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, _, err := d.conn.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				select {
				case <-d.stop:
					return
				default:
					continue
				}
			}
			msg := strings.TrimSpace(string(buf[:n]))
			parts := strings.SplitN(msg, ":", 3)
			if len(parts) < 2 {
				continue
			}
			addr := parts[0] + ":" + parts[1]
			name := ""
			if len(parts) > 2 {
				name = parts[2]
			}
			localIP, _ := lanIP()
			if parts[0] == localIP {
				continue
			}
			d.seenLock.Lock()
			if d.seen[addr] {
				d.seenLock.Unlock()
				continue
			}
			d.seen[addr] = true
			d.seenLock.Unlock()
			select {
			case d.peers <- PeerAnnouncement{Addr: addr, Name: name}:
			default:
			}
		}
	}()
}

func (d *Discovery) Stop() {
	close(d.stop)
	d.conn.Close()
	<-d.done
}

func (d *Discovery) Forget(addr string) {
	d.seenLock.Lock()
	delete(d.seen, addr)
	d.seenLock.Unlock()
}

func lanIP() (string, error) {
	conn, err := net.Dial("udp4", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String(), nil
}
