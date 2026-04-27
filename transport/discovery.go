package transport

import (
	"fmt"
	"net"
	"time"
)

const (
	broadcastAddr    = "255.255.255.255:9999"
	listenAddr       = "0.0.0.0:9999"
	announceInterval = 2 * time.Second
)

// Announcer sends our TCP listen address as a UDP broadcast every 2s
// so dialers on the same LAN can find us without knowing our IP
type Announcer struct {
	conn *net.UDPConn
	port int
	stop chan struct{}
	done chan struct{}
}

func NewAnnouncer(tcpPort int) (*Announcer, error) {
	dst, err := net.ResolveUDPAddr("udp4", broadcastAddr)
	if err != nil {
		return nil, err
	}
	// SO_BROADCAST is required to send to 255.255.255.255
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
	msg := fmt.Sprintf("%s:%d", ip, a.port)
	a.conn.Write([]byte(msg))
}

// Discover listens for a UDP broadcast announcement and returns the TCP address
// of the first peer found
func Discover() (string, error) {
	addr, err := net.ResolveUDPAddr("udp4", listenAddr)
	if err != nil {
		return "", err
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	buf := make([]byte, 256)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

// lanIP returns the machine's LAN IP by checking which local address
// would be used to reach an external host (no packet is actually sent)
func lanIP() (string, error) {
	conn, err := net.Dial("udp4", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String(), nil
}
