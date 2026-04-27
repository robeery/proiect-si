package transport

import (
	"fmt"
	"net"
	"time"
)

const (
	multicastGroup   = "239.255.0.1:9999"
	announceInterval = 2 * time.Second
)

// Announcer sends our TCP listen address to the LAN multicast group every 2s
// so dialers can find us without knowing our IP in advance
type Announcer struct {
	conn *net.UDPConn
	port int
	stop chan struct{}
	done chan struct{}
}

func NewAnnouncer(tcpPort int) (*Announcer, error) {
	dst, err := net.ResolveUDPAddr("udp4", multicastGroup)
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

// Discover joins the multicast group and blocks until it receives one announcement
// returns the TCP address of the discovered peer
func Discover() (string, error) {
	group, err := net.ResolveUDPAddr("udp4", multicastGroup)
	if err != nil {
		return "", err
	}
	conn, err := net.ListenMulticastUDP("udp4", nil, group)
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
