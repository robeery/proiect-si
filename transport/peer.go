package transport

import (
	"net"
	"sync"
)

// Peer is one live TCP connection to another station
// handshake runs on connect, after that all traffic is encrypted via Session
type Peer struct {
	conn      net.Conn
	session   *Session
	incoming  chan []byte
	done      chan struct{}
	closeOnce sync.Once
	sendMu    sync.Mutex // guards WriteMessage so concurrent Sends dont interleave frame bytes
}

// Dial connects to addr, runs the client side of the handshake, starts the read loop
func Dial(addr string) (*Peer, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	key, err := ClientHandshake(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return newPeer(conn, key)
}

// Listener accepts incoming TCP connections and produces authenticated Peers
type Listener struct {
	ln    net.Listener
	peers chan *Peer
}

// NewListener binds to addr and starts accepting in the background
// use ":0" to let the OS pick a free port, then read the actual address with Addr()
func NewListener(addr string) (*Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	l := &Listener{
		ln:    ln,
		peers: make(chan *Peer, 8),
	}
	go l.acceptLoop()
	return l, nil
}

func (l *Listener) Addr() net.Addr  { return l.ln.Addr() }
func (l *Listener) Accept() <-chan *Peer { return l.peers }
func (l *Listener) Close()           { l.ln.Close() }

func (l *Listener) acceptLoop() {
	defer close(l.peers)
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			return // listener was closed
		}
		go func() {
			key, err := ServerHandshake(conn)
			if err != nil {
				conn.Close()
				return
			}
			p, err := newPeer(conn, key)
			if err != nil {
				conn.Close()
				return
			}
			l.peers <- p
		}()
	}
}

func newPeer(conn net.Conn, key [32]byte) (*Peer, error) {
	s, err := NewSession(key)
	if err != nil {
		return nil, err
	}
	p := &Peer{
		conn:     conn,
		session:  s,
		incoming: make(chan []byte, 16),
		done:     make(chan struct{}),
	}
	go p.readLoop()
	return p, nil
}

func (p *Peer) Send(plaintext []byte) error {
	p.sendMu.Lock()
	defer p.sendMu.Unlock()
	return p.session.WriteMessage(p.conn, plaintext)
}

// Incoming returns the channel of decrypted messages from the remote peer
// the channel is closed when the connection drops
func (p *Peer) Incoming() <-chan []byte { return p.incoming }

func (p *Peer) RemoteAddr() string { return p.conn.RemoteAddr().String() }

func (p *Peer) Close() error {
	var err error
	p.closeOnce.Do(func() {
		close(p.done)
		err = p.conn.Close()
	})
	return err
}

func (p *Peer) readLoop() {
	defer close(p.incoming)
	for {
		msg, err := p.session.ReadMessage(p.conn)
		if err != nil {
			return
		}
		select {
		case p.incoming <- msg:
		case <-p.done:
			return
		}
	}
}
