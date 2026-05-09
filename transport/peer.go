package transport

import (
	"net"
	"sync"
)

type Peer struct {
	conn        net.Conn
	session     *Session
	incoming    chan []byte
	done        chan struct{}
	closeOnce   sync.Once
	sendMu      sync.Mutex
	name        string
	fingerprint string
}

func Dial(addr string) (*Peer, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	key, fp, err := ClientHandshake(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	p, err := newPeer(conn, key, fp)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return p, nil
}

type Listener struct {
	ln    net.Listener
	peers chan *Peer
}

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

func (l *Listener) Addr() net.Addr       { return l.ln.Addr() }
func (l *Listener) Accept() <-chan *Peer { return l.peers }
func (l *Listener) Close()               { l.ln.Close() }

func (l *Listener) acceptLoop() {
	defer close(l.peers)
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			return
		}
		go func() {
			key, fp, err := ServerHandshake(conn)
			if err != nil {
				conn.Close()
				return
			}
			p, err := newPeer(conn, key, fp)
			if err != nil {
				conn.Close()
				return
			}
			l.peers <- p
		}()
	}
}

func newPeer(conn net.Conn, key [32]byte, fingerprint string) (*Peer, error) {
	s, err := NewSession(key)
	if err != nil {
		return nil, err
	}
	p := &Peer{
		conn:        conn,
		session:     s,
		incoming:    make(chan []byte, 16),
		done:        make(chan struct{}),
		fingerprint: fingerprint,
	}
	go p.readLoop()
	return p, nil
}

func (p *Peer) Send(plaintext []byte) error {
	p.sendMu.Lock()
	defer p.sendMu.Unlock()
	return p.session.WriteMessage(p.conn, plaintext)
}

func (p *Peer) Incoming() <-chan []byte { return p.incoming }

func (p *Peer) RemoteAddr() string { return p.conn.RemoteAddr().String() }

func (p *Peer) Name() string { return p.name }

func (p *Peer) SetName(name string) { p.name = name }

func (p *Peer) Fingerprint() string { return p.fingerprint }

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
