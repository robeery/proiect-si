package transport

import (
	"errors"
	"net"
	"sync"
)

const (
	chatQueueSize  = 64
	fileQueueSize  = 256
	chatBurstLimit = 5
)

var ErrPeerClosed = errors.New("transport: peer closed")

type Peer struct {
	conn        net.Conn
	session     *Session
	incoming    chan []byte
	done        chan struct{}
	closeOnce   sync.Once
	chatQueue   chan []byte
	fileQueue   chan fileMessage
	name        string
	fingerprint string
}

type fileMessage struct {
	plaintext []byte
	written   chan error
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
		chatQueue:   make(chan []byte, chatQueueSize),
		fileQueue:   make(chan fileMessage, fileQueueSize),
		fingerprint: fingerprint,
	}
	go p.readLoop()
	go p.writeLoop()
	return p, nil
}

func (p *Peer) Send(plaintext []byte) error {
	return p.enqueue(p.chatQueue, plaintext)
}

func (p *Peer) SendFileMessage(plaintext []byte) error {
	written := make(chan error, 1)
	msg := fileMessage{
		plaintext: plaintext,
		written:   written,
	}

	if p.isClosed() {
		return ErrPeerClosed
	}
	select {
	case <-p.done:
		return ErrPeerClosed
	case p.fileQueue <- msg:
	}

	select {
	case err := <-written:
		return err
	case <-p.done:
		select {
		case err := <-written:
			return err
		default:
			return ErrPeerClosed
		}
	}
}

func (p *Peer) enqueue(ch chan []byte, plaintext []byte) error {
	if p.isClosed() {
		return ErrPeerClosed
	}
	select {
	case <-p.done:
		return ErrPeerClosed
	case ch <- plaintext:
		return nil
	}
}

func (p *Peer) isClosed() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
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

func (p *Peer) writeLoop() {
	chatQ := p.chatQueue
	fileQ := p.fileQueue
	chatBurst := 0

	for {
		if chatQ == nil && fileQ == nil {
			return
		}

		select {
		case <-p.done:
			return
		default:
		}

		if chatBurst >= chatBurstLimit && fileQ != nil {
			select {
			case msg, ok := <-fileQ:
				if !ok {
					fileQ = nil
					chatBurst = 0
					continue
				}
				if err := p.session.WriteMessage(p.conn, msg.plaintext); err != nil {
					completeFileMessage(msg, err)
					p.Close()
					return
				}
				completeFileMessage(msg, nil)
				chatBurst = 0
				continue
			default:
			}
		}

		if chatQ != nil && chatBurst < chatBurstLimit {
			select {
			case msg, ok := <-chatQ:
				if !ok {
					chatQ = nil
					chatBurst = 0
					continue
				}
				if err := p.session.WriteMessage(p.conn, msg); err != nil {
					p.Close()
					return
				}
				chatBurst++
				continue
			default:
			}
		}

		select {
		case msg, ok := <-chatQ:
			if !ok {
				chatQ = nil
				chatBurst = 0
				continue
			}
			if err := p.session.WriteMessage(p.conn, msg); err != nil {
				p.Close()
				return
			}
			chatBurst++
		case msg, ok := <-fileQ:
			if !ok {
				fileQ = nil
				chatBurst = 0
				continue
			}
			if err := p.session.WriteMessage(p.conn, msg.plaintext); err != nil {
				completeFileMessage(msg, err)
				p.Close()
				return
			}
			completeFileMessage(msg, nil)
			chatBurst = 0
		case <-p.done:
			return
		}
	}
}

func completeFileMessage(msg fileMessage, err error) {
	if msg.written == nil {
		return
	}
	select {
	case msg.written <- err:
	default:
	}
}
