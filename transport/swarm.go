package transport

import (
	"fmt"
	"sync"
)

type SwarmEvent interface{ swarmEvent() }

type PeerJoinedEvent struct {
	Peer *ConnectedPeer
}

func (PeerJoinedEvent) swarmEvent() {}

type PeerLeftEvent struct {
	Fingerprint string
}

func (PeerLeftEvent) swarmEvent() {}

type PeerMessageEvent struct {
	Fingerprint string
	Data        []byte
}

func (PeerMessageEvent) swarmEvent() {}

type ConnectedPeer struct {
	Peer        *Peer
	Name        string
	Fingerprint string
	Addr        string
}

type Swarm struct {
	listener  *Listener
	announcer *Announcer
	discovery *Discovery

	mu      sync.RWMutex
	peers   map[string]*ConnectedPeer
	dialing map[string]bool
	name    string
	port    int

	events    chan SwarmEvent
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func NewSwarm(port int, name string) (*Swarm, error) {
	l, err := NewListener(fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}
	ann, err := NewAnnouncer(port)
	if err != nil {
		l.Close()
		return nil, err
	}
	ann.SetName(name)
	disc, err := NewDiscovery()
	if err != nil {
		l.Close()
		ann.Stop()
		return nil, err
	}
	return &Swarm{
		listener:  l,
		announcer: ann,
		discovery: disc,
		peers:     make(map[string]*ConnectedPeer),
		dialing:   make(map[string]bool),
		name:      name,
		port:      port,
		events:    make(chan SwarmEvent, 64),
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}, nil
}

func (s *Swarm) Start() {
	s.announcer.Start()
	s.discovery.Start()
	go s.acceptLoop()
	go s.discoverLoop()
	go func() {
		<-s.stop
		s.listener.Close()
		s.announcer.Stop()
		s.discovery.Stop()
		s.mu.Lock()
		for _, cp := range s.peers {
			cp.Peer.Close()
		}
		s.mu.Unlock()
		close(s.done)
	}()
}

func (s *Swarm) Events() <-chan SwarmEvent { return s.events }

func (s *Swarm) Name() string { return s.name }

func (s *Swarm) SetName(name string) {
	s.mu.Lock()
	s.name = name
	s.mu.Unlock()
	s.announcer.SetName(name)
}

func (s *Swarm) Peers() []*ConnectedPeer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*ConnectedPeer, 0, len(s.peers))
	for _, cp := range s.peers {
		out = append(out, cp)
	}
	return out
}

func (s *Swarm) Send(fingerprint string, data []byte) error {
	s.mu.RLock()
	cp, ok := s.peers[fingerprint]
	s.mu.RUnlock()
	if !ok {
		return fmt.Errorf("swarm: peer %s not connected", fingerprint)
	}
	return cp.Peer.Send(data)
}

func (s *Swarm) Port() int    { return s.port }
func (s *Swarm) Addr() string { return s.listener.Addr().String() }

func (s *Swarm) Close() error {
	s.closeOnce.Do(func() {
		close(s.stop)
		<-s.done
	})
	return nil
}

func (s *Swarm) acceptLoop() {
	for {
		select {
		case <-s.stop:
			return
		case peer, ok := <-s.listener.Accept():
			if !ok {
				return
			}
			go s.handleNewPeer(peer)
		}
	}
}

func (s *Swarm) discoverLoop() {
	for {
		select {
		case <-s.stop:
			return
		case ann, ok := <-s.discovery.Peers():
			if !ok {
				return
			}
			go s.dialPeer(ann.Addr)
		}
	}
}

func (s *Swarm) dialPeer(addr string) {
	s.mu.Lock()
	dialing := s.dialing[addr]
	if dialing {
		s.mu.Unlock()
		return
	}
	s.dialing[addr] = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.dialing, addr)
		s.mu.Unlock()
	}()

	peer, err := Dial(addr)
	if err != nil {
		s.discovery.Forget(addr)
		return
	}
	s.handleNewPeer(peer)
}

func (s *Swarm) handleNewPeer(peer *Peer) {
	s.mu.RLock()
	name := s.name
	s.mu.RUnlock()

	if err := peer.Send(EncodeHello(name)); err != nil {
		peer.Close()
		return
	}

	helloData, ok := <-peer.Incoming()
	if !ok {
		peer.Close()
		return
	}
	typ, payload, err := DecodeMessage(helloData)
	if err != nil || typ != MsgHello {
		peer.Close()
		return
	}
	peerName, err := DecodeHello(payload)
	if err != nil {
		peer.Close()
		return
	}
	peer.SetName(peerName)
	fp := peer.Fingerprint()
	addr := peer.RemoteAddr()

	s.mu.Lock()
	if _, exists := s.peers[fp]; exists {
		s.mu.Unlock()
		peer.Close()
		return
	}
	cp := &ConnectedPeer{
		Peer:        peer,
		Name:        peerName,
		Fingerprint: fp,
		Addr:        addr,
	}
	s.peers[fp] = cp
	s.mu.Unlock()

	select {
	case s.events <- PeerJoinedEvent{Peer: cp}:
	default:
	}

	go s.readLoop(cp)
}

func (s *Swarm) readLoop(cp *ConnectedPeer) {
	for data := range cp.Peer.Incoming() {
		select {
		case s.events <- PeerMessageEvent{Fingerprint: cp.Fingerprint, Data: data}:
		case <-s.stop:
			return
		}
	}
	s.mu.Lock()
	delete(s.peers, cp.Fingerprint)
	s.mu.Unlock()
	s.discovery.Forget(cp.Addr)
	select {
	case s.events <- PeerLeftEvent{Fingerprint: cp.Fingerprint}:
	default:
	}
}
