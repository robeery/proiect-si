package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"proiect-si/transport"
)

func randomName() string {
	var b [2]byte
	rand.Read(b[:])
	return "peer-" + hex.EncodeToString(b[:])
}

func main() {
	port := flag.Int("port", 9001, "TCP listen port")
	name := flag.String("name", "", "display name (default: auto-generated)")
	testDiscovery := flag.Bool("test-discovery", false, "run discovery test mode: discover peers then exit")
	testTimeout := flag.Duration("test-timeout", 15*time.Second, "timeout for discovery test mode")
	flag.Parse()

	if *name == "" {
		*name = randomName()
	}

	swarm, err := transport.NewSwarm(*port, *name)
	if err != nil {
		fmt.Fprintln(os.Stderr, "swarm:", err)
		os.Exit(1)
	}

	swarm.Start()
	defer swarm.Close()

	fmt.Printf("listening on %s, announcing as %q\n", swarm.Addr(), swarm.Name())

	if *testDiscovery {
		runDiscoveryTest(swarm, *testTimeout)
		return
	}

	prog := tea.NewProgram(
		newTUIModel(swarm, "exchanged"),
		tea.WithAltScreen(),
	)
	if _, err := prog.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "tui:", err)
		os.Exit(1)
	}
}

func runDiscoveryTest(swarm *transport.Swarm, timeout time.Duration) {
	seen := make(map[string]string)
	deadline := time.After(timeout)

	for {
		select {
		case ev := <-swarm.Events():
			switch e := ev.(type) {
			case transport.PeerJoinedEvent:
				seen[e.Peer.Fingerprint] = e.Peer.Name
				fmt.Printf("discovered peer: %s (%s)\n", e.Peer.Name, e.Peer.Fingerprint)
			case transport.PeerLeftEvent:
				fmt.Printf("peer left: %s\n", e.Fingerprint)
			}
		case <-deadline:
			if len(seen) == 0 {
				fmt.Println("discovered 0 peers")
				os.Exit(1)
			}
			names := make([]string, 0, len(seen))
			for _, n := range seen {
				names = append(names, n)
			}
			fmt.Printf("discovered %d peer(s): %s\n", len(seen), names)
			os.Exit(0)
		}
	}
}
