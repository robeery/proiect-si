package main

import (
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"proiect-si/transport"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "listen":
		cmdListen(os.Args[2:])
	case "dial":
		cmdDial(os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage:\n")
	fmt.Fprintf(os.Stderr, "  %s listen [--port <port>]\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s dial   [--peer <host:port>]   omit --peer to discover via LAN multicast\n", os.Args[0])
}

func cmdListen(args []string) {
	fs := flag.NewFlagSet("listen", flag.ExitOnError)
	port := fs.Int("port", 9001, "TCP port to listen on")
	fs.Parse(args)

	l, err := transport.NewListener(fmt.Sprintf(":%d", *port))
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	fmt.Printf("listening on %s, waiting for peer...\n", l.Addr())

	ann, err := transport.NewAnnouncer(*port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "discovery: %v (LAN announce disabled)\n", err)
	} else {
		ann.Start()
		defer ann.Stop()
		fmt.Println("announcing on LAN multicast")
	}

	peer, ok := <-l.Accept()
	l.Close()
	if !ok {
		fmt.Fprintln(os.Stderr, "listener closed with no connection")
		os.Exit(1)
	}

	runTUI(peer, "exchanged")
}

func cmdDial(args []string) {
	fs := flag.NewFlagSet("dial", flag.ExitOnError)
	addr := fs.String("peer", "", "peer address (host:port), omit to discover via LAN multicast")
	fs.Parse(args)

	if *addr == "" {
		fmt.Println("no --peer given, searching for peers on LAN...")
		discovered, err := transport.Discover()
		if err != nil {
			fmt.Fprintln(os.Stderr, "discovery:", err)
			os.Exit(1)
		}
		*addr = discovered
		fmt.Printf("found peer: %s\n", *addr)
	}

	peer, err := transport.Dial(*addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dial:", err)
		os.Exit(1)
	}

	runTUI(peer, "exchanged")
}

func runTUI(p *transport.Peer, recvDir string) {
	prog := tea.NewProgram(
		newTUIModel(p, recvDir),
		tea.WithAltScreen(),
	)
	if _, err := prog.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "tui:", err)
		os.Exit(1)
	}
}
