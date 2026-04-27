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
	fmt.Fprintf(os.Stderr, "  %s listen --port <port>\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s dial   --peer <host:port>\n", os.Args[0])
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

	peer, ok := <-l.Accept()
	l.Close()
	if !ok {
		fmt.Fprintln(os.Stderr, "listener closed with no connection")
		os.Exit(1)
	}

	runTUI(peer, ".")
}

func cmdDial(args []string) {
	fs := flag.NewFlagSet("dial", flag.ExitOnError)
	addr := fs.String("peer", "", "peer address (host:port)")
	fs.Parse(args)

	if *addr == "" {
		fmt.Fprintln(os.Stderr, "dial: --peer is required")
		os.Exit(1)
	}

	peer, err := transport.Dial(*addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dial:", err)
		os.Exit(1)
	}

	runTUI(peer, ".")
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
