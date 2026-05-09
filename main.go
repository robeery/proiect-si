package main

import (
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"proiect-si/transport"
)

func main() {
	port := flag.Int("port", 9001, "TCP listen port")
	name := flag.String("name", "", "display name (default: auto-generated)")
	flag.Parse()

	swarm, err := transport.NewSwarm(*port, *name)
	if err != nil {
		fmt.Fprintln(os.Stderr, "swarm:", err)
		os.Exit(1)
	}

	swarm.Start()
	defer swarm.Close()

	fmt.Printf("listening on %s, announcing as %q...\n", swarm.Addr(), swarm.Name())

	prog := tea.NewProgram(
		newTUIModel(swarm, "exchanged"),
		tea.WithAltScreen(),
	)
	if _, err := prog.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "tui:", err)
		os.Exit(1)
	}
}
