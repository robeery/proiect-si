package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

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
	fmt.Printf("listening on %s\n", l.Addr())
	fmt.Println("waiting for peer...")

	peer, ok := <-l.Accept()
	l.Close()
	if !ok {
		fmt.Fprintln(os.Stderr, "listener closed with no connection")
		os.Exit(1)
	}
	fmt.Printf("connected: %s\n", peer.RemoteAddr())
	runSession(peer)
}

func cmdDial(args []string) {
	fs := flag.NewFlagSet("dial", flag.ExitOnError)
	addr := fs.String("peer", "", "peer address (host:port)")
	fs.Parse(args)

	if *addr == "" {
		fmt.Fprintln(os.Stderr, "dial: --peer is required")
		os.Exit(1)
	}

	fmt.Printf("connecting to %s...\n", *addr)
	peer, err := transport.Dial(*addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dial:", err)
		os.Exit(1)
	}
	fmt.Printf("connected: %s\n", peer.RemoteAddr())
	runSession(peer)
}

func runSession(p *transport.Peer) {
	defer p.Close()

	fmt.Println("type a message and enter to send")
	fmt.Println("commands: /sendfile <path>   /quit")

	go func() {
		recvr := transport.NewFileReceiver(".")
		for data := range p.Incoming() {
			typ, payload, err := transport.DecodeMessage(data)
			if err != nil {
				continue
			}
			switch typ {
			case transport.MsgText:
				// \r clears the "> " prompt before printing so the line looks clean
				fmt.Printf("\r[%s] %s\n> ", p.RemoteAddr(), transport.DecodeText(payload))
			case transport.MsgFileMeta, transport.MsgFileChunk, transport.MsgFileDone:
				done, outPath, ferr := recvr.HandleMessage(data)
				if ferr != nil {
					fmt.Fprintf(os.Stderr, "\rfile recv error: %v\n> ", ferr)
					continue
				}
				if done {
					fmt.Printf("\r[%s] file received: %s\n> ", p.RemoteAddr(), outPath)
				}
			}
		}
		fmt.Println("\nconnection closed")
		// os.Exit here because scanner.Scan() below blocks indefinitely on stdin
		// and there is no clean way to interrupt it from another goroutine
		os.Exit(0)
	}()

	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("> ")
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case line == "/quit":
			fmt.Println("bye")
			return
		case strings.HasPrefix(line, "/sendfile "):
			path := strings.TrimPrefix(line, "/sendfile ")
			fmt.Printf("sending %s...\n", path)
			if err := transport.SendFile(p, path); err != nil {
				fmt.Fprintln(os.Stderr, "sendfile:", err)
			} else {
				fmt.Println("file sent")
			}
		case line == "":
			// skip
		default:
			if err := p.Send(transport.EncodeText(line)); err != nil {
				fmt.Fprintln(os.Stderr, "send:", err)
				return
			}
		}
		fmt.Print("> ")
	}
}
