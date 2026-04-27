package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"proiect-si/transport"
)

// tea.Msg types for async events
type incomingMsgEvent struct{ data []byte }
type connClosedEvent struct{}
type fileSentEvent struct {
	path string
	err  error
}

var (
	styleSystem  = lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Italic(true)
	styleYou     = lipgloss.NewStyle().Foreground(lipgloss.Color("86")).Bold(true)
	stylePeer    = lipgloss.NewStyle().Foreground(lipgloss.Color("213")).Bold(true)
	styleHeader  = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	styleDivider = lipgloss.NewStyle().Foreground(lipgloss.Color("236"))
)

type tuiModel struct {
	peer     *transport.Peer
	viewport viewport.Model
	input    textinput.Model
	recvr    *transport.FileReceiver
	lines    []string
	width    int
	height   int
}

func newTUIModel(p *transport.Peer, recvDir string) tuiModel {
	ti := textinput.New()
	ti.Placeholder = "type a message, /sendfile <path>, or /quit"
	ti.Focus()
	ti.Prompt = "> "

	return tuiModel{
		peer:  p,
		input: ti,
		recvr: transport.NewFileReceiver(recvDir),
	}
}

func (m tuiModel) Init() tea.Cmd {
	return tea.Batch(
		textinput.Blink,
		listenForMsg(m.peer.Incoming()),
	)
}

// listenForMsg waits for one message from the peer channel then delivers it as a tea.Msg
// re-issue this cmd after each message to keep the loop going
func listenForMsg(ch <-chan []byte) tea.Cmd {
	return func() tea.Msg {
		data, ok := <-ch
		if !ok {
			return connClosedEvent{}
		}
		return incomingMsgEvent{data}
	}
}

// sendFileCmd runs SendFile in a background goroutine so the TUI stays responsive
func sendFileCmd(p *transport.Peer, path string) tea.Cmd {
	return func() tea.Msg {
		return fileSentEvent{path: path, err: transport.SendFile(p, path)}
	}
}

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		// header + 2 dividers + input = 4 rows reserved
		vpHeight := msg.Height - 4
		if vpHeight < 1 {
			vpHeight = 1
		}
		if m.viewport.Width == 0 {
			m.viewport = viewport.New(msg.Width, vpHeight)
			m.viewport.SetContent(joinLines(m.lines))
			m.viewport.GotoBottom()
		} else {
			m.viewport.Width = msg.Width
			m.viewport.Height = vpHeight
		}

	case incomingMsgEvent:
		// re-arm the listener immediately so we dont miss the next message
		cmds = append(cmds, listenForMsg(m.peer.Incoming()))

		typ, payload, err := transport.DecodeMessage(msg.data)
		if err != nil {
			m = m.appendLine(styleSystem.Render(fmt.Sprintf("decode error: %v", err)))
			break
		}
		switch typ {
		case transport.MsgText:
			label := stylePeer.Render(fmt.Sprintf("[%s]", m.peer.RemoteAddr()))
			m = m.appendLine(label + " " + transport.DecodeText(payload))
		case transport.MsgFileMeta, transport.MsgFileChunk, transport.MsgFileDone:
			done, outPath, ferr := m.recvr.HandleMessage(msg.data)
			if ferr != nil {
				m = m.appendLine(styleSystem.Render(fmt.Sprintf("file error: %v", ferr)))
			} else if done {
				m = m.appendLine(styleSystem.Render(fmt.Sprintf("file received: %s", outPath)))
			}
		}

	case connClosedEvent:
		m = m.appendLine(styleSystem.Render("connection closed"))
		return m, tea.Quit

	case fileSentEvent:
		if msg.err != nil {
			m = m.appendLine(styleSystem.Render(fmt.Sprintf("sendfile error: %v", msg.err)))
		} else {
			m = m.appendLine(styleSystem.Render(fmt.Sprintf("sent: %s", msg.path)))
		}

	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC, tea.KeyEsc:
			m.peer.Close()
			return m, tea.Quit

		case tea.KeyEnter:
			line := strings.TrimSpace(m.input.Value())
			m.input.SetValue("")
			if line == "" {
				break
			}
			switch {
			case line == "/quit":
				m.peer.Close()
				return m, tea.Quit
			case strings.HasPrefix(line, "/sendfile "):
				path := strings.TrimPrefix(line, "/sendfile ")
				m = m.appendLine(styleSystem.Render(fmt.Sprintf("sending %s...", path)))
				cmds = append(cmds, sendFileCmd(m.peer, path))
			default:
				label := styleYou.Render("[you]")
				m = m.appendLine(label + " " + line)
				if err := m.peer.Send(transport.EncodeText(line)); err != nil {
					m = m.appendLine(styleSystem.Render(fmt.Sprintf("send error: %v", err)))
				}
			}
		}
	}

	var tiCmd tea.Cmd
	m.input, tiCmd = m.input.Update(msg)
	cmds = append(cmds, tiCmd)

	var vpCmd tea.Cmd
	m.viewport, vpCmd = m.viewport.Update(msg)
	cmds = append(cmds, vpCmd)

	return m, tea.Batch(cmds...)
}

func (m tuiModel) View() string {
	if m.width == 0 {
		return "initializing..."
	}
	divider := styleDivider.Render(strings.Repeat("─", m.width))
	header := styleHeader.Render(fmt.Sprintf("peer: %s", m.peer.RemoteAddr()))
	return header + "\n" +
		divider + "\n" +
		m.viewport.View() + "\n" +
		divider + "\n" +
		m.input.View()
}

// appendLine adds a line to the history and scrolls the viewport to the bottom
func (m tuiModel) appendLine(s string) tuiModel {
	m.lines = append(m.lines, s)
	m.viewport.SetContent(joinLines(m.lines))
	m.viewport.GotoBottom()
	return m
}

func joinLines(lines []string) string {
	return strings.Join(lines, "\n")
}
