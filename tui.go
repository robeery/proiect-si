package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	colorful "github.com/lucasb-eyer/go-colorful"

	"proiect-si/transport"
)

// tea.Msg types for async events
type incomingMsgEvent struct{ data []byte }
type connClosedEvent struct{}
type fileSentEvent struct {
	path string
	err  error
}
type fileProgressEvent struct {
	sent  uint32
	total uint32
}

var (
	styleSystem   = lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Italic(true)
	styleYou      = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FFFF")).Bold(true)
	stylePeer     = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF69B4")).Bold(true)
	styleHeader   = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	styleDivider  = lipgloss.NewStyle().Foreground(lipgloss.Color("236"))
	styleProgress = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
)

type tuiModel struct {
	peer       *transport.Peer
	viewport   viewport.Model
	input      textinput.Model
	recvr      *transport.FileReceiver
	lines      []string
	progressCh <-chan fileProgressEvent // nil when no transfer in progress
	progress   string                  // rendered progress bar line, empty when idle
	width      int
	height     int
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

// listenFileProgress waits for one progress update from the channel
// when the channel closes it returns nil which Bubble Tea ignores
func listenFileProgress(ch <-chan fileProgressEvent) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return nil
		}
		return ev
	}
}

// sendFileCmd runs SendFileWithProgress in a background goroutine
// progress updates are pushed to progressCh; fileSentEvent is returned when done
func sendFileCmd(p *transport.Peer, path string, progressCh chan fileProgressEvent) tea.Cmd {
	return func() tea.Msg {
		err := transport.SendFileWithProgress(p, path, func(sent, total uint32) {
			progressCh <- fileProgressEvent{sent, total}
		})
		close(progressCh)
		return fileSentEvent{path: path, err: err}
	}
}

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		// header + 2 dividers + progress line + input = 5 rows reserved
		vpHeight := msg.Height - 5
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

	case fileProgressEvent:
		if m.progressCh != nil {
			cmds = append(cmds, listenFileProgress(m.progressCh))
		}
		m.progress = renderProgressBar(msg.sent, msg.total, m.width-2)

	case fileSentEvent:
		m.progress = ""
		m.progressCh = nil
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
				progressCh := make(chan fileProgressEvent, 8)
				m.progressCh = progressCh
				cmds = append(cmds, sendFileCmd(m.peer, path, progressCh))
				cmds = append(cmds, listenFileProgress(progressCh))
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
	title := gradientText("gommunication")
	peer := styleHeader.Render(fmt.Sprintf("  peer: %s", m.peer.RemoteAddr()))
	return title + peer + "\n" +
		divider + "\n" +
		m.viewport.View() + "\n" +
		divider + "\n" +
		m.progress + "\n" +
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

var (
	gradientCyan, _ = colorful.Hex("#00FFFF")
	gradientPink, _ = colorful.Hex("#FF69B4")
)

// renderProgressBar renders a cyan-to-pink gradient bar
func renderProgressBar(sent, total uint32, width int) string {
	if total == 0 {
		return ""
	}
	pct := float64(sent) / float64(total)
	barWidth := width / 2
	if barWidth < 8 {
		barWidth = 8
	}
	filled := int(pct * float64(barWidth))

	var bar strings.Builder
	for i := range barWidth {
		if i < filled {
			t := float64(i) / float64(barWidth-1)
			c := gradientCyan.BlendHcl(gradientPink, t)
			bar.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color(c.Hex())).Render("█"))
		} else {
			bar.WriteString(styleDivider.Render("░"))
		}
	}

	pink := lipgloss.NewStyle().Foreground(lipgloss.Color("#FF69B4"))
	suffix := pink.Render(fmt.Sprintf(" %d/%d chunks (%.0f%%)", sent, total, pct*100))
	return "[" + bar.String() + "]" + suffix
}

// gradientText renders s with a per-character cyan-to-pink gradient
func gradientText(s string) string {
	runes := []rune(s)
	n := len(runes)
	var b strings.Builder
	for i, r := range runes {
		t := float64(i) / float64(n-1)
		c := gradientCyan.BlendHcl(gradientPink, t)
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color(c.Hex())).Bold(true).Render(string(r)))
	}
	return b.String()
}
