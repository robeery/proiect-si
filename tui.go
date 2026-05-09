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

type peerJoinedEvent struct{ peer *transport.ConnectedPeer }
type peerLeftEvent struct{ fingerprint string }
type peerMessageEvent struct {
	fingerprint string
	data        []byte
}
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
	styleSelected = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FFFF")).Bold(true)
	stylePeerName = lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	stylePeerList = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1)
	styleInactive = lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
)

var (
	gradientCyan, _ = colorful.Hex("#00FFFF")
	gradientPink, _ = colorful.Hex("#FF69B4")
)

type tuiModel struct {
	swarm     *transport.Swarm
	recvDir   string
	peerOrder []string
	chats     map[string][]string
	fileRecv  map[string]*transport.FileReceiver

	selected   int
	width      int
	height     int
	input      textinput.Model
	viewport   viewport.Model
	progressCh <-chan fileProgressEvent
	progress   string
}

func newTUIModel(swarm *transport.Swarm, recvDir string) tuiModel {
	ti := textinput.New()
	ti.Placeholder = "type a message, /sendfile <path>, or /quit"
	ti.Focus()
	ti.Prompt = "> "

	return tuiModel{
		swarm:    swarm,
		recvDir:  recvDir,
		chats:    make(map[string][]string),
		fileRecv: make(map[string]*transport.FileReceiver),
		input:    ti,
	}
}

func (m tuiModel) Init() tea.Cmd {
	return tea.Batch(
		textinput.Blink,
		listenSwarmEvents(m.swarm.Events()),
	)
}

func listenSwarmEvents(ch <-chan transport.SwarmEvent) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return nil
		}
		switch e := ev.(type) {
		case transport.PeerJoinedEvent:
			return peerJoinedEvent{peer: e.Peer}
		case transport.PeerLeftEvent:
			return peerLeftEvent{fingerprint: e.Fingerprint}
		case transport.PeerMessageEvent:
			return peerMessageEvent{fingerprint: e.Fingerprint, data: e.Data}
		default:
			return nil
		}
	}
}

func listenFileProgress(ch <-chan fileProgressEvent) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return nil
		}
		return ev
	}
}

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
		leftWidth := 22
		if m.width < 60 {
			leftWidth = m.width / 4
		}
		rightWidth := m.width - leftWidth - 3
		vpHeight := m.height - 5
		if vpHeight < 1 {
			vpHeight = 1
		}
		if m.viewport.Width == 0 {
			m.viewport = viewport.New(rightWidth, vpHeight)
			m.viewport.SetContent("")
			m.viewport.GotoBottom()
		} else {
			m.viewport.Width = rightWidth
			m.viewport.Height = vpHeight
		}

	case peerJoinedEvent:
		fp := msg.peer.Fingerprint
		m.peerOrder = append(m.peerOrder, fp)
		m.chats[fp] = []string{styleSystem.Render(fmt.Sprintf("connected to %s", msg.peer.Name))}
		m.fileRecv[fp] = transport.NewFileReceiver(m.recvDir)
		if len(m.peerOrder) == 1 {
			m.selected = 0
		}
		m = m.refreshViewport()
		cmds = append(cmds, listenSwarmEvents(m.swarm.Events()))

	case peerLeftEvent:
		for i, fp := range m.peerOrder {
			if fp == msg.fingerprint {
				m.peerOrder = append(m.peerOrder[:i], m.peerOrder[i+1:]...)
				break
			}
		}
		delete(m.chats, msg.fingerprint)
		delete(m.fileRecv, msg.fingerprint)
		if m.selected >= len(m.peerOrder) && len(m.peerOrder) > 0 {
			m.selected = len(m.peerOrder) - 1
		}
		m = m.refreshViewport()
		cmds = append(cmds, listenSwarmEvents(m.swarm.Events()))

	case peerMessageEvent:
		fp := msg.fingerprint
		typ, payload, err := transport.DecodeMessage(msg.data)
		if err != nil {
			m.chats[fp] = append(m.chats[fp], styleSystem.Render(fmt.Sprintf("decode error: %v", err)))
		} else {
			switch typ {
			case transport.MsgText:
				peerName := m.peerName(fp)
				label := stylePeer.Render(fmt.Sprintf("[%s]", peerName))
				m.chats[fp] = append(m.chats[fp], label+" "+transport.DecodeText(payload))
			case transport.MsgFileMeta, transport.MsgFileChunk, transport.MsgFileDone:
				if recv, ok := m.fileRecv[fp]; ok {
					done, outPath, ferr := recv.HandleMessage(msg.data)
					if ferr != nil {
						m.chats[fp] = append(m.chats[fp], styleSystem.Render(fmt.Sprintf("file error: %v", ferr)))
					} else if done {
						m.chats[fp] = append(m.chats[fp], styleSystem.Render(fmt.Sprintf("file received: %s", outPath)))
					}
				}
			}
		}
		m = m.refreshViewport()
		cmds = append(cmds, listenSwarmEvents(m.swarm.Events()))

	case fileProgressEvent:
		if m.progressCh != nil {
			cmds = append(cmds, listenFileProgress(m.progressCh))
		}
		m.progress = renderProgressBar(msg.sent, msg.total, m.width-2)

	case fileSentEvent:
		m.progress = ""
		m.progressCh = nil
		fp := m.currentFingerprint()
		if msg.err != nil {
			m.chats[fp] = append(m.chats[fp], styleSystem.Render(fmt.Sprintf("sendfile error: %v", msg.err)))
		} else {
			m.chats[fp] = append(m.chats[fp], styleSystem.Render(fmt.Sprintf("sent: %s", msg.path)))
		}
		m = m.refreshViewport()

	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC, tea.KeyEsc:
			go m.swarm.Close()
			return m, tea.Quit

		case tea.KeyTab:
			if len(m.peerOrder) > 0 {
				m.selected = (m.selected + 1) % len(m.peerOrder)
				m = m.refreshViewport()
			}

		case tea.KeyShiftTab:
			if len(m.peerOrder) > 0 {
				m.selected = (m.selected - 1 + len(m.peerOrder)) % len(m.peerOrder)
				m = m.refreshViewport()
			}

		case tea.KeyEnter:
			line := strings.TrimSpace(m.input.Value())
			m.input.SetValue("")
			if line == "" {
				break
			}
			cmds = append(cmds, m.handleInput(line)...)
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

func (m tuiModel) handleInput(line string) []tea.Cmd {
	var cmds []tea.Cmd
	switch {
	case line == "/quit":
		go m.swarm.Close()
		cmds = append(cmds, tea.Quit)
	case strings.HasPrefix(line, "/sendfile "):
		fp := m.currentFingerprint()
		if fp == "" {
			break
		}
		path := strings.TrimPrefix(line, "/sendfile ")
		peer := m.currentPeer()
		if peer == nil {
			break
		}
		m.chats[fp] = append(m.chats[fp], styleSystem.Render(fmt.Sprintf("sending %s...", path)))
		progressCh := make(chan fileProgressEvent, 8)
		m.progressCh = progressCh
		cmds = append(cmds, sendFileCmd(peer.Peer, path, progressCh))
		cmds = append(cmds, listenFileProgress(progressCh))
	default:
		fp := m.currentFingerprint()
		if fp == "" {
			break
		}
		m.chats[fp] = append(m.chats[fp], styleYou.Render("[you]")+" "+line)
		if err := m.swarm.Send(fp, transport.EncodeText(line)); err != nil {
			m.chats[fp] = append(m.chats[fp], styleSystem.Render(fmt.Sprintf("send error: %v", err)))
		}
	}
	return cmds
}

func (m tuiModel) currentFingerprint() string {
	if len(m.peerOrder) == 0 || m.selected >= len(m.peerOrder) {
		return ""
	}
	return m.peerOrder[m.selected]
}

func (m tuiModel) currentPeer() *transport.ConnectedPeer {
	fp := m.currentFingerprint()
	if fp == "" {
		return nil
	}
	for _, p := range m.swarm.Peers() {
		if p.Fingerprint == fp {
			return p
		}
	}
	return nil
}

func (m tuiModel) peerName(fp string) string {
	for _, p := range m.swarm.Peers() {
		if p.Fingerprint == fp {
			return p.Name
		}
	}
	return fp
}

func (m tuiModel) refreshViewport() tuiModel {
	fp := m.currentFingerprint()
	lines := m.chats[fp]
	if lines == nil {
		lines = []string{}
	}
	m.viewport.SetContent(strings.Join(lines, "\n"))
	m.viewport.GotoBottom()
	return m
}

func (m tuiModel) View() string {
	if m.width == 0 {
		return "initializing..."
	}

	leftWidth := 22
	if m.width < 60 {
		leftWidth = m.width / 4
	}
	rightWidth := m.width - leftWidth - 3
	divider := styleDivider.Render(strings.Repeat("─", m.width))
	title := gradientText("gommunication")

	peerPanel := m.renderPeerList(leftWidth, m.height-4)
	chatPanel := m.renderChat(rightWidth)

	combined := lipgloss.JoinHorizontal(lipgloss.Top, peerPanel, chatPanel)
	return title + "\n" + divider + "\n" + combined + "\n" + divider + "\n" + m.progress + "\n" + m.input.View()
}

func (m tuiModel) renderPeerList(width, height int) string {
	var b strings.Builder
	b.WriteString(styleHeader.Render("Peers"))
	b.WriteString("\n")

	if len(m.peerOrder) == 0 {
		b.WriteString(styleInactive.Render("  waiting..."))
	} else {
		for i, fp := range m.peerOrder {
			name := m.peerName(fp)
			prefix := "  "
			if i == m.selected {
				prefix = styleSelected.Render("❯ ")
				b.WriteString(styleSelected.Render(fmt.Sprintf("%s%s", prefix, name)))
			} else {
				b.WriteString(stylePeerName.Render(fmt.Sprintf("%s%s", prefix, name)))
			}
			b.WriteString("\n")
		}
	}

	content := b.String()
	style := lipgloss.NewStyle().
		Width(width).
		Height(height).
		Border(lipgloss.RoundedBorder(), true, false, true, true).
		Padding(0, 1)
	return style.Render(content)
}

func (m tuiModel) renderChat(width int) string {
	_ = width
	return m.viewport.View()
}

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
