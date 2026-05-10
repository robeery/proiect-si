package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/sahilm/fuzzy"
)

type fileItem struct {
	name  string
	path  string
	isDir bool
}

func (f fileItem) FilterValue() string { return f.name }

func (f fileItem) Title() string {
	if f.isDir {
		return f.name + "/"
	}
	return f.name
}

func (f fileItem) Description() string {
	if f.isDir {
		return "dir"
	}
	return "file"
}

type filePickerDirMsg struct {
	dir     string
	entries []os.DirEntry
	err     error
}

type filePickerModel struct {
	cwd          string
	list         list.Model
	search       textinput.Model
	allItems     []fileItem
	width        int
	height       int
	selectedPath string
	errMsg       string
	showHidden   bool
	showHelp     bool
}

func newFilePicker() (filePickerModel, error) {
	startDir, err := os.UserHomeDir()
	if err != nil || startDir == "" {
		startDir = "/"
	}

	search := textinput.New()
	search.Prompt = "/ "
	search.Placeholder = "search files"
	search.CharLimit = 256
	search.Blur()
	search.PromptStyle = styleSelected
	search.TextStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	search.PlaceholderStyle = styleInactive

	delegate := list.NewDefaultDelegate()
	delegate.ShowDescription = false
	delegate.SetHeight(1)
	delegate.Styles.NormalTitle = lipgloss.NewStyle().Foreground(lipgloss.Color("252")).Padding(0, 0, 0, 1)
	delegate.Styles.SelectedTitle = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FFFF")).Bold(true).Padding(0, 0, 0, 1)
	delegate.Styles.FilterMatch = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FFFF")).Bold(true)

	l := list.New([]list.Item{}, delegate, 0, 0)
	l.SetShowTitle(false)
	l.SetShowStatusBar(false)
	l.SetShowPagination(false)
	l.SetShowHelp(false)
	l.SetFilteringEnabled(false)
	l.DisableQuitKeybindings()
	l.SetStatusBarItemName("file", "files")
	l.Styles.NoItems = lipgloss.NewStyle().Foreground(lipgloss.Color("243")).SetString("no files")
	l.Styles.FilterPrompt = styleSelected
	l.Styles.Title = styleHeader
	l.Styles.TitleBar = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))

	return filePickerModel{
		cwd:      startDir,
		list:     l,
		search:   search,
		showHelp: true,
	}, err
}

func (m filePickerModel) Init() tea.Cmd {
	return readDirCmd(m.cwd)
}

func (m *filePickerModel) SetSize(width, height int) {
	m.width = width
	m.height = height
	listWidth, _ := m.layout()

	listHeight := height - 5
	if listHeight < 1 {
		listHeight = 1
	}
	m.list.SetSize(listWidth, listHeight)

	inputWidth := listWidth - 3
	if inputWidth < 0 {
		inputWidth = 0
	}
	m.search.Width = inputWidth
}

func (m *filePickerModel) TakeSelection() (string, bool) {
	if m.selectedPath == "" {
		return "", false
	}
	path := m.selectedPath
	m.selectedPath = ""
	return path, true
}

func (m filePickerModel) View() string {
	width := m.width
	if width <= 0 {
		width = m.list.Width()
	}
	if width < 1 {
		width = 1
	}
	m.width = width
	browserWidth, helpWidth := m.layout()

	headerText := "Files"
	header := lipgloss.NewStyle().Width(browserWidth).Render(styleHeader.Render(headerText))
	hiddenLabel := "hidden:off"
	if m.showHidden {
		hiddenLabel = "hidden:on"
	}
	helpLabel := "help:off"
	if m.showHelp && helpWidth > 0 {
		helpLabel = "help:on"
	}
	pathLine := lipgloss.NewStyle().Width(browserWidth).Render(styleInactive.Render(m.cwd + " · " + hiddenLabel + " · " + helpLabel + " (?)"))
	search := lipgloss.NewStyle().Width(browserWidth).Render(m.search.View())

	body := m.list.View()
	if m.errMsg != "" {
		body = styleSystem.Render("error: "+m.errMsg) + "\n" + body
	}

	browser := lipgloss.JoinVertical(lipgloss.Left, header, pathLine, search, body)
	content := browser
	if m.showHelp && helpWidth > 0 {
		content = lipgloss.JoinHorizontal(lipgloss.Top, browser, m.renderHelp(helpWidth))
	}
	border := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("236")).
		Padding(0, 1).
		Width(width)
	return border.Render(content)
}

func (m filePickerModel) Update(msg tea.Msg) (filePickerModel, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case filePickerDirMsg:
		if msg.err != nil {
			m.errMsg = msg.err.Error()
			cmds = append(cmds, m.list.SetItems(nil))
			return m, tea.Batch(cmds...)
		}
		m.errMsg = ""
		m.cwd = msg.dir
		cmds = append(cmds, m.setEntries(msg.entries))
		return m, tea.Batch(cmds...)
	}

	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch keyMsg.Type {
		case tea.KeyEnter:
			var cmd tea.Cmd
			m.selectedPath, cmd = m.activateSelection()
			if cmd != nil {
				cmds = append(cmds, cmd)
			}
			return m, tea.Batch(cmds...)
		case tea.KeyRight:
			if !m.search.Focused() {
				cmd := m.enterSelectedDir()
				if cmd != nil {
					cmds = append(cmds, cmd)
				}
				return m, tea.Batch(cmds...)
			}
		case tea.KeyBackspace, tea.KeyCtrlH:
			if m.search.Value() == "" {
				cmd := m.goUp()
				if cmd != nil {
					cmds = append(cmds, cmd)
				}
				return m, tea.Batch(cmds...)
			}
		case tea.KeyEsc:
			if m.search.Focused() {
				m.search.SetValue("")
				m.search.Blur()
				cmds = append(cmds, m.applyFilter())
				m.SetSize(m.width, m.height)
				return m, tea.Batch(cmds...)
			}
		}

		if keyMsg.Type == tea.KeyRunes && string(keyMsg.Runes) == "/" && !m.search.Focused() {
			m.search.Focus()
			cmds = append(cmds, textinput.Blink)
			m.SetSize(m.width, m.height)
			return m, tea.Batch(cmds...)
		}

		if keyMsg.Type == tea.KeyRunes && string(keyMsg.Runes) == "." && !m.search.Focused() {
			m.showHidden = !m.showHidden
			return m, readDirCmd(m.cwd)
		}

		if keyMsg.Type == tea.KeyRunes && string(keyMsg.Runes) == "?" && !m.search.Focused() {
			m.showHelp = !m.showHelp
			m.SetSize(m.width, m.height)
			return m, tea.Batch(cmds...)
		}
	}

	prevSearch := m.search.Value()
	if m.search.Focused() {
		var searchCmd tea.Cmd
		m.search, searchCmd = m.search.Update(msg)
		cmds = append(cmds, searchCmd)
		if prevSearch != m.search.Value() {
			cmds = append(cmds, m.applyFilter())
			m.SetSize(m.width, m.height)
		}
	}

	var listCmd tea.Cmd
	m.list, listCmd = m.list.Update(msg)
	cmds = append(cmds, listCmd)

	return m, tea.Batch(cmds...)
}

func (m filePickerModel) layout() (browserWidth, helpWidth int) {
	if !m.showHelp {
		return m.width, 0
	}
	return filePickerLayout(m.width)
}

func filePickerLayout(width int) (browserWidth, helpWidth int) {
	browserWidth = width
	if width < 72 {
		return browserWidth, 0
	}

	helpWidth = 36
	browserWidth = width - helpWidth - 2
	if browserWidth < 28 {
		return width, 0
	}
	return browserWidth, helpWidth
}

func (m filePickerModel) renderHelp(width int) string {
	keyStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#FF69B4")).Bold(true).Width(11)
	action := lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	lines := []string{styleSelected.Render("Navigation")}
	rows := [][2]string{
		{"↑/↓", "select"},
		{"→", "open folder"},
		{"Enter", "open / send file"},
		{"Backspace", "parent folder"},
		{"/", "search files"},
		{".", "hidden files"},
		{"Esc", "close picker"},
		{"?", "hide help"},
	}
	for _, row := range rows {
		lines = append(lines, keyStyle.Render(row[0])+action.Render(row[1]))
	}
	return lipgloss.NewStyle().
		Width(width-4).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("236")).
		Padding(0, 1).
		Render(strings.Join(lines, "\n"))
}

func (m *filePickerModel) setEntries(entries []os.DirEntry) tea.Cmd {
	items := make([]fileItem, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !m.showHidden && strings.HasPrefix(name, ".") {
			continue
		}
		items = append(items, fileItem{
			name:  name,
			path:  filepath.Join(m.cwd, name),
			isDir: entry.IsDir(),
		})
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].isDir != items[j].isDir {
			return items[i].isDir
		}
		return strings.ToLower(items[i].name) < strings.ToLower(items[j].name)
	})

	m.allItems = items
	return m.applyFilter()
}

func (m *filePickerModel) applyFilter() tea.Cmd {
	term := strings.TrimSpace(m.search.Value())
	if term == "" {
		items := make([]list.Item, 0, len(m.allItems))
		for _, item := range m.allItems {
			items = append(items, item)
		}
		cmd := m.list.SetItems(items)
		m.list.ResetSelected()
		return cmd
	}

	names := make([]string, 0, len(m.allItems))
	for _, item := range m.allItems {
		names = append(names, item.name)
	}
	matches := fuzzy.Find(term, names)
	filtered := make([]list.Item, 0, len(matches))
	for _, match := range matches {
		filtered = append(filtered, m.allItems[match.Index])
	}
	cmd := m.list.SetItems(filtered)
	m.list.ResetSelected()
	return cmd
}

func (m *filePickerModel) activateSelection() (string, tea.Cmd) {
	item := m.list.SelectedItem()
	if item == nil {
		return "", nil
	}
	entry, ok := item.(fileItem)
	if !ok {
		return "", nil
	}
	if entry.isDir {
		m.cwd = entry.path
		m.search.SetValue("")
		m.search.Blur()
		return "", readDirCmd(m.cwd)
	}
	return entry.path, nil
}

func (m *filePickerModel) enterSelectedDir() tea.Cmd {
	item := m.list.SelectedItem()
	if item == nil {
		return nil
	}
	entry, ok := item.(fileItem)
	if !ok || !entry.isDir {
		return nil
	}
	m.cwd = entry.path
	m.search.SetValue("")
	m.search.Blur()
	return readDirCmd(m.cwd)
}

func (m *filePickerModel) goUp() tea.Cmd {
	parent := filepath.Dir(m.cwd)
	if parent == m.cwd {
		return nil
	}
	m.cwd = parent
	m.search.SetValue("")
	m.search.Blur()
	return readDirCmd(m.cwd)
}

func readDirCmd(dir string) tea.Cmd {
	return func() tea.Msg {
		entries, err := os.ReadDir(dir)
		return filePickerDirMsg{dir: dir, entries: entries, err: err}
	}
}
