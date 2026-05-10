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
	search.PromptStyle = styleHeader
	search.TextStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	search.PlaceholderStyle = styleInactive

	delegate := list.NewDefaultDelegate()
	delegate.ShowDescription = false
	delegate.SetHeight(1)
	delegate.Styles.NormalTitle = lipgloss.NewStyle().Foreground(lipgloss.Color("252")).Padding(0, 0, 0, 1)
	delegate.Styles.SelectedTitle = lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true).Padding(0, 0, 0, 1)
	delegate.Styles.FilterMatch = lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)

	l := list.New([]list.Item{}, delegate, 0, 0)
	l.SetShowTitle(false)
	l.SetShowStatusBar(false)
	l.SetShowPagination(false)
	l.SetShowHelp(false)
	l.SetFilteringEnabled(false)
	l.DisableQuitKeybindings()
	l.SetStatusBarItemName("file", "files")
	l.Styles.NoItems = lipgloss.NewStyle().Foreground(lipgloss.Color("243")).SetString("no files")
	l.Styles.FilterPrompt = styleHeader
	l.Styles.Title = styleHeader
	l.Styles.TitleBar = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))

	return filePickerModel{
		cwd:    startDir,
		list:   l,
		search: search,
	}, err
}

func (m filePickerModel) Init() tea.Cmd {
	return readDirCmd(m.cwd)
}

func (m *filePickerModel) SetSize(width, height int) {
	m.width = width
	m.height = height

	listHeight := height - 5
	if listHeight < 1 {
		listHeight = 1
	}
	m.list.SetSize(width, listHeight)

	inputWidth := width - 3
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

	headerText := "Files"
	header := lipgloss.NewStyle().Width(width).Render(styleHeader.Render(headerText))
	hiddenLabel := "hidden:off"
	if m.showHidden {
		hiddenLabel = "hidden:on"
	}
	pathLine := lipgloss.NewStyle().Width(width).Render(styleInactive.Render(m.cwd + " · " + hiddenLabel))
	search := lipgloss.NewStyle().Width(width).Render(m.search.View())

	body := m.list.View()
	if m.errMsg != "" {
		body = styleSystem.Render("error: "+m.errMsg) + "\n" + body
	}

	content := lipgloss.JoinVertical(lipgloss.Left, header, pathLine, search, body)
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
