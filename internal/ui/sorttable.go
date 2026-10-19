package ui

import (
	"sort"
	"strconv"
	"strings"
	"unicode"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/widget"
)

// Column describes a SortTable column.
type Column struct {
	Title string
	Width float32
}

// SortTable is a table whose columns sort when their header is clicked.
// Clicking a header cycles ascending, descending, and the original order.
type SortTable struct {
	Table      *widget.Table
	columns    []Column
	rows       [][]string
	order      []int // view row -> data row
	sortCol    int   // -1: original (data) order
	asc        bool
	selected   int // data row, -1 if none
	OnSelected func(dataRow int)
	OnSorted   func()
}

// NewSortTable creates an empty table with the given columns.
func NewSortTable(cols []Column) *SortTable {
	st := &SortTable{columns: cols, sortCol: -1, asc: true, selected: -1}
	st.Table = widget.NewTableWithHeaders(
		func() (int, int) { return len(st.order), len(st.columns) },
		func() fyne.CanvasObject {
			l := widget.NewLabel("")
			l.Truncation = fyne.TextTruncateEllipsis
			return l
		},
		func(id widget.TableCellID, o fyne.CanvasObject) {
			l := o.(*widget.Label)
			if id.Row < len(st.order) && id.Col < len(st.columns) {
				l.SetText(st.rows[st.order[id.Row]][id.Col])
			} else {
				l.SetText("")
			}
		},
	)
	st.Table.ShowHeaderColumn = false
	st.Table.CreateHeader = func() fyne.CanvasObject {
		b := widget.NewButton("", nil)
		b.Importance = widget.LowImportance
		b.Alignment = widget.ButtonAlignLeading
		return b
	}
	st.Table.UpdateHeader = func(id widget.TableCellID, o fyne.CanvasObject) {
		b := o.(*widget.Button)
		if id.Col < 0 || id.Col >= len(st.columns) {
			b.SetText("")
			b.OnTapped = nil
			return
		}
		col := id.Col
		title := st.columns[col].Title
		if col == st.sortCol {
			if st.asc {
				title += " ▲"
			} else {
				title += " ▼"
			}
		}
		b.SetText(title)
		b.OnTapped = func() { st.cycleSort(col) }
	}
	for i, c := range cols {
		if c.Width > 0 {
			st.Table.SetColumnWidth(i, c.Width)
		}
	}
	st.Table.OnSelected = func(id widget.TableCellID) {
		if id.Row < 0 || id.Row >= len(st.order) {
			return
		}
		dr := st.order[id.Row]
		if dr == st.selected {
			return
		}
		st.selected = dr
		if st.OnSelected != nil {
			st.OnSelected(dr)
		}
	}
	st.Table.OnUnselected = func(widget.TableCellID) {}
	return st
}

// SetRows replaces the data. If keepSelection is a valid data row index in the
// new data it stays selected.
func (st *SortTable) SetRows(rows [][]string, keepSelection int) {
	st.rows = rows
	st.applySort()
	st.selected = -1
	st.Table.UnselectAll()
	st.Table.Refresh()
	if keepSelection >= 0 && keepSelection < len(rows) {
		st.SelectData(keepSelection)
	} else if st.OnSelected != nil {
		st.OnSelected(-1)
	}
}

// SelectData selects the view row showing data row dr.
func (st *SortTable) SelectData(dr int) {
	for vr, d := range st.order {
		if d == dr {
			st.Table.Select(widget.TableCellID{Row: vr, Col: 0})
			st.Table.ScrollTo(widget.TableCellID{Row: vr, Col: 0})
			return
		}
	}
}

// Selected returns the selected data row or -1.
func (st *SortTable) Selected() int { return st.selected }

// IsNaturalOrder reports whether rows are shown in their original order.
func (st *SortTable) IsNaturalOrder() bool { return st.sortCol < 0 }

// ResetSort restores the original order.
func (st *SortTable) ResetSort() {
	st.sortCol, st.asc = -1, true
	st.resort()
}

func (st *SortTable) cycleSort(col int) {
	switch {
	case st.sortCol != col:
		st.sortCol, st.asc = col, true
	case st.asc:
		st.asc = false
	default:
		st.sortCol, st.asc = -1, true
	}
	st.resort()
}

func (st *SortTable) resort() {
	sel := st.selected
	st.applySort()
	st.Table.Refresh()
	if sel >= 0 {
		st.selected = -1
		st.SelectData(sel)
	}
	if st.OnSorted != nil {
		st.OnSorted()
	}
}

func (st *SortTable) applySort() {
	st.order = make([]int, len(st.rows))
	for i := range st.order {
		st.order[i] = i
	}
	if st.sortCol < 0 {
		return
	}
	c := st.sortCol
	sort.SliceStable(st.order, func(i, j int) bool {
		a, b := st.rows[st.order[i]][c], st.rows[st.order[j]][c]
		if st.asc {
			return naturalLess(a, b)
		}
		return naturalLess(b, a)
	})
}

// naturalLess compares strings case-insensitively with embedded numbers
// compared numerically ("rule 9" < "rule 10", "22/tcp" < "443/tcp").
func naturalLess(a, b string) bool {
	a, b = strings.ToLower(a), strings.ToLower(b)
	for a != "" && b != "" {
		ra, rb := rune(a[0]), rune(b[0])
		if unicode.IsDigit(ra) && unicode.IsDigit(rb) {
			na, resta := leadingNumber(a)
			nb, restb := leadingNumber(b)
			if na != nb {
				return na < nb
			}
			a, b = resta, restb
			continue
		}
		if ra != rb {
			return ra < rb
		}
		a, b = a[1:], b[1:]
	}
	return len(a) < len(b)
}

func leadingNumber(s string) (uint64, string) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	n, _ := strconv.ParseUint(s[:i], 10, 64)
	return n, s[i:]
}
