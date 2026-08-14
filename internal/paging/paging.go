// Package paging holds the page arithmetic every listing shares.
//
// The record table and the audit log both page over a total the database
// counts, and both had their own copy of the same clamp. Two copies of an
// off-by-one is two places to fix it and nothing that fails when only one of
// them is.
package paging

// The page sizes a listing accepts.
//
// The lower bound keeps a request from asking for a page so small that paging
// costs more than the rows, and the upper bound is what one page may cost the
// panel to render.
const (
	Min = 10
	Max = 100
)

// Clamp bounds a requested page number and page size.
//
// A size of zero means the caller named none, which is what the fallback is
// for. The page number itself cannot be clamped here, because the total is only
// known once the query has run. Of does that afterwards.
func Clamp(page, perPage, fallback int) (int, int) {
	if perPage == 0 {
		perPage = fallback
	}
	return max(1, page), max(Min, min(Max, perPage))
}

// Window is where one page sits in a result set.
//
// A listing embeds it, so its rows carry their own type while the numbers a
// pager reads are the same everywhere.
type Window struct {
	Total      int
	Page       int
	PerPage    int
	TotalPages int
}

// Of places a requested page against the total.
//
// The page is clamped against the number of pages there turned out to be,
// because a page number out of range comes from a stale link rather than from a
// missing page.
func Of(page, perPage, total int) Window {
	if perPage < 1 {
		perPage = Min
	}
	totalPages := max(1, (total+perPage-1)/perPage)

	return Window{
		Total:      total,
		Page:       max(1, min(page, totalPages)),
		PerPage:    perPage,
		TotalPages: totalPages,
	}
}

// Offset is where the page starts in the result set.
func (w Window) Offset() int { return (w.Page - 1) * w.PerPage }
