package paging

import "testing"

func TestClampBoundsWhatTheRequestAsksFor(t *testing.T) {
	cases := []struct {
		name                  string
		page, perPage         int
		wantPage, wantPerPage int
	}{
		{name: "a request that names no size takes the fallback",
			page: 1, perPage: 0, wantPage: 1, wantPerPage: 25},
		{name: "a size below the minimum is raised",
			page: 1, perPage: 1, wantPage: 1, wantPerPage: Min},
		{name: "a size above the maximum is cut",
			page: 1, perPage: 5000, wantPage: 1, wantPerPage: Max},
		{name: "page zero is the first page",
			page: 0, perPage: 25, wantPage: 1, wantPerPage: 25},
		{name: "a negative page is the first page",
			page: -7, perPage: 25, wantPage: 1, wantPerPage: 25},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			page, perPage := Clamp(testCase.page, testCase.perPage, 25)

			if page != testCase.wantPage {
				t.Errorf("page = %d, want %d", page, testCase.wantPage)
			}
			if perPage != testCase.wantPerPage {
				t.Errorf("per page = %d, want %d", perPage, testCase.wantPerPage)
			}
		})
	}
}

func TestTheLastPageHoldsTheRemainder(t *testing.T) {
	// The rounding is the part a listing gets wrong: 51 rows of 25 is three
	// pages, and the third one holds a single row.
	cases := []struct {
		total, perPage, wantPages int
	}{
		{total: 0, perPage: 25, wantPages: 1},
		{total: 1, perPage: 25, wantPages: 1},
		{total: 25, perPage: 25, wantPages: 1},
		{total: 26, perPage: 25, wantPages: 2},
		{total: 51, perPage: 25, wantPages: 3},
	}

	for _, testCase := range cases {
		window := Of(1, testCase.perPage, testCase.total)
		if window.TotalPages != testCase.wantPages {
			t.Errorf("%d rows of %d = %d pages, want %d",
				testCase.total, testCase.perPage, window.TotalPages, testCase.wantPages)
		}
	}
}

func TestAPageBeyondTheEndIsTheLastOne(t *testing.T) {
	// A page number out of range comes from a stale link rather than from a
	// page that is missing, so it lands on the last one rather than on nothing.
	window := Of(99, 25, 30)

	if window.Page != 2 {
		t.Errorf("page = %d, want 2", window.Page)
	}
	if window.Offset() != 25 {
		t.Errorf("offset = %d, want 25", window.Offset())
	}
}

func TestAnEmptyResultStillHasAFirstPage(t *testing.T) {
	window := Of(1, 25, 0)

	if window.TotalPages != 1 || window.Page != 1 {
		t.Errorf("got %+v, want one page", window)
	}
	if window.Offset() != 0 {
		t.Errorf("offset = %d, want 0", window.Offset())
	}
}

func TestAWindowWithNoSizeDoesNotDivideByZero(t *testing.T) {
	// Of is reached with whatever the caller holds. A listing that forgot to
	// clamp first would otherwise panic rather than report a short page.
	window := Of(1, 0, 30)

	if window.PerPage != Min {
		t.Errorf("per page = %d, want %d", window.PerPage, Min)
	}
	if window.TotalPages != 3 {
		t.Errorf("total pages = %d, want 3", window.TotalPages)
	}
}
