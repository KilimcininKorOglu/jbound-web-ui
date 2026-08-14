package web

import (
	"slices"
	"testing"

	"jbound/internal/auth"
)

func adminSession() auth.Session { return auth.Session{Role: auth.RoleAdmin} }
func plainSession() auth.Session { return auth.Session{Role: auth.RoleUser} }
func pathsOf(sections []MenuSection) []string {
	var paths []string
	for _, section := range sections {
		for _, item := range section.Items {
			paths = append(paths, item.Path)
		}
	}
	return paths
}

func contains(paths []string, want string) bool {
	return slices.Contains(paths, want)
}

func TestMenuHidesAdminItemsFromAPlainUser(t *testing.T) {
	paths := pathsOf(menuFor(plainSession(), "/dns"))

	for _, hidden := range []string{"/servers", "/siem", "/logs"} {
		if contains(paths, hidden) {
			t.Errorf("a plain user sees %s in the menu", hidden)
		}
	}
	for _, shown := range []string{"/dns", "/diff", "/system"} {
		if !contains(paths, shown) {
			t.Errorf("a plain user cannot see %s in the menu", shown)
		}
	}
}

func TestMenuShowsEveryItemToAnAdmin(t *testing.T) {
	paths := pathsOf(menuFor(adminSession(), "/dns"))

	for _, shown := range []string{"/dns", "/diff", "/servers", "/logs", "/siem", "/system"} {
		if !contains(paths, shown) {
			t.Errorf("an admin cannot see %s in the menu", shown)
		}
	}
}

func TestMenuDropsASectionThatLostEveryItem(t *testing.T) {
	// Infrastructure holds only admin items, so a plain user must not see the
	// heading hanging over an empty list.
	for _, section := range menuFor(plainSession(), "/dns") {
		if len(section.Items) == 0 {
			t.Errorf("section %q is empty", section.Title)
		}
		if section.Title == "Infrastructure" {
			t.Error("a plain user sees the Infrastructure heading")
		}
	}
}

func TestMenuMarksTheCurrentPage(t *testing.T) {
	// The reference interface marks the active item in the browser after the
	// page loads. Doing it here means the menu arrives correct.
	var active []string
	for _, section := range menuFor(adminSession(), "/logs") {
		for _, item := range section.Items {
			if item.Active {
				active = append(active, item.Path)
			}
		}
	}

	if len(active) != 1 || active[0] != "/logs" {
		t.Errorf("active items = %v, want only /logs", active)
	}
}

func TestMenuMarksNothingOnAnUnlistedPath(t *testing.T) {
	for _, section := range menuFor(adminSession(), "/servers/42/edit") {
		for _, item := range section.Items {
			if item.Active {
				t.Errorf("%s is marked active on a path that is not in the menu", item.Path)
			}
		}
	}
}
