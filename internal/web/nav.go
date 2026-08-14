package web

import "jbound/internal/auth"

// MenuItem is one navigation entry.
type MenuItem struct {
	// Label is a catalogue key rather than a text. The layout looks it up, so
	// one menu serves every language.
	Label string
	Path  string
	Icon  string
	// AdminOnly hides the item from a plain user. The route itself is guarded
	// by the middleware as well, because hiding a link is not access control.
	AdminOnly bool
	Active    bool
}

// MenuSection groups the items under one heading.
type MenuSection struct {
	Title string
	Items []MenuItem
}

// menu is the navigation of the panel.
//
// The reference interface has a single server, so its menu has no
// infrastructure section. Servers and the record diff are new here because the
// panel manages a fleet.
var menu = []MenuSection{
	{
		Title: "nav.section.dns",
		Items: []MenuItem{
			{Label: "nav.dns_records", Path: "/dns", Icon: "bx-server"},
			{Label: "nav.record_diff", Path: "/diff", Icon: "bx-git-compare"},
		},
	},
	{
		Title: "nav.section.infrastructure",
		Items: []MenuItem{
			{Label: "nav.servers", Path: "/servers", Icon: "bx-network-chart", AdminOnly: true},
		},
	},
	{
		Title: "nav.section.system",
		Items: []MenuItem{
			{Label: "nav.audit_logs", Path: "/logs", Icon: "bx-list-ul", AdminOnly: true},
			{Label: "nav.sessions", Path: "/sessions", Icon: "bx-user-check", AdminOnly: true},
			{Label: "nav.siem_config", Path: "/siem", Icon: "bx-transfer", AdminOnly: true},
			{Label: "nav.settings", Path: "/settings", Icon: "bx-cog", AdminOnly: true},
			{Label: "nav.system_info", Path: "/system", Icon: "bx-info-circle"},
		},
	},
}

// menuFor returns the navigation of one session with the current page marked.
//
// The reference interface marks the active item in the browser by comparing
// the location to every link. Doing it here means the page arrives correct,
// with no flash of an unmarked menu.
func menuFor(session auth.Session, path string) []MenuSection {
	sections := make([]MenuSection, 0, len(menu))

	for _, section := range menu {
		items := make([]MenuItem, 0, len(section.Items))
		for _, item := range section.Items {
			if item.AdminOnly && !session.IsAdmin() {
				continue
			}
			item.Active = item.Path == path
			items = append(items, item)
		}
		if len(items) == 0 {
			continue
		}
		sections = append(sections, MenuSection{Title: section.Title, Items: items})
	}
	return sections
}
