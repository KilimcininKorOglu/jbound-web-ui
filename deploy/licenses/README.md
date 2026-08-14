# Third-party licences

The panel serves its stylesheets, scripts, icons and fonts from inside its own
binary, because an air-gapped install reaches no CDN. Those assets are
redistributed with the panel, so their licences travel with it.

Every licence here requires its notice to be kept with the copies. Keep this
directory with the binary you ship.

| Component | Version | Licence | File |
| --- | --- | --- | --- |
| Sneat Bootstrap 5 HTML Admin Template (free) | 1.0 | MIT | `sneat.txt` |
| Bootstrap | 5.3.3 | MIT | `bootstrap.txt` |
| htmx | 2.0.10 | 0BSD | `htmx.txt` |
| SweetAlert2 | 11.14.5 | MIT | `sweetalert2.txt` |
| perfect-scrollbar | 1.5.3 | MIT | `perfect-scrollbar.txt` |
| Boxicons | 2.1.4 | MIT | `boxicons.txt` |
| Public Sans | 2.001 | SIL Open Font License 1.1 | `public-sans.txt` |

The Sneat licence covers `core.css`, `theme-default.css`, `demo.css`,
`page-auth.css`, `helpers.js` and `menu.js`. The panel's own overrides,
`brand.css`, `panel.css`, `theme-dark.css`, `layout.js` and `app.js`, carry the
licence of the panel.

Boxicons ships as `boxicons.woff2`, `boxicons.woff` and `boxicons.ttf`. The
`eot` and `svg` formats are left out: they serve browsers the panel does not
support and cost 1.4 MB.

Public Sans is served from `fonts/publicsans` rather than from Google Fonts, so
no page reaches a third party. The latin and latin-ext subsets are both carried,
because Turkish needs latin-ext.
