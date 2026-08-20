# Third-party licences

The panel serves its stylesheets, scripts, icons and fonts from inside its own
binary, because an air-gapped install reaches no CDN. Those assets are
redistributed with the panel, so their licences travel with it.

Every licence here requires its notice to be kept with the copies. Keep this
directory with the binary you ship.

| Component | Version | Licence | File |
| --- | --- | --- | --- |
| htmx | 2.0.10 | 0BSD | `htmx.txt` |
| SweetAlert2 | 11.14.5 | MIT | `sweetalert2.txt` |
| Boxicons | 2.1.4 | MIT | `boxicons.txt` |

Everything else is the panel's own. `panel.css` and `app.js` are written here
and carry the licence of the panel. There is no vendor template under them: the
interface used to sit on Sneat and Bootstrap, and dropping both took a megabyte
of stylesheet and five scripts out of the binary.

The text is set in the fonts the reader's system already has, so no font is
shipped for it and no page reaches a font host.

Boxicons ships as `boxicons.woff2`, `boxicons.woff` and `boxicons.ttf`. The
`eot` and `svg` formats are left out: they serve browsers the panel does not
support and cost 1.4 MB.
