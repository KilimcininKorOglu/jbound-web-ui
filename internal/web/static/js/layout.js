/**
 * Layout startup.
 *
 * The reference interface loads webpack bundles of these two modules. Those
 * bundles wrap every module in a call to eval, which the content security
 * policy refuses, so the panel loads the module sources directly and does the
 * wiring here.
 *
 * This replaces the main.js of the template. The parts that are gone are the
 * ones the panel does not use: the speech to text button, the accordion class
 * toggle and the template password toggle, which app.js implements against the
 * markup of this project.
 */

import { Helpers } from './helpers.js';
import { Menu } from './menu.js';

/* The template reads both from the global scope in places. */
window.Helpers = Helpers;
window.Menu = Menu;

const layoutMenu = document.getElementById('layout-menu');

if (layoutMenu) {
  const menu = new Menu(layoutMenu, {
    orientation: 'vertical',
    closeChildren: false
  });

  Helpers.scrollToActive(false);
  Helpers.mainMenu = menu;

  document.querySelectorAll('.layout-menu-toggle').forEach(function (toggle) {
    toggle.addEventListener('click', function (event) {
      event.preventDefault();
      Helpers.toggleCollapsed();
    });
  });

  /* On a wide screen the collapse control appears after a short hover, so it
     does not sit over the menu while the pointer passes across it. */
  let hoverTimer = null;
  layoutMenu.addEventListener('mouseenter', function () {
    hoverTimer = setTimeout(function () {
      const toggle = document.querySelector('.layout-menu-toggle');
      if (toggle && !Helpers.isSmallScreen()) {
        toggle.classList.add('d-block');
      }
    }, Helpers.isSmallScreen() ? 0 : 300);
  });
  layoutMenu.addEventListener('mouseleave', function () {
    const toggle = document.querySelector('.layout-menu-toggle');
    if (toggle) {
      toggle.classList.remove('d-block');
    }
    clearTimeout(hoverTimer);
  });

  /* The shadow under the brand appears once the menu is scrolled. */
  const inner = document.querySelector('.menu-inner');
  const shadow = document.querySelector('.menu-inner-shadow');
  if (inner && shadow) {
    inner.addEventListener('ps-scroll-y', function () {
      const thumb = inner.querySelector('.ps__thumb-y');
      shadow.style.display = thumb && thumb.offsetTop ? 'block' : 'none';
    });
  }
}

document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(function (element) {
  new bootstrap.Tooltip(element);
});

Helpers.setAutoUpdate(true);

/* A small screen gets the overlay menu, which has no collapsed state. */
if (!Helpers.isSmallScreen()) {
  Helpers.setCollapsed(true, false);
}
