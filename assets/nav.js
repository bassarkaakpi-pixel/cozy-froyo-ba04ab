/**
 * Bassar Kàakpi — Navigation Unifiée & Multilingue (FR / EN / DE)
 * Conforme aux directives d'architecture et aux règles strictes de traduction.
 */
(function () {
  "use strict";

  var NAV_I18N = {
    fr: {
      btchamb: "B'Tchamb",
      btchamb_histoire: "Histoire et patrimoine Bassar",
      btchamb_cultures: "Cultures & Traditions du Monde",
      btchamb_galas: "Galas & Dîners",
      marketplace: "Marketplace",
      marketplace_annonces: "Annonces et échanges",
      marketplace_annuaire: "Annuaire",
      shop: "Boutique",
      connexion: "Connexion",
      mon_espace: "Mon Espace",
      toggle_menu: "Menu"
    },
    en: {
      btchamb: "B'Tchamb",
      btchamb_histoire: "Bassar History & Heritage",
      btchamb_cultures: "World Cultures & Traditions",
      btchamb_galas: "Galas & Dinners",
      marketplace: "Marketplace",
      marketplace_annonces: "Listings & Exchanges",
      marketplace_annuaire: "Directory",
      shop: "Shop",
      connexion: "Login",
      mon_espace: "My Account",
      toggle_menu: "Menu"
    },
    de: {
      btchamb: "B'Tchamb",
      btchamb_histoire: "Geschichte & Erbe der Bassar",
      btchamb_cultures: "Kulturen & Traditionen der Welt",
      btchamb_galas: "Galas & Dinners",
      marketplace: "Marktplatz",
      marketplace_annonces: "Anzeigen & Austausch",
      marketplace_annuaire: "Verzeichnis",
      shop: "Shop",
      connexion: "Anmelden",
      mon_espace: "Mein Bereich",
      toggle_menu: "Menü"
    }
  };

  /*
   * Language registry — single source of truth for the navigation.
   * Only languages flagged `enabled` are offered and accepted. To add one of
   * the seven planned languages: add its dictionary to NAV_I18N, add an entry
   * here with enabled:true, and add a <button data-l="xx" class="bk-lang-btn">
   * to the header language switch. Nothing else in this file needs to change.
   */
  var LANG_REGISTRY = [
    { code: "fr", label: "FR", name: "Français", enabled: true },
    { code: "en", label: "EN", name: "English", enabled: true },
    { code: "de", label: "DE", name: "Deutsch", enabled: true }
  ];
  var DEFAULT_LANG = "fr";

  var SUPPORTED_LANGS = LANG_REGISTRY.filter(function (l) {
    return l.enabled && NAV_I18N[l.code];
  }).map(function (l) { return l.code; });

  function isSupported(code) {
    return SUPPORTED_LANGS.indexOf(code) > -1;
  }

  function getSavedLang() {
    var s = null;
    try {
      s = localStorage.getItem("lang");
    } catch (e) {}
    if (s && isSupported(s)) return s;

    var navLangs = navigator.languages && navigator.languages.length ? navigator.languages : [navigator.language || ""];
    for (var i = 0; i < navLangs.length; i++) {
      var code = String(navLangs[i]).slice(0, 2).toLowerCase();
      if (isSupported(code)) return code;
    }
    return DEFAULT_LANG;
  }

  // Resolution order shared with the page scripts: explicit saved choice,
  // then the language the page itself applied to <html lang>, then browser.
  function getCurrentLang() {
    var s = null;
    try { s = localStorage.getItem("lang"); } catch (e) {}
    if (s && isSupported(s)) return s;
    var docLang = String(document.documentElement.lang || "").slice(0, 2).toLowerCase();
    if (isSupported(docLang)) return docLang;
    return getSavedLang();
  }

  // The session cookie is httpOnly (invisible to JS); the client-side session
  // marker kept by bk-auth.js is used for display purposes only.
  function isLoggedIn() {
    try {
      if (window.BKAuth && typeof window.BKAuth.getUser === "function") {
        return !!window.BKAuth.getUser();
      }
      return !!localStorage.getItem("bk_user");
    } catch (e) {
      return false;
    }
  }

  function applyNavTranslations(lang) {
    if (!isSupported(lang)) lang = DEFAULT_LANG;
    var dict = NAV_I18N[lang];

    // Clean up any legacy injected navigation elements
    var rogue = document.querySelectorAll(".nav-culture, .nav-vendeurs, .nav-events, .nav-auth-link");
    rogue.forEach(function (el) { el.remove(); });

    // Check if user is logged in
    var loggedIn = isLoggedIn();

    // Translate all nav elements with data-nav-i18n
    var translatables = document.querySelectorAll("[data-nav-i18n]");
    translatables.forEach(function (el) {
      var key = el.getAttribute("data-nav-i18n");
      if (key === "connexion" && loggedIn) {
        el.textContent = dict.mon_espace || "Mon Espace";
      } else if (dict[key]) {
        el.textContent = dict[key];
      }
    });

    // Update connexion link destination if logged in
    var connLinks = document.querySelectorAll(".bk-link-connexion");
    connLinks.forEach(function (link) {
      link.setAttribute("href", loggedIn ? "/espace-abonne.html" : "/connexion.html");
      link.classList.toggle("is-account", loggedIn);
    });

    // Update active state on language buttons
    var allLangBtns = document.querySelectorAll(".bk-lang-btn, .lang button");
    allLangBtns.forEach(function (btn) {
      var bl = btn.getAttribute("data-l");
      if (!isSupported(bl)) { btn.hidden = true; return; }
      var isActive = bl === lang;
      btn.setAttribute("aria-pressed", String(isActive));
      if (isActive) {
        btn.classList.add("is-active");
      } else {
        btn.classList.remove("is-active");
      }
    });

    // Synchronize any legacy .ml elements to guarantee no dual language display
    var mlNodes = document.querySelectorAll(".ml");
    mlNodes.forEach(function (e) {
      var dl = e.getAttribute("data-l");
      e.classList.toggle("on", dl === lang);
    });

    document.documentElement.lang = lang;
    window.curLang = lang;
  }

  function setLanguage(lang, save) {
    if (!isSupported(lang)) return;
    if (save) {
      try {
        localStorage.setItem("lang", lang);
      } catch (e) {}
    }
    applyNavTranslations(lang);
    document.dispatchEvent(new CustomEvent("langchange", { detail: { lang: lang } }));
  }

  function highlightActivePage() {
    var currentPath = window.location.pathname.split("/").pop() || "index.html";
    if (currentPath === "") currentPath = "index.html";

    var allLinks = document.querySelectorAll(".bk-nav-link, .bk-dropdown-link");
    allLinks.forEach(function (link) {
      var href = link.getAttribute("href") || "";
      var linkPath = href.split("/").pop();
      if (linkPath === currentPath) {
        link.classList.add("is-active");
        var parentDropdown = link.closest(".bk-dropdown");
        if (parentDropdown) {
          parentDropdown.classList.add("is-active");
        }
      } else {
        link.classList.remove("is-active");
      }
    });
  }

  // Keep the mobile drawer aligned with the real header height.
  function syncHeaderHeight() {
    var h = document.querySelector(".bk-header");
    if (h) document.documentElement.style.setProperty("--bk-header-h", h.offsetHeight + "px");
  }

  function initNavEvents() {
    var header = document.querySelector(".bk-header");
    syncHeaderHeight();
    window.addEventListener("resize", syncHeaderHeight);
    var toggleBtn = document.getElementById("bkNavToggle");
    var navMenu = document.getElementById("bkNavMenu");

    if (toggleBtn && header) {
      toggleBtn.addEventListener("click", function (e) {
        e.stopPropagation();
        var isOpen = header.classList.toggle("menu-open");
        toggleBtn.setAttribute("aria-expanded", String(isOpen));
        if (isOpen) {
          document.body.style.overflow = "hidden";
        } else {
          document.body.style.overflow = "";
        }
      });
    }

    // Dropdown toggles (click / touch for mobile and accessible desktop)
    var dropdowns = document.querySelectorAll(".bk-dropdown");
    dropdowns.forEach(function (drop) {
      var btn = drop.querySelector(".bk-dropdown-btn");
      if (!btn) return;

      btn.addEventListener("click", function (e) {
        e.preventDefault();
        e.stopPropagation();
        var isCurrentlyOpen = drop.classList.contains("is-open");

        // Close other dropdowns
        dropdowns.forEach(function (d) {
          if (d !== drop) {
            d.classList.remove("is-open");
            var b = d.querySelector(".bk-dropdown-btn");
            if (b) b.setAttribute("aria-expanded", "false");
          }
        });

        if (isCurrentlyOpen) {
          drop.classList.remove("is-open");
          btn.setAttribute("aria-expanded", "false");
        } else {
          drop.classList.add("is-open");
          btn.setAttribute("aria-expanded", "true");
        }
      });
    });

    // Language switch buttons. The header switch also carries the legacy
    // "lang" class, so each page's own translation script is bound to these
    // buttons and runs first; this document-level listener then synchronises
    // <html lang>, storage, the menu and broadcasts "langchange".
    document.addEventListener("click", function (e) {
      var btn = e.target.closest(".bk-lang-btn, .lang button");
      if (btn && btn.getAttribute("data-l")) {
        e.preventDefault();
        var selectedLang = btn.getAttribute("data-l");
        setLanguage(selectedLang, true);
      }
    });

    // Close dropdowns when clicking outside
    document.addEventListener("click", function (e) {
      if (!e.target.closest(".bk-dropdown")) {
        dropdowns.forEach(function (drop) {
          drop.classList.remove("is-open");
          var btn = drop.querySelector(".bk-dropdown-btn");
          if (btn) btn.setAttribute("aria-expanded", "false");
        });
      }
    });

    // Keyboard accessibility: Escape key closes menus
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") {
        dropdowns.forEach(function (drop) {
          drop.classList.remove("is-open");
          var btn = drop.querySelector(".bk-dropdown-btn");
          if (btn) btn.setAttribute("aria-expanded", "false");
        });
        if (header && header.classList.contains("menu-open")) {
          header.classList.remove("menu-open");
          if (toggleBtn) toggleBtn.setAttribute("aria-expanded", "false");
          document.body.style.overflow = "";
        }
      }
    });
  }

  // Initialize once DOM is ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      initNavEvents();
      applyNavTranslations(getCurrentLang());
      highlightActivePage();
    });
  } else {
    initNavEvents();
    applyNavTranslations(getCurrentLang());
    highlightActivePage();
  }

  // Listen to langchange from any source to keep nav in sync
  document.addEventListener("langchange", function (e) {
    var lang = (e && e.detail && e.detail.lang) || getCurrentLang();
    applyNavTranslations(lang);
  });

  // Refresh "Connexion" / "Mon Espace" when the session changes.
  document.addEventListener("bk_auth_change", function () {
    applyNavTranslations(getCurrentLang());
  });

  // Expose global helper if needed
  window.bkSetLanguage = setLanguage;
  window.BK_LANGS = SUPPORTED_LANGS.slice();
  window.bkRefreshNav = function () {
    applyNavTranslations(getCurrentLang());
  };
})();
