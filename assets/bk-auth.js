/**
 * Bassar Kàakpi - Authentication & Subscriber Space Helper
 */
(function (window) {
  var BKAuth = {
    getUser: function () {
      try {
        var u = localStorage.getItem("bk_user");
        return u ? JSON.parse(u) : null;
      } catch (e) {
        return null;
      }
    },

    setUser: function (user) {
      try {
        if (user) {
          localStorage.setItem("bk_user", JSON.stringify(user));
        } else {
          localStorage.removeItem("bk_user");
        }
      } catch (e) {}
      document.dispatchEvent(new CustomEvent("bk_auth_change", { detail: user }));
    },

    // Sessions now rely solely on the httpOnly, Secure, SameSite=Lax cookie set
    // by the server; the token is never readable by JavaScript. These helpers
    // remain for compatibility and only clean up the legacy localStorage copy.
    getToken: function () {
      return "";
    },

    setToken: function () {
      try {
        localStorage.removeItem("bk_token");
      } catch (e) {}
    },

    fetchWithAuth: function (url, options) {
      options = options || {};
      options.headers = options.headers || {};
      options.credentials = "same-origin";
      return fetch(url, options);
    },

    // Called when the server reports that the session is no longer valid
    // (expired, or signed with a retired key after a JWT_SECRET rotation).
    sessionExpired: function () {
      var hadSession = !!BKAuth.getUser();
      BKAuth.setUser(null);
      BKAuth.setToken(null);
      return hadSession;
    },

    checkSession: function () {
      return BKAuth.fetchWithAuth("/api/auth/me")
        .then(function (res) {
          if (res.ok) {
            return res.json().then(function (data) {
              BKAuth.setUser(data.subscriber);
              return data.subscriber;
            });
          } else if (res.status === 401 || res.status === 403) {
            BKAuth.lastSessionWasExpired = BKAuth.sessionExpired();
            return null;
          } else {
            return BKAuth.getUser();
          }
        })
        .catch(function () {
          return BKAuth.getUser();
        });
    },

    login: function (email, password) {
      return fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email, password: password }),
      }).then(function (res) {
        return res.json().then(function (data) {
          if (!res.ok) throw new Error(data.error || "Erreur de connexion");
          BKAuth.setUser(data.subscriber);
          return data.subscriber;
        });
      });
    },

    register: function (formData) {
      return fetch("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formData),
      }).then(function (res) {
        return res.json().then(function (data) {
          if (!res.ok) throw new Error(data.error || "Erreur lors de l'inscription");
          BKAuth.setUser(data.subscriber);
          return data.subscriber;
        });
      });
    },

    logout: function () {
      return fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" })
        .catch(function () {})
        .then(function () {
          BKAuth.setUser(null);
          BKAuth.setToken(null);
          window.location.href = "connexion.html";
        });
    },

    // Navigation rendering (labels, "Connexion" / "Mon Espace" link) is owned
    // exclusively by assets/nav.js. This wrapper is kept for compatibility
    // with pages that still call BKAuth.initNav().
    initNav: function () {
      if (typeof window.bkRefreshNav === "function") window.bkRefreshNav();
    },
  };

  window.BKAuth = BKAuth;

  // Transition: remove the session token that older versions stored in localStorage.
  try { localStorage.removeItem("bk_token"); } catch (e) {}

  document.addEventListener("DOMContentLoaded", function () {
    BKAuth.initNav();
    BKAuth.checkSession().then(function () {
      BKAuth.initNav();
    });
  });
})(window);
