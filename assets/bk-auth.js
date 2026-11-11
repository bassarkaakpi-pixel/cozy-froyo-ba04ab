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

    getToken: function () {
      try {
        return localStorage.getItem("bk_token") || "";
      } catch (e) {
        return "";
      }
    },

    setToken: function (token) {
      try {
        if (token) {
          localStorage.setItem("bk_token", token);
        } else {
          localStorage.removeItem("bk_token");
        }
      } catch (e) {}
    },

    fetchWithAuth: function (url, options) {
      options = options || {};
      options.headers = options.headers || {};
      var token = BKAuth.getToken();
      if (token) {
        options.headers["Authorization"] = "Bearer " + token;
      }
      options.credentials = "same-origin";
      return fetch(url, options);
    },

    checkSession: function () {
      return BKAuth.fetchWithAuth("/api/auth/me")
        .then(function (res) {
          if (res.ok) {
            return res.json().then(function (data) {
              BKAuth.setUser(data.subscriber);
              return data.subscriber;
            });
          } else {
            BKAuth.setUser(null);
            BKAuth.setToken(null);
            return null;
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
          BKAuth.setToken(data.token);
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
          BKAuth.setToken(data.token);
          return data.subscriber;
        });
      });
    },

    logout: function () {
      return fetch("/api/auth/logout", { method: "POST" })
        .catch(function () {})
        .then(function () {
          BKAuth.setUser(null);
          BKAuth.setToken(null);
          window.location.href = "connexion.html";
        });
    },

    initNav: function () {
      var nav = document.querySelector("header nav");
      if (!nav) return;

      // Add 'Vendeurs' and 'Espace Abonnés' if missing
      var user = BKAuth.getUser();

      var existingVendeurs = nav.querySelector('a[href="vendeurs.html"]');
      if (!existingVendeurs) {
        var vLink = document.createElement("a");
        vLink.href = "vendeurs.html";
        vLink.textContent = "Annuaire";
        vLink.className = "nav-vendeurs";
        var mktLink = nav.querySelector('a[href="marketplace.html"]');
        if (mktLink && mktLink.nextSibling) {
          nav.insertBefore(vLink, mktLink.nextSibling);
        } else {
          nav.appendChild(vLink);
        }
      }

      var existingAuth = nav.querySelector(".nav-auth-link");
      if (!existingAuth) {
        var aLink = document.createElement("a");
        aLink.className = "nav-auth-link";
        nav.appendChild(aLink);
        existingAuth = aLink;
      }

      if (user) {
        existingAuth.href = "espace-abonne.html";
        existingAuth.textContent = "Mon Espace";
        existingAuth.style.color = "var(--gold)";
        existingAuth.style.fontWeight = "600";
      } else {
        existingAuth.href = "connexion.html";
        existingAuth.textContent = "Connexion";
        existingAuth.style.fontWeight = "600";
      }
    },
  };

  window.BKAuth = BKAuth;

  document.addEventListener("DOMContentLoaded", function () {
    BKAuth.initNav();
    BKAuth.checkSession().then(function () {
      BKAuth.initNav();
    });
  });
})(window);
