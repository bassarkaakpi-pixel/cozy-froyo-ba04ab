import crypto from "crypto";
import { Hono } from "hono";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { eq, desc, and, sql, inArray, lt } from "drizzle-orm";
import { db } from "../../db/index.js";
import { subscribers, listings, culturalPublications, eventReservations, paymentEvents } from "../../db/schema.js";

const app = new Hono().basePath("/api");

app.use("*", async (c, next) => {
  console.log("Hono req:", c.req.method, c.req.path);
  await next();
});

// CSRF defence in depth (in addition to SameSite=Lax on the session cookie):
// state-changing requests sent by a browser must come from this same site.
// Provider webhooks are server-to-server and authenticated by signature.
app.use("*", async (c, next) => {
  const method = c.req.method.toUpperCase();
  if (method === "GET" || method === "HEAD" || method === "OPTIONS" || c.req.path.startsWith("/api/payments/")) {
    return next();
  }
  const allowedHosts = new Set<string>();
  try { allowedHosts.add(new URL(c.req.url).host); } catch {}
  const hostHeader = c.req.header("host");
  if (hostHeader) allowedHosts.add(hostHeader);

  const origin = c.req.header("origin");
  if (origin) {
    let originHost = "";
    try { originHost = new URL(origin).host; } catch {}
    if (!originHost || !allowedHosts.has(originHost)) {
      return c.json({ error: "Origine de la requête refusée." }, 403);
    }
  } else {
    const site = c.req.header("sec-fetch-site");
    if (site && site !== "same-origin" && site !== "none") {
      return c.json({ error: "Origine de la requête refusée." }, 403);
    }
  }
  return next();
});

// Helper: Safely retrieve JWT secret from environment only (never hardcode fallback)
function getJwtSecret(): string | null {
  const secret = process.env.JWT_SECRET;
  if (!secret || typeof secret !== "string" || secret.trim().length === 0) {
    return null;
  }
  return secret.trim();
}

const COOKIE_NAME = "bk_subscriber_token";
const SESSION_MAX_AGE_S = 30 * 24 * 60 * 60;
const JWT_ISSUER = "bassarkaakpi";
const JWT_AUDIENCE = "bk-subscriber";

// Secure is always set, except under `netlify dev` (plain http://localhost).
function sessionCookieOptions() {
  return {
    httpOnly: true,
    secure: process.env.NETLIFY_DEV !== "true",
    sameSite: "Lax" as const,
    path: "/",
    maxAge: SESSION_MAX_AGE_S,
  };
}

function issueSession(c, sub: { id: number; email: string }, jwtSecret: string) {
  const token = jwt.sign({ id: sub.id, email: sub.email }, jwtSecret, {
    algorithm: "HS256",
    expiresIn: SESSION_MAX_AGE_S,
    issuer: JWT_ISSUER,
    audience: JWT_AUDIENCE,
    subject: String(sub.id),
  });
  setCookie(c, COOKIE_NAME, token, sessionCookieOptions());
}

function clearSession(c) {
  deleteCookie(c, COOKIE_NAME, { path: "/", secure: process.env.NETLIFY_DEV !== "true" });
}

// The client IP is taken ONLY from x-nf-client-connection-ip, which Netlify's
// edge sets from the TCP connection and overwrites if a client sends it.
// x-forwarded-for / client-ip are client-controllable and never used.
function getClientIp(c): string {
  return (c.req.header("x-nf-client-connection-ip") || "unknown").trim();
}

// Validation constants and whitelist helpers
const ALLOWED_MEMBER_CATEGORIES = new Set([
  "trade",
  "craft",
  "culture",
  "textile",
  "realestate",
  "land",
  "service",
  "vehicle",
  "other",
]);

const ALLOWED_CONTINENTS = new Set([
  "Afrique",
  "Europe",
  "Amériques",
  "Asie",
  "Océanie",
]);

const ALLOWED_CULTURAL_CATEGORIES = new Set([
  "tradition",
  "textile_attire",
  "dance_music",
  "rites_festivals",
  "gastronomie",
  "history",
  "art_craft",
]);

function isValidHttpsUrl(url: unknown): boolean {
  if (!url || typeof url !== "string") return false;
  const trimmed = url.trim();
  if (trimmed === "" || /[<>"'\s]/.test(trimmed)) return false;
  try {
    const parsed = new URL(trimmed);
    return parsed.protocol === "https:";
  } catch {
    return false;
  }
}

function sanitizeText(val: unknown, maxLen = 1000): string {
  if (val == null) return "";
  const s = String(val).trim();
  return s.slice(0, maxLen);
}

function sanitizeEmoji(val: unknown, fallback = "🌍"): string {
  if (!val || typeof val !== "string") return fallback;
  const s = val.trim();
  if (/<[^>]*>|[&"'<>]/.test(s)) return fallback;
  return s.slice(0, 10);
}

// Helper: Authenticate subscriber from cookie or Bearer token
async function getAuthSubscriber(c) {
  try {
    const jwtSecret = getJwtSecret();
    if (!jwtSecret) {
      // Refuse authentication when JWT_SECRET is absent
      return null;
    }

    // Sessions are carried only by the httpOnly cookie. Bearer tokens (formerly
    // kept in localStorage, readable by any injected script) are no longer accepted.
    const token = getCookie(c, COOKIE_NAME);
    if (!token) return null;

    const decoded = jwt.verify(token, jwtSecret, {
      algorithms: ["HS256"],
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    }) as { id: number; email: string };
    if (!decoded || !decoded.id) return null;

    const [subscriber] = await db
      .select()
      .from(subscribers)
      .where(eq(subscribers.id, decoded.id))
      .limit(1);

    if (!subscriber || subscriber.status === "suspended") return null;

    const { passwordHash, ...safeSubscriber } = subscriber;
    return safeSubscriber;
  } catch (err) {
    return null;
  }
}

// Helpers: Reference IDs
function generateMemberRef() {
  const now = new Date();
  const yr = String(now.getFullYear()).slice(-2);
  const mo = String(now.getMonth() + 1).padStart(2, "0");
  const rand = Math.floor(1000 + Math.random() * 9000);
  return `MEM-${yr}${mo}-${rand}`;
}

function generateListingRef() {
  const now = new Date();
  const yr = String(now.getFullYear()).slice(-2);
  const mo = String(now.getMonth() + 1).padStart(2, "0");
  const rand = Math.floor(1000 + Math.random() * 9000);
  return `ANN-${yr}${mo}-${rand}`;
}

// ==========================================
// AUTHENTICATION
// ==========================================

// Register
app.post("/auth/register", async (c) => {
  try {
    const jwtSecret = getJwtSecret();
    if (!jwtSecret) {
      return c.json(
        { error: "Configuration de sécurité serveur incomplète (JWT_SECRET absent). Inscription temporairement indisponible." },
        503
      );
    }

    if (!(await checkRateLimit("register", getClientIp(c), 5, 60 * 60 * 1000))) {
      return c.json({ error: "Trop de tentatives. Veuillez réessayer plus tard." }, 429);
    }

    const body = await c.req.json();
    const {
      fullName,
      businessName,
      email,
      password,
      phone,
      city,
      country = "Togo",
      category = "trade",
      plan = "free",
      bio = "",
      website = "",
    } = body;

    if (!fullName || !email || !password || !phone || !city) {
      return c.json({ error: "Tous les champs obligatoires doivent être remplis." }, 400);
    }

    if (typeof password !== "string" || password.length < 8 || password.length > 200) {
      return c.json({ error: "Le mot de passe doit contenir au moins 8 caractères." }, 400);
    }

    const cleanEmail = String(email).trim().toLowerCase();
    const cleanCategory = ALLOWED_MEMBER_CATEGORIES.has(String(category).trim()) ? String(category).trim() : "trade";
    const cleanWebsite = isValidHttpsUrl(website) ? String(website).trim() : "";
    const cleanPhone = String(phone).replace(/[^\d+]/g, "").slice(0, 20);

    const [existing] = await db
      .select()
      .from(subscribers)
      .where(eq(subscribers.email, cleanEmail))
      .limit(1);

    if (existing) {
      return c.json({ error: "Un compte existe déjà avec cette adresse e-mail." }, 409);
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const memberRef = generateMemberRef();

    const [newSub] = await db
      .insert(subscribers)
      .values({
        email: cleanEmail,
        passwordHash,
        fullName: sanitizeText(fullName, 100),
        businessName: businessName ? sanitizeText(businessName, 100) : "",
        phone: cleanPhone,
        city: sanitizeText(city, 80),
        country: sanitizeText(country, 80),
        category: cleanCategory,
        plan: ["free", "seller", "premium"].includes(plan) ? plan : "free",
        status: "active",
        isVerified: plan === "premium",
        bio: bio ? sanitizeText(bio, 500) : "",
        website: cleanWebsite,
        memberRef,
      })
      .returning();

    issueSession(c, newSub, jwtSecret);

    const { passwordHash: _, ...safeUser } = newSub;
    return c.json({ success: true, subscriber: safeUser }, 201);
  } catch (error) {
    console.error("Register error:", error);
    return c.json({ error: "Erreur serveur lors de l'inscription." }, 500);
  }
});

// Login
app.post("/auth/login", async (c) => {
  try {
    const jwtSecret = getJwtSecret();
    if (!jwtSecret) {
      return c.json(
        { error: "Configuration de sécurité serveur incomplète (JWT_SECRET absent). Connexion temporairement indisponible." },
        503
      );
    }

    const { email, password } = await c.req.json();
    if (!email || !password) {
      return c.json({ error: "E-mail et mot de passe requis." }, 400);
    }

    const cleanEmail = String(email).trim().toLowerCase();

    // Brute-force protection: per IP and per account.
    const ipOk = await checkRateLimit("login-ip", getClientIp(c), 20, 15 * 60 * 1000);
    const accountOk = await checkRateLimit(
      "login-account",
      crypto.createHash("sha256").update(cleanEmail).digest("hex").slice(0, 32),
      10,
      15 * 60 * 1000
    );
    if (!ipOk || !accountOk) {
      return c.json({ error: "Trop de tentatives de connexion. Veuillez réessayer dans quelques minutes." }, 429);
    }

    const [subscriber] = await db
      .select()
      .from(subscribers)
      .where(eq(subscribers.email, cleanEmail))
      .limit(1);

    if (!subscriber) {
      return c.json({ error: "Identifiants incorrects." }, 401);
    }

    const valid = await bcrypt.compare(password, subscriber.passwordHash);
    if (!valid) {
      return c.json({ error: "Identifiants incorrects." }, 401);
    }

    if (subscriber.status === "suspended") {
      return c.json({ error: "Votre compte a été suspendu." }, 403);
    }

    issueSession(c, subscriber, jwtSecret);

    const { passwordHash: _, ...safeUser } = subscriber;
    return c.json({ success: true, subscriber: safeUser });
  } catch (error) {
    console.error("Login error:", error);
    return c.json({ error: "Erreur serveur lors de la connexion." }, 500);
  }
});

// Current user profile
app.get("/auth/me", async (c) => {
  const subscriber = await getAuthSubscriber(c);
  if (!subscriber) {
    // Remove an invalid or outdated session cookie (e.g. signed with a retired key)
    if (getCookie(c, COOKIE_NAME)) clearSession(c);
    return c.json({ error: "Non connecté", reason: getJwtSecret() ? "session_invalid" : "auth_unavailable" }, 401);
  }
  return c.json({ subscriber });
});

// Logout
app.post("/auth/logout", (c) => {
  clearSession(c);
  return c.json({ success: true });
});

// Update profile
app.put("/auth/profile", async (c) => {
  const subscriber = await getAuthSubscriber(c);
  if (!subscriber) return c.json({ error: "Non connecté" }, 401);

  try {
    const body = await c.req.json();
    const { fullName, businessName, phone, city, country, category, bio, website, logoUrl } = body;

    const cleanFullName = fullName !== undefined ? sanitizeText(fullName, 100) : subscriber.fullName;
    const cleanBusiness = businessName !== undefined ? sanitizeText(businessName, 100) : subscriber.businessName;
    const cleanPhone = phone !== undefined ? String(phone).replace(/[^\d+]/g, "").slice(0, 20) : subscriber.phone;
    const cleanCity = city !== undefined ? sanitizeText(city, 80) : subscriber.city;
    const cleanCountry = country !== undefined ? sanitizeText(country, 80) : subscriber.country;
    const cleanCategory = category !== undefined && ALLOWED_MEMBER_CATEGORIES.has(String(category).trim())
      ? String(category).trim()
      : subscriber.category;
    const cleanBio = bio !== undefined ? sanitizeText(bio, 500) : subscriber.bio;
    const cleanWebsite = website !== undefined ? (isValidHttpsUrl(website) ? String(website).trim() : "") : subscriber.website;
    const cleanLogoUrl = logoUrl !== undefined ? (isValidHttpsUrl(logoUrl) ? String(logoUrl).trim() : "") : subscriber.logoUrl;

    const [updated] = await db
      .update(subscribers)
      .set({
        fullName: cleanFullName,
        businessName: cleanBusiness,
        phone: cleanPhone,
        city: cleanCity,
        country: cleanCountry,
        category: cleanCategory,
        bio: cleanBio,
        website: cleanWebsite,
        logoUrl: cleanLogoUrl,
        updatedAt: new Date(),
      })
      .where(eq(subscribers.id, subscriber.id))
      .returning();

    const { passwordHash: _, ...safeUser } = updated;
    return c.json({ success: true, subscriber: safeUser });
  } catch (error) {
    console.error("Update profile error:", error);
    return c.json({ error: "Erreur lors de la mise à jour du profil." }, 500);
  }
});

// ==========================================
// SUBSCRIBER LISTINGS MANAGEMENT
// ==========================================

// Get my listings
app.get("/my/listings", async (c) => {
  const subscriber = await getAuthSubscriber(c);
  if (!subscriber) return c.json({ error: "Non connecté" }, 401);

  try {
    const myListings = await db
      .select()
      .from(listings)
      .where(eq(listings.subscriberId, subscriber.id))
      .orderBy(desc(listings.createdAt));

    return c.json({ listings: myListings });
  } catch (error) {
    console.error("Fetch my listings error:", error);
    return c.json({ error: "Erreur lors de la récupération des annonces." }, 500);
  }
});

// Create listing
app.post("/my/listings", async (c) => {
  const subscriber = await getAuthSubscriber(c);
  if (!subscriber) return c.json({ error: "Non connecté" }, 401);

  try {
    const body = await c.req.json();
    const { category, title, city, price, currency = "XOF", description, imageUrl = "" } = body;

    if (!category || !title || !description) {
      return c.json({ error: "Catégorie, titre et description sont obligatoires." }, 400);
    }

    if (subscriber.plan === "free") {
      const existingCount = await db
        .select({ count: sql`count(*)` })
        .from(listings)
        .where(eq(listings.subscriberId, subscriber.id));
      const count = Number(existingCount[0]?.count || 0);
      if (count >= 5) {
        return c.json({
          error:
            "La formule Gratuite permet jusqu'à 5 annonces. Passez à la formule Vendeur (jusqu'à 20 annonces) ou Premium pour publier davantage.",
        }, 403);
      }
    } else if (subscriber.plan === "seller") {
      const existingCount = await db
        .select({ count: sql`count(*)` })
        .from(listings)
        .where(eq(listings.subscriberId, subscriber.id));
      const count = Number(existingCount[0]?.count || 0);
      if (count >= 20) {
        return c.json({
          error: "La formule Vendeur permet jusqu'à 20 annonces par mois. Passez à la formule Premium pour des annonces illimitées.",
        }, 403);
      }
    }

    const safeCategory = ALLOWED_MEMBER_CATEGORIES.has(String(category).trim())
      ? String(category).trim()
      : "trade";
    const rawImg = imageUrl ? String(imageUrl).trim() : "";
    const safeImg = (isValidHttpsUrl(rawImg) || /^assets\/[\w\-\/.]+\.(?:jpe?g|png|webp|svg)$/i.test(rawImg)) ? rawImg : "";

    const ref = generateListingRef();
    const parsedPrice = price !== null && price !== "" && !isNaN(Number(price)) ? Math.round(Number(price)) : null;

    const [newListing] = await db
      .insert(listings)
      .values({
        subscriberId: subscriber.id,
        ref,
        category: safeCategory,
        title: sanitizeText(title, 120),
        city: city ? sanitizeText(city, 80) : subscriber.city,
        price: parsedPrice,
        currency: currency === "EUR" ? "EUR" : "XOF",
        description: sanitizeText(description, 3000),
        imageUrl: safeImg,
        status: "active",
        isFeatured: subscriber.plan === "premium",
      })
      .returning();

    return c.json({ success: true, listing: newListing }, 201);
  } catch (error) {
    console.error("Create listing error:", error);
    return c.json({ error: "Erreur lors de la publication de l'annonce." }, 500);
  }
});

// Update listing
app.put("/my/listings/:id", async (c) => {
  const subscriber = await getAuthSubscriber(c);
  if (!subscriber) return c.json({ error: "Non connecté" }, 401);

  try {
    const listingId = parseInt(c.req.param("id"), 10);
    const body = await c.req.json();
    const { category, title, city, price, currency, description, imageUrl, status } = body;

    const [existing] = await db
      .select()
      .from(listings)
      .where(and(eq(listings.id, listingId), eq(listings.subscriberId, subscriber.id)))
      .limit(1);

    if (!existing) {
      return c.json({ error: "Annonce introuvable ou non autorisée." }, 404);
    }

    const safeCategory = category && ALLOWED_MEMBER_CATEGORIES.has(String(category).trim())
      ? String(category).trim()
      : existing.category;

    let safeImg = existing.imageUrl;
    if (imageUrl !== undefined) {
      const rawImg = String(imageUrl).trim();
      safeImg = (isValidHttpsUrl(rawImg) || /^assets\/[\w\-\/.]+\.(?:jpe?g|png|webp|svg)$/i.test(rawImg)) ? rawImg : "";
    }

    const parsedPrice = price !== null && price !== "" && !isNaN(Number(price)) ? Math.round(Number(price)) : null;

    const [updated] = await db
      .update(listings)
      .set({
        category: safeCategory,
        title: title ? sanitizeText(title, 120) : existing.title,
        city: city ? sanitizeText(city, 80) : existing.city,
        price: parsedPrice !== undefined ? parsedPrice : existing.price,
        currency: currency === "EUR" ? "EUR" : (currency === "XOF" ? "XOF" : existing.currency),
        description: description ? sanitizeText(description, 3000) : existing.description,
        imageUrl: safeImg,
        status: status === "inactive" ? "inactive" : (status === "active" ? "active" : existing.status),
        updatedAt: new Date(),
      })
      .where(eq(listings.id, listingId))
      .returning();

    return c.json({ success: true, listing: updated });
  } catch (error) {
    console.error("Update listing error:", error);
    return c.json({ error: "Erreur lors de la mise à jour." }, 500);
  }
});

// Delete listing
app.delete("/my/listings/:id", async (c) => {
  const subscriber = await getAuthSubscriber(c);
  if (!subscriber) return c.json({ error: "Non connecté" }, 401);

  try {
    const listingId = parseInt(c.req.param("id"), 10);

    const [deleted] = await db
      .delete(listings)
      .where(and(eq(listings.id, listingId), eq(listings.subscriberId, subscriber.id)))
      .returning();

    if (!deleted) {
      return c.json({ error: "Annonce introuvable ou déjà supprimée." }, 404);
    }

    return c.json({ success: true, message: "Annonce supprimée." });
  } catch (error) {
    console.error("Delete listing error:", error);
    return c.json({ error: "Erreur lors de la suppression." }, 500);
  }
});

// ==========================================
// PUBLIC SPACES
// ==========================================

// Public directory of members
app.get("/members", async (c) => {
  try {
    const category = c.req.query("category");
    const city = c.req.query("city");
    const search = c.req.query("search");

    const membersList = await db
      .select({
        id: subscribers.id,
        fullName: subscribers.fullName,
        businessName: subscribers.businessName,
        city: subscribers.city,
        country: subscribers.country,
        category: subscribers.category,
        plan: subscribers.plan,
        isVerified: subscribers.isVerified,
        bio: subscribers.bio,
        website: subscribers.website,
        logoUrl: subscribers.logoUrl,
        memberRef: subscribers.memberRef,
        createdAt: subscribers.createdAt,
      })
      .from(subscribers)
      .where(eq(subscribers.status, "active"))
      .orderBy(desc(subscribers.isVerified), desc(subscribers.createdAt));

    let filtered = membersList;
    if (category && category !== "all") {
      filtered = filtered.filter((m) => m.category === category);
    }
    if (city) {
      filtered = filtered.filter((m) => m.city.toLowerCase() === String(city).toLowerCase());
    }
    if (search) {
      const s = String(search).toLowerCase();
      filtered = filtered.filter(
        (m) =>
          m.fullName.toLowerCase().includes(s) ||
          (m.businessName && m.businessName.toLowerCase().includes(s)) ||
          m.city.toLowerCase().includes(s) ||
          (m.bio && m.bio.toLowerCase().includes(s))
      );
    }

    const counts = await db
      .select({
        subscriberId: listings.subscriberId,
        count: sql`count(*)`,
      })
      .from(listings)
      .where(eq(listings.status, "active"))
      .groupBy(listings.subscriberId);

    const countMap = new Map();
    counts.forEach((row) => countMap.set(row.subscriberId, Number(row.count)));

    const result = filtered.map((m) => ({
      ...m,
      listingsCount: countMap.get(m.id) || 0,
    }));

    return c.json({ members: result });
  } catch (error) {
    console.error("Public members error:", error);
    return c.json({ error: "Erreur lors du chargement des membres." }, 500);
  }
});

// Single public member profile + their listings
app.get("/members/:idOrRef", async (c) => {
  try {
    const param = c.req.param("idOrRef");
    const isId = /^\d+$/.test(param);

    const condition = isId
      ? eq(subscribers.id, parseInt(param, 10))
      : eq(subscribers.memberRef, param);

    const [member] = await db
      .select({
        id: subscribers.id,
        fullName: subscribers.fullName,
        businessName: subscribers.businessName,
        phone: subscribers.phone,
        city: subscribers.city,
        country: subscribers.country,
        category: subscribers.category,
        plan: subscribers.plan,
        isVerified: subscribers.isVerified,
        bio: subscribers.bio,
        website: subscribers.website,
        logoUrl: subscribers.logoUrl,
        memberRef: subscribers.memberRef,
        createdAt: subscribers.createdAt,
      })
      .from(subscribers)
      .where(and(condition, eq(subscribers.status, "active")))
      .limit(1);

    if (!member) {
      return c.json({ error: "Profil membre introuvable." }, 404);
    }

    const memberListings = await db
      .select()
      .from(listings)
      .where(and(eq(listings.subscriberId, member.id), eq(listings.status, "active")))
      .orderBy(desc(listings.isFeatured), desc(listings.createdAt));

    const sanitizedPhone = member.phone ? String(member.phone).replace(/[^\d+]/g, "").slice(0, 20) : "";
    const safeMember = { ...member, phone: sanitizedPhone };

    return c.json({ member: safeMember, listings: memberListings });
  } catch (error) {
    console.error("Public member detail error:", error);
    return c.json({ error: "Erreur lors du chargement du profil." }, 500);
  }
});

// Public listings (Marketplace feed)
app.get("/annonces", async (c) => {
  try {
    const category = c.req.query("category");
    const city = c.req.query("city");
    const search = c.req.query("search");
    const sort = c.req.query("sort");
    const subscriberId = c.req.query("subscriberId");

    const rows = await db
      .select({
        id: listings.id,
        ref: listings.ref,
        category: listings.category,
        title: listings.title,
        city: listings.city,
        price: listings.price,
        currency: listings.currency,
        description: listings.description,
        imageUrl: listings.imageUrl,
        isFeatured: listings.isFeatured,
        createdAt: listings.createdAt,
        subscriberId: subscribers.id,
        subscriberName: subscribers.fullName,
        subscriberBusiness: subscribers.businessName,
        subscriberPhone: subscribers.phone,
        subscriberCity: subscribers.city,
        subscriberPlan: subscribers.plan,
        subscriberVerified: subscribers.isVerified,
        subscriberRef: subscribers.memberRef,
      })
      .from(listings)
      .innerJoin(subscribers, eq(listings.subscriberId, subscribers.id))
      .where(and(eq(listings.status, "active"), eq(subscribers.status, "active")))
      .orderBy(desc(listings.isFeatured), desc(listings.createdAt));

    let filtered = rows;

    if (subscriberId) {
      filtered = filtered.filter((r) => r.subscriberId === parseInt(subscriberId, 10));
    }
    if (category && category !== "all") {
      filtered = filtered.filter((r) => r.category === category);
    }
    if (city) {
      filtered = filtered.filter((r) => r.city.toLowerCase() === String(city).toLowerCase());
    }
    if (search) {
      const s = String(search).toLowerCase();
      filtered = filtered.filter(
        (r) =>
          r.title.toLowerCase().includes(s) ||
          r.description.toLowerCase().includes(s) ||
          r.city.toLowerCase().includes(s) ||
          r.subscriberName.toLowerCase().includes(s) ||
          (r.subscriberBusiness && r.subscriberBusiness.toLowerCase().includes(s))
      );
    }

    if (sort === "1" || sort === "newest") {
      filtered.sort((a, b) => new Date(b.createdAt as any).getTime() - new Date(a.createdAt as any).getTime());
    } else if (sort === "2" || sort === "price_asc") {
      filtered.sort((a, b) => (Number(a.price) || 1e12) - (Number(b.price) || 1e12));
    } else if (sort === "3" || sort === "price_desc") {
      filtered.sort((a, b) => (Number(b.price) || -1) - (Number(a.price) || -1));
    }

    return c.json({ listings: filtered });
  } catch (error) {
    console.error("Public annonces error:", error);
    return c.json({ error: "Erreur lors du chargement des annonces." }, 500);
  }
});

// Single public listing
app.get("/annonces/:refOrId", async (c) => {
  try {
    const param = c.req.param("refOrId");
    const isId = /^\d+$/.test(param);

    const condition = isId
      ? eq(listings.id, parseInt(param, 10))
      : eq(listings.ref, param);

    const [listing] = await db
      .select({
        id: listings.id,
        ref: listings.ref,
        category: listings.category,
        title: listings.title,
        city: listings.city,
        price: listings.price,
        currency: listings.currency,
        description: listings.description,
        imageUrl: listings.imageUrl,
        isFeatured: listings.isFeatured,
        createdAt: listings.createdAt,
        subscriberId: subscribers.id,
        subscriberName: subscribers.fullName,
        subscriberBusiness: subscribers.businessName,
        subscriberPhone: subscribers.phone,
        subscriberCity: subscribers.city,
        subscriberPlan: subscribers.plan,
        subscriberVerified: subscribers.isVerified,
        subscriberBio: subscribers.bio,
        subscriberRef: subscribers.memberRef,
      })
      .from(listings)
      .innerJoin(subscribers, eq(listings.subscriberId, subscribers.id))
      .where(and(condition, eq(listings.status, "active"), eq(subscribers.status, "active")))
      .limit(1);

    if (!listing) {
      return c.json({ error: "Annonce introuvable." }, 404);
    }

    return c.json({ listing });
  } catch (error) {
    console.error("Public listing detail error:", error);
    return c.json({ error: "Erreur lors du chargement de l'annonce." }, 500);
  }
});

// ==========================================
// CULTURAL PUBLICATIONS (AFRICA & WORLD)
// ==========================================

const INITIAL_CULTURAL_PUBLICATIONS = [
  {
    title: "La Danse du Feu des Bassar (T'bol) : Rite ancestral de purification et forge séculaire",
    continent: "Afrique",
    country: "Togo",
    countryCode: "TG",
    flagEmoji: "🇹🇬",
    category: "tradition",
    summary: "Rituel millénaire unique au monde où les initiés Bassar dansent pieds nus sur les braises incandescentes sans aucune brûlure.",
    content: "Au cœur de la région de Bassar au Nord du Togo, le T'bol ou Danse du Feu est l'une des expressions spirituelles et initiatiques les plus fascinantes d'Afrique de l'Ouest. Liée à la tradition métallurgique plurimillénaire des Bassar — maîtres du fer et constructeurs des hauts-fourneaux traditionnels de Nangbani et Bandjéli —, cette cérémonie sacrée rassemble les forgerons initiés, guérisseurs et dignitaires. Au son des tambours graves et des chants invocatoires, les danseurs pénètrent dans un gigantesque brasier d'écorces médicinales séculaires. Ils manipulent les charbons ardents avec leurs mains et leurs bouches, purifiant la communauté et éloignant les calamités. Cette tradition vivante est un témoignage éclatant du courage, de la maîtrise des forces naturelles et de la mémoire inaltérable du peuple Bassar.",
    authorName: "Comité du Patrimoine Bassar Kàakpi",
    imageUrl: "https://images.unsplash.com/photo-1516450360452-9312f5e86fc7?auto=format&fit=crop&w=1200&q=80",
    videoUrl: "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    tags: "Bassar, Danse du Feu, T'bol, Togo, Métallurgie, Rites",
    likesCount: 142,
    status: "published",
  },
  {
    title: "Le Tissu Imprimé Kàakpi : L'étoffe emblématique et la mémoire visuelle du peuple Bassar",
    continent: "Afrique",
    country: "Togo",
    countryCode: "TG",
    flagEmoji: "🇹🇬",
    category: "textile_attire",
    summary: "Tissu imprimé aux motifs authentiques du peuple Bassar, le Kàakpi incarne la mémoire, la dignité et l'élégance contemporaine.",
    content: "Le tissu imprimé Bassar Kàakpi est une création emblématique portant les motifs graphiques et les symboles sacrés du peuple Bassar. Conçu comme une étoffe imprimée de haute qualité alliant respect de l'héritage et exigence esthétique moderne, chaque motif fait écho à la tradition de la forge, à la mémoire collective et à l'identité culturelle. Porté lors des cérémonies, fêtes et rassemblements communautaires, le tissu imprimé Kàakpi habille avec fierté les nouvelles générations à travers le monde.",
    authorName: "Maison Bassar Kàakpi",
    imageUrl: "https://images.unsplash.com/photo-1607344645866-009c320c5ab8?auto=format&fit=crop&w=1200&q=80",
    videoUrl: "",
    tags: "Kàakpi, Tissu Imprimé, Textile, Bassar, Togo, Mode Contemporaine",
    likesCount: 198,
    status: "published",
  },
  {
    title: "La Fête Vodun d'Ouidah & les Masques Guèlèdè : Spiritualité et mémoire vivante",
    continent: "Afrique",
    country: "Bénin",
    countryCode: "BJ",
    flagEmoji: "🇧🇯",
    category: "rites_festivals",
    summary: "Chaque 10 janvier, Ouidah et le Bénin célèbrent les divinités ancestrales et l'harmonie entre l'homme et le cosmos.",
    content: "Le Bénin, berceau des civilisations Fon, Yoruba et Bariba, abrite l'une des spiritualités les plus riches de l'humanité. À Ouidah, au bord de l'Océan Atlantique et de la Porte du Non-Retour, la fête annuelle du Vodun rassemble des pèlerins venus du monde entier — Caraïbes, Brésil, États-Unis et Afrique. Les masques Guèlèdè, classés au patrimoine immatériel de l'UNESCO, rendent hommage au pouvoir primordial des mères et des ancêtres féminins à travers des chorégraphies théâtrales, des coiffes sculptées en bois polychrome et des polyrythmies sacrées.",
    authorName: "Cercle Culturel Ouidah-Dahomey",
    imageUrl: "https://images.unsplash.com/photo-1547471080-7cc2caa01a7e?auto=format&fit=crop&w=1200&q=80",
    videoUrl: "",
    tags: "Bénin, Vodun, Guèlèdè, Ouidah, UNESCO, Traditions",
    likesCount: 115,
    status: "published",
  },
  {
    title: "Le Tissage Kente des Ashanti : Géométrie sacrée et noblesse des rois de Kumasi",
    continent: "Afrique",
    country: "Ghana",
    countryCode: "GH",
    flagEmoji: "🇬🇭",
    category: "textile_attire",
    summary: "Étoffe mythique de soie et coton où chaque couleur symbolise une vertu morale et spirituelle.",
    content: "Né dans le village historique de Bonwire dans le royaume Ashanti au Ghana, le tissu Kente est l'un des trésors vestimentaires les plus universellement reconnus. À l'origine réservé aux rois (Asantehene) et aux reines mères, le Kente est tissé sur des métiers à pédales de bois noble. L'or symbolise la royauté et la prospérité, le vert la fertilité et le renouveau, le bleu la paix et l'harmonie, et le noir l'énergie spirituelle des ancêtres. Chaque motif possède un nom philosophique, comme 'Adwinasa' (tous les motifs sont épuisés), exprimant le sommet de la maîtrise artisanale.",
    authorName: "Société des Arts du Ghana",
    imageUrl: "https://images.unsplash.com/photo-1523821741446-edb2b68bb7a0?auto=format&fit=crop&w=1200&q=80",
    videoUrl: "",
    tags: "Ghana, Kente, Ashanti, Kumasi, Textile, Royauté",
    likesCount: 167,
    status: "published",
  },
  {
    title: "La Fête des Ignames en Pays Akan & l'Artisanat Senoufo : Célébration de la terre nourricière",
    continent: "Afrique",
    country: "Côte d'Ivoire",
    countryCode: "CI",
    flagEmoji: "🇨🇮",
    category: "rites_festivals",
    summary: "Action de grâce pour les récoltes abondantes et transmission des valeurs de solidarité communautaire.",
    content: "En Côte d'Ivoire, la fête des ignames est un temps fort qui marque le passage à la nouvelle année agricole en pays Baoulé, Agni et Abron. Avant que quiconque ne consomme la nouvelle igname, les prémices sont offerts aux ancêtres protecteurs lors de libations solennelles. Dans le Nord du pays, les sculpteurs et forgerons Senoufo de Korhogo créent les toiles de Korhogo peintes à la boue fermentée et les célèbres oiseaux calaos protecteurs, symbolisant la maternité, la fécondité et la transmission du savoir initiatique du Poro.",
    authorName: "Mémoire des Terroirs Ivoiriens",
    imageUrl: "https://images.unsplash.com/photo-1518709268805-4e9042af9f23?auto=format&fit=crop&w=1200&q=80",
    videoUrl: "",
    tags: "Côte d'Ivoire, Fête des Ignames, Senoufo, Korhogo, Akan",
    likesCount: 89,
    status: "published",
  },
  {
    title: "La Teranga Sénégalaise & le Ceebu Jën : Hospitalité légendaire et gastronomie d'exception",
    continent: "Afrique",
    country: "Sénégal",
    countryCode: "SN",
    flagEmoji: "🇸🇳",
    category: "gastronomie",
    summary: "L'art de recevoir et le plat national sénégalais classé au patrimoine mondial immatériel de l'UNESCO.",
    content: "La 'Teranga' est bien plus qu'un mot wolof : c'est une philosophie de vie qui place l'hôte, le voyageur et l'étranger au rang de bénédiction suprême. Au cœur de cette générosité se trouve le Ceebu Jën (riz au poisson de Saint-Louis), inscrit au patrimoine immatériel de l'UNESCO. Cuisiné lentement avec du poisson frais de l'Atlantique, du riz brisé parfumé, des légumes gorgés de soleil (manioc, chou, carotte, aubergine amère) et du 'gejj' (poisson séché traditionnel), il est partagé autour du grand bol commun 'bolus', symbole d'unité, d'égalité et de convivialité.",
    authorName: "Académie Gourmande de Dakar",
    imageUrl: "https://images.unsplash.com/photo-1504674900247-0877df9cc836?auto=format&fit=crop&w=1200&q=80",
    videoUrl: "",
    tags: "Sénégal, Teranga, Ceebu Jën, Gastronomie, UNESCO",
    likesCount: 153,
    status: "published",
  },
  {
    title: "L'Épopée Mandingue & le Bogolan : Mémoire des griots et art textile végétal",
    continent: "Afrique",
    country: "Mali",
    countryCode: "ML",
    flagEmoji: "🇲🇱",
    category: "tradition",
    summary: "Du grand empire de Soundiata Keïta aux toiles de coton teintes à l'argile du fleuve Niger.",
    content: "Le Mali porte la mémoire vivante de la Charte de Kouroukan Fouga (1236), l'une des premières déclarations des droits humains au monde. Les griots (Djelis) y perpétuent l'art oratoire au son de la Kora et du Balafon. En parallèle, les femmes de San et du pays Bélédougou maîtrisent l'art du Bogolanfini : un tissu de coton écru trempé dans des décoctions de feuilles riches en tanins, puis peint à la main avec de la boue ferrugineuse fermentée prélevée dans les méandres du fleuve Niger. Chaque graphisme raconte une histoire, guérit et protège la personne qui le porte.",
    authorName: "Fondation du Mandé",
    imageUrl: "https://images.unsplash.com/photo-1544816155-12df9643f363?auto=format&fit=crop&w=1200&q=80",
    videoUrl: "",
    tags: "Mali, Bogolan, Griots, Kora, Soundiata Keïta, Niger",
    likesCount: 134,
    status: "published",
  },
  {
    title: "Les Masques Eyo & la Richesse des Royaumes Yoruba et Igbo : Fêtes grandioses et tambours parlants",
    continent: "Afrique",
    country: "Nigeria",
    countryCode: "NG",
    flagEmoji: "🇳🇬",
    category: "dance_music",
    summary: "Le festival mythique d'Adamu Orisha à Lagos et l'héritage musical séculaire du tambour bata et du talking drum.",
    content: "Le Nigeria, géant culturel de plus de 250 ethnies, offre des traditions spectaculaires. À Lagos, le festival des masques Eyo transforme l'île historique en une procession immaculée de silhouettes blanches drapées de voiles et portant le 'Opambata' (bâton sacré sculpté). Au son du 'Gangan' (tambour dundun parlant capable d'imiter les intonations tonales de la langue yoruba), les dignitaires et sociétés secrètes célèbrent la vie des grands souverains défunts. La créativité nigériane est un pont continu entre royautés séculaires d'Ifé et Bénin City et effervescence culturelle contemporaine.",
    authorName: "Institut des Arts Vivants de Lagos",
    imageUrl: "https://images.unsplash.com/photo-1514525253161-7a46d19cd819?auto=format&fit=crop&w=1200&q=80",
    videoUrl: "",
    tags: "Nigeria, Eyo, Yoruba, Lagos, Musique, Gangan",
    likesCount: 121,
    status: "published",
  },
  {
    title: "Le Ngondo des Sawa & le Tissu Ndop des Bamiléké : Mystère aquatique et chefferies royales",
    continent: "Afrique",
    country: "Cameroun",
    countryCode: "CM",
    flagEmoji: "🇨🇲",
    category: "tradition",
    summary: "Immersion sacrée au fond du fleuve Wouri et tentures cérémonielles indigo des hauts plateaux de l'Ouest.",
    content: "Le Cameroun, 'Afrique en miniature', abrite le grand rituel du Ngondo sur les berges du fleuve Wouri à Douala : un messager plonge dans les eaux profondes avec un vase sacré et en ressort les vêtements secs, porteur du message annuel des divinités de l'eau (Miengu). Dans les Grassfields, les chefferies Bamiléké et Bamoun conservent le Ndop, tissu indigo teint à la réserve selon des techniques ancestrales, réservé au roi (Fo) et aux sociétés secrètes coutumières lors des funérailles royales et intronisations.",
    authorName: "Union des Traditions du Littoral et de l'Ouest",
    imageUrl: "https://images.unsplash.com/photo-1511192336575-5a79af67a629?auto=format&fit=crop&w=1200&q=80",
    videoUrl: "",
    tags: "Cameroun, Ngondo, Wouri, Ndop, Bamiléké, Sawa",
    likesCount: 108,
    status: "published",
  },
  {
    title: "Le Faso Dan Fani & les Masques Bobo : Fierté du coton tissé et rituels agraires",
    continent: "Afrique",
    country: "Burkina Faso",
    countryCode: "BF",
    flagEmoji: "🇧🇫",
    category: "textile_attire",
    summary: "'L'étoffe tissée de la patrie' : symbole d'émancipation économique, d'élégance et de savoir-faire des tisserandes burkinabè.",
    content: "Au pays des Hommes Intègres, le Faso Dan Fani (le pagne tissé de la patrie) est un emblème national érigé en symbole d'indépendance, de fierté et de consommation locale. Tissé fil par fil par des coopératives de femmes talentueuses à Ouagadougou et Koudougou, il offre des rayures vives et une tenue impeccable. Lors du festival des masques de Dédougou (FESTIMA), les masques de feuilles et de fibres des ethnies Bobo, Bwaba et Mossi célèbrent le réveil de la nature et l'équilibre écologique avant les premières pluies.",
    authorName: "Coopérative Mémoire du Coton Burkinabè",
    imageUrl: "https://images.unsplash.com/photo-1528459801416-a9e53bbf4e17?auto=format&fit=crop&w=1200&q=80",
    videoUrl: "",
    tags: "Burkina Faso, Faso Dan Fani, Coton, Masques, Tissage",
    likesCount: 145,
    status: "published",
  },
  {
    title: "La Rumba Congolaise & le Tissu Kuba : Patrimoine mondial de l'UNESCO et raphia royal",
    continent: "Afrique",
    country: "RD Congo",
    countryCode: "CD",
    flagEmoji: "🇨🇩",
    category: "dance_music",
    summary: "L'élégance légendaire de Kinshasa et la complexité mathématique des velours du Kasaï.",
    content: "Inscrite au patrimoine culturel immatériel de l'humanité, la Rumba congolaise transcende les frontières : poésie des guitares cristallines de Grand Kalle et Franco, élégance vestimentaire mythique des Sapeurs et joie de vivre contagieuse. Dans le royaume Kuba au Kasaï, les artistes réalisent des velours de raphia aux motifs géométriques asymétriques d'une modernité stupéfiante, qui ont inspiré les plus grands artistes de l'art moderne mondial dont Matisse et Picasso.",
    authorName: "Cercle Culturel du Fleuve Congo",
    imageUrl: "https://images.unsplash.com/photo-1465847899084-d164df4dedc6?auto=format&fit=crop&w=1200&q=80",
    videoUrl: "",
    tags: "RDC, Rumba Congolaise, Velours Kuba, UNESCO, Kinshasa",
    likesCount: 176,
    status: "published",
  },
  {
    title: "La Haute Gastronomie & les Arts de la Table : Traditions culinaires et élégance des terroirs",
    continent: "Europe",
    country: "France",
    countryCode: "FR",
    flagEmoji: "🇫🇷",
    category: "gastronomie",
    summary: "Le repas gastronomique des Français inscrit au patrimoine immatériel de l'UNESCO : rituel du goût et convivialité.",
    content: "En France, le repas n'est pas seulement un acte nourricier : c'est un rituel social et culturel séculaire fondé sur le respect des produits de saison, l'alliance minutieuse entre mets et vins fins, et l'art de dresser une table harmonieuse. Des bistrots parisiens aux banquets de gala des grands châteaux, la gastronomie française partage avec les traditions africaines la célébration du rassemblement familial et du dialogue entre les générations.",
    authorName: "Société des Épicuriens du Monde",
    imageUrl: "https://images.unsplash.com/photo-1550966871-3ed3cdb5ed0c?auto=format&fit=crop&w=1200&q=80",
    videoUrl: "",
    tags: "France, Gastronomie, UNESCO, Arts de la Table, Terroirs",
    likesCount: 92,
    status: "published",
  },
  {
    title: "L'Artisanat de Précision & les Fêtes de Moisson : Héritage musical et savoir-faire d'Europe Centrale",
    continent: "Europe",
    country: "Allemagne",
    countryCode: "DE",
    flagEmoji: "🇩🇪",
    category: "history",
    summary: "Tradition des corporations de maîtres artisans, musique classique et grandes fêtes de village 'Erntedankfest'.",
    content: "L'Allemagne cultive une tradition séculaire de transmission de l'artisanat d'excellence à travers le système des corporations (Handwerk) et des maîtres compagnons. Lors des fêtes d'automne et de moisson (Erntedankfest), les communautés célèbrent la terre nourricière avec des couronnes de blé tressées, des danses folkloriques et des concerts d'instruments traditionnels en bois et cuivres, illustrant la diversité des traditions régionales européennes.",
    authorName: "Institut Culturel Rhénan",
    imageUrl: "https://images.unsplash.com/photo-1467269204594-9661b134dd2b?auto=format&fit=crop&w=1200&q=80",
    videoUrl: "",
    tags: "Allemagne, Artisanat, Erntedankfest, Musique, Traditions",
    likesCount: 81,
    status: "published",
  },
  {
    title: "L'Héritage Afro-Caribéen & la Peinture Naïve : Cérémonie de Bwa Kayiman et résilience",
    continent: "Amériques",
    country: "Haïti",
    countryCode: "HT",
    flagEmoji: "🇭🇹",
    category: "tradition",
    summary: "La première république noire libre du monde et la fusion poétique des mémoires d'Afrique de l'Ouest et des Caraïbes.",
    content: "Haïti conserve au plus profond de son âme les racines des peuples Bassar, Fon, Yoruba et Kongo déportés lors de la traite transatlantique. La cérémonie fondatrice du Bwa Kayiman en août 1791 a sonné l'éveil de la liberté universelle. Les peintres de Saint-Soleil et de Jacmel transforment les couleurs éclatantes tropicales en fresques vibrantes peuplées d'esprits bienveillants, de tambours radas et de marchés foisonnants, célébrant la victoire éternelle de la dignité humaine.",
    authorName: "Collectif Mémoire & Racines Caribéennes",
    imageUrl: "https://images.unsplash.com/photo-1579783900882-c0d3dad7b119?auto=format&fit=crop&w=1200&q=80",
    videoUrl: "",
    tags: "Haïti, Bwa Kayiman, Diaspora, Caraïbes, Peinture, Racines",
    likesCount: 129,
    status: "published",
  },
  {
    title: "Le Carnaval de Salvador de Bahia & la Capoeira : Racines afro-brésiliennes et percussions sacrées",
    continent: "Amériques",
    country: "Brésil",
    countryCode: "BR",
    flagEmoji: "🇧🇷",
    category: "dance_music",
    summary: "Le berceau noir du Brésil : berimbau, danses martiales, spiritualité du Candomblé et ferveur des tambours de l'Olodum.",
    content: "À Salvador de Bahia, le cœur noir du Brésil bat au rythme de l'Afrique de l'Ouest. La Capoeira, art martial déguisé en danse acrobatique créé par les esclaves pour conquérir leur liberté, résonne au son du 'berimbau' et des chants de mémoire. Lors du carnaval, les blocs afro comme Olodum et Ilê Aiyê font vibrer le quartier historique du Pelourinho avec des centaines de tambours repiques et de surdos vêtus de tissus aux couleurs panafricaines (rouge, or, vert, noir), unissant les générations dans une fierté inébranlable.",
    authorName: "Centre Afro-Bahianais des Traditions",
    imageUrl: "https://images.unsplash.com/photo-1516450360452-9312f5e86fc7?auto=format&fit=crop&w=1200&q=80",
    videoUrl: "",
    tags: "Brésil, Salvador de Bahia, Capoeira, Olodum, Afro-Brésil, Candomblé",
    likesCount: 162,
    status: "published",
  },
  {
    title: "La Cérémonie du Thé Chanoyu & le Tissage Royal Nishijin : Harmonie et précision séculaire",
    continent: "Asie",
    country: "Japon",
    countryCode: "JP",
    flagEmoji: "🇯🇵",
    category: "tradition",
    summary: "L'art du 'Wabi-Sabi' et les soieries impériales de Kyoto tissées selon des méthodes millénaires.",
    content: "Au Japon, la cérémonie du thé (Chanoyu) est un art total alliant architecture épurée, céramiques cuites au feu de bois et respect spirituel des saisons. À Kyoto, les artisans du quartier historique de Nishijin perpétuent le tissage des brocarts d'or et de soie pour les kimonos d'apparat, incarnant une quête d'excellence partagée avec les grands maîtres tisserands d'Afrique.",
    authorName: "Cercle des Maîtres de Kyoto",
    imageUrl: "https://images.unsplash.com/photo-1528360983277-13d401cdc186?auto=format&fit=crop&w=1200&q=80",
    videoUrl: "",
    tags: "Japon, Chanoyu, Nishijin, Soie, Artisanat, Asie",
    likesCount: 95,
    status: "published",
  }
];

// Helper: Ensure initial cultural publications exist
const MEMORY_PUBS: any[] = [];
const MEMORY_LIKES: Record<string, number> = {};

let tablesEnsured = false;
async function ensureTables() {
  if (tablesEnsured) return;
  try {
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS "cultural_publications" (
        "id" serial PRIMARY KEY,
        "title" text NOT NULL,
        "continent" text DEFAULT 'Afrique' NOT NULL,
        "country" text NOT NULL,
        "country_code" text NOT NULL,
        "flag_emoji" text NOT NULL,
        "category" text NOT NULL,
        "summary" text NOT NULL,
        "content" text NOT NULL,
        "author_name" text DEFAULT 'Communauté Bassar Kàakpi',
        "image_url" text DEFAULT '',
        "video_url" text DEFAULT '',
        "tags" text DEFAULT '',
        "likes_count" integer DEFAULT 0,
        "status" text DEFAULT 'published' NOT NULL,
        "created_at" timestamp DEFAULT now(),
        "updated_at" timestamp DEFAULT now()
      );
    `);
    // event_reservations is managed exclusively by migrations (netlify/database/migrations).
    tablesEnsured = true;
  } catch (err) {
    console.warn("ensureTables warning:", err);
  }
}

async function ensureCulturalPublications() {
  await ensureTables();
  try {
    const existing = await db
      .select({ count: sql`count(*)` })
      .from(culturalPublications);
    const count = Number(existing[0]?.count || 0);
    if (count < INITIAL_CULTURAL_PUBLICATIONS.length) {
      const allRows = await db.select({ title: culturalPublications.title }).from(culturalPublications);
      const existingTitles = new Set(allRows.map((x) => x.title));
      const toInsert = INITIAL_CULTURAL_PUBLICATIONS.filter((p) => !existingTitles.has(p.title));
      if (toInsert.length > 0) {
        await db.insert(culturalPublications).values(toInsert);
      }
    }
  } catch (err) {
    console.warn("Auto-seed cultural publications error:", err);
  }
}

// Get cultural publications (public with filters)
app.get("/cultural-publications", async (c) => {
  try {
    const continent = c.req.query("continent");
    const country = c.req.query("country");
    const category = c.req.query("category");
    const search = c.req.query("search");

    let posts: any[] = [];
    try {
      await ensureCulturalPublications();
      posts = await db
        .select()
        .from(culturalPublications)
        .where(eq(culturalPublications.status, "published"))
        .orderBy(desc(culturalPublications.createdAt));
    } catch (dbErr) {
      const defaults = INITIAL_CULTURAL_PUBLICATIONS.map((p, idx) => ({ id: idx + 1, ...p, createdAt: new Date() }));
      posts = [...MEMORY_PUBS, ...defaults];
    }

    let filtered = posts;
    if (continent && continent !== "all") {
      filtered = filtered.filter(
        (p) => (p.continent || "Afrique").toLowerCase() === String(continent).toLowerCase()
      );
    }
    if (country && country !== "all") {
      filtered = filtered.filter(
        (p) =>
          p.country.toLowerCase() === String(country).toLowerCase() ||
          p.countryCode.toLowerCase() === String(country).toLowerCase()
      );
    }
    if (category && category !== "all") {
      filtered = filtered.filter((p) => p.category === category);
    }
    if (search) {
      const s = String(search).toLowerCase();
      filtered = filtered.filter(
        (p) =>
          p.title.toLowerCase().includes(s) ||
          p.country.toLowerCase().includes(s) ||
          p.summary.toLowerCase().includes(s) ||
          p.content.toLowerCase().includes(s) ||
          (p.tags && p.tags.toLowerCase().includes(s))
      );
    }

    return c.json({ publications: filtered });
  } catch (error) {
    console.error("Fetch cultural publications error:", error);
    let list = INITIAL_CULTURAL_PUBLICATIONS.map((p, idx) => ({ id: idx + 1, ...p, createdAt: new Date() }));
    return c.json({ publications: [...MEMORY_PUBS, ...list] });
  }
});

// Get single cultural publication
app.get("/cultural-publications/:id", async (c) => {
  try {
    await ensureCulturalPublications();
    const id = parseInt(c.req.param("id"), 10);

    const [post] = await db
      .select()
      .from(culturalPublications)
      .where(eq(culturalPublications.id, id))
      .limit(1);

    if (!post) {
      return c.json({ error: "Publication introuvable." }, 404);
    }

    return c.json({ publication: post });
  } catch (error) {
    console.error("Get cultural publication error:", error);
    return c.json({ error: "Erreur serveur." }, 500);
  }
});

// Submit a new cultural publication
app.post("/cultural-publications", async (c) => {
  try {
    if (!(await checkRateLimit("culture-post", getClientIp(c), 5, 60 * 60 * 1000))) {
      return c.json({ error: "Trop de publications. Veuillez réessayer plus tard." }, 429);
    }
    await ensureTables();
    const subscriber = await getAuthSubscriber(c);
    const body = await c.req.json();
    const {
      title,
      continent = "Afrique",
      country,
      countryCode = "TG",
      flagEmoji = "🌍",
      category = "tradition",
      summary,
      content,
      authorName,
      imageUrl = "",
      videoUrl = "",
      tags = "",
    } = body;

    if (!title || !country || !summary || !content) {
      return c.json(
        { error: "Titre, pays, résumé et contenu détaillé sont obligatoires." },
        400
      );
    }

    const safeContinent = ALLOWED_CONTINENTS.has(String(continent).trim()) ? String(continent).trim() : "Afrique";
    const safeCategory = ALLOWED_CULTURAL_CATEGORIES.has(String(category).trim()) ? String(category).trim() : "tradition";
    const safeFlag = sanitizeEmoji(flagEmoji, "🌍");
    const safeImg = isValidHttpsUrl(imageUrl) ? String(imageUrl).trim() : "";
    const safeVid = isValidHttpsUrl(videoUrl) ? String(videoUrl).trim() : "";
    const safeCountryCode = String(countryCode || "TG").replace(/[^A-Za-z]/g, "").slice(0, 3).toUpperCase();
    const finalAuthor = authorName ? sanitizeText(authorName, 100) : (subscriber ? (subscriber.businessName || subscriber.fullName) : "Membre de la Communauté");

    let newPost: any = null;
    try {
      const [inserted] = await db
        .insert(culturalPublications)
        .values({
          title: sanitizeText(title, 200),
          continent: safeContinent,
          country: sanitizeText(country, 80),
          countryCode: safeCountryCode,
          flagEmoji: safeFlag,
          category: safeCategory,
          summary: sanitizeText(summary, 500),
          content: sanitizeText(content, 10000),
          authorName: sanitizeText(finalAuthor, 100),
          imageUrl: safeImg,
          videoUrl: safeVid,
          tags: sanitizeText(tags, 200),
          status: "published",
          likesCount: 1,
        })
        .returning();
      newPost = inserted;
    } catch (dbErr) {
      console.warn("DB cultural publication insert fallback:", dbErr);
      newPost = {
        id: Date.now(),
        title: sanitizeText(title, 200),
        continent: safeContinent,
        country: sanitizeText(country, 80),
        countryCode: safeCountryCode,
        flagEmoji: safeFlag,
        category: safeCategory,
        summary: sanitizeText(summary, 500),
        content: sanitizeText(content, 10000),
        authorName: sanitizeText(finalAuthor, 100),
        imageUrl: safeImg,
        videoUrl: safeVid,
        tags: sanitizeText(tags, 200),
        status: "published",
        likesCount: 1,
        createdAt: new Date(),
      };
    }

    if (newPost) {
      MEMORY_PUBS.unshift(newPost);
    }

    return c.json({ success: true, publication: newPost }, 201);
  } catch (error) {
    console.error("Create cultural publication error:", error);
    return c.json({ error: "Erreur lors de l'enregistrement de la publication." }, 500);
  }
});

// Like a cultural publication
app.post("/cultural-publications/:id/like", async (c) => {
  if (!(await checkRateLimit("culture-like", getClientIp(c), 30, 60 * 1000))) {
    return c.json({ error: "Trop de requêtes." }, 429);
  }
  const idStr = c.req.param("id");
  const id = parseInt(idStr, 10);
  let updatedLikes = (MEMORY_LIKES[idStr] || 0) + 1;

  try {
    const [existing] = await db
      .select()
      .from(culturalPublications)
      .where(eq(culturalPublications.id, id))
      .limit(1);

    if (existing) {
      updatedLikes = (existing.likesCount || 0) + 1;
      await db
        .update(culturalPublications)
        .set({ likesCount: updatedLikes })
        .where(eq(culturalPublications.id, id));
    }
  } catch (error) {
    console.warn("Like db fallback:", error);
  }

  // Also update in memory pubs if present
  var mItem = MEMORY_PUBS.find((p) => String(p.id) === idStr);
  if (mItem) mItem.likesCount = updatedLikes;
  MEMORY_LIKES[idStr] = updatedLikes;

  return c.json({ success: true, likesCount: updatedLikes });
});

// ==========================================
// GALA, DINNER & FESTIVE EVENTS & RESERVATIONS
// ==========================================

const GALA_EVENTS = [
  {
    slug: "gala-prestige-kaakpi",
    title: "Grand Gala Bassar Kàakpi & Nuit de l'Élégance Africaine",
    subtitle: "Célébration royale, défilé haute couture Kàakpi, dîner gastronomique 5 services & bal de prestige",
    date: "2026-11-28",
    time: "19:30 - 02:00",
    city: "Lomé & Retransmission Paris",
    venue: "Palais des Congrès de Lomé & Salons Élysées",
    category: "gala",
    badge: "Événement Majeur",
    remainingSeats: 18,
    image: "https://images.unsplash.com/photo-1519671482749-fd09be7ccebf?auto=format&fit=crop&w=1200&q=80",
    description: "Une soirée féerique au cœur de l'élégance africaine et des traditions Bassar Kàakpi. Au programme : cocktail de bienvenue au champagne et nectars exotiques, défilé exclusif des créations en tissu Kàakpi impérial, dîner gastronomique 5 services préparé par des maîtres cuisiniers, prestations de tambours royaux et orchestre live afro-jazz, suivi de la grande remise des Trophées d'Honneur de la diaspora.",
    dressCode: "Tenue royale africaine, Kàakpi d'apparat, smoking ou robe de soirée",
    program: [
      { time: "19:30", title: "Accueil VIP au Tapis Rouge & Cocktail Pétillant" },
      { time: "20:30", title: "Grand Défilé Haute Couture Kàakpi & Étoffes Royales" },
      { time: "21:30", title: "Dîner Gastronomique 5 Services & Duo Harpe-Kora" },
      { time: "23:00", title: "Cérémonie des Trophées d'Honneur de la Diaspora" },
      { time: "23:45", title: "Grand Bal de Prestige & Orchestre Live Afro-Jazz" }
    ],
    tickets: [
      { type: "standard", name: "Place Standard", price: 25000, cur: "XOF", eur: 38, remaining: 10, desc: "Accès complet au gala, cocktail de bienvenue, dîner gastronomique 5 services et soirée dansante." },
      { type: "couple", name: "Formule Duo Prestige (Couple)", price: 45000, cur: "XOF", eur: 68, remaining: 5, desc: "2 places réservées côte à côte, table avec vue privilégiée, coupe de champagne offerte." },
      { type: "vip", name: "Place VIP Prestige", price: 60000, cur: "XOF", eur: 92, remaining: 2, desc: "Carré d'Honneur, accueil VIP au tapis rouge, champagne à discrétion, cadeau souvenir Kàakpi." },
      { type: "table_prestige", name: "Table Royale Privatisée (8 pers.)", price: 200000, cur: "XOF", eur: 305, remaining: 1, desc: "Table entière de 8 personnes au premier rang, service de majordome dédié, 2 bouteilles de champagne grand cru, mention du nom sur le programme officiel." }
    ],
    highlights: ["Défilé Haute Couture Kàakpi", "Dîner gastronomique 5 services", "Trophées d'Honneur Diaspora", "Grand Bal dansant live"]
  },
  {
    slug: "diner-terroir-monde",
    title: "Dîner Gastronomique : Saveurs du Terroir & du Monde",
    subtitle: "Voyage culinaire immersif entre cuisine ancestrale d'Afrique de l'Ouest et haute gastronomie internationale",
    date: "2026-12-12",
    time: "20:00 - 23:30",
    city: "Lomé",
    venue: "Salons Royaux & Terrasse Panoramique de l'Océan",
    category: "diner",
    badge: "Haute Gastronomie",
    remainingSeats: 12,
    image: "https://images.unsplash.com/photo-1544025162-d76694265947?auto=format&fit=crop&w=1200&q=80",
    description: "Une expérience culinaire immersive où les ingrédients nobles du terroir Bassar et togolais (igname pilée noble, sauces épicées raffinées, gibier délicat, poissons fumés de lagune) rencontrent les techniques de la haute cuisine contemporaine. Menus accords mets et vins fins, animation acoustique kora et violoncelle.",
    dressCode: "Chic & Épique, tenue de ville élégante ou tenue traditionnelle raffinée",
    program: [
      { time: "20:00", title: "Cocktail d'Ouverture & Dégustation d'Amuse-Bouches" },
      { time: "20:30", title: "Entrée Signature : Terroir de Bassar Reconnecté" },
      { time: "21:30", title: "Plat Principal d'Apparat & Accords Vins Millésimés" },
      { time: "22:30", title: "Dessert Création & Récital Acoustique" }
    ],
    tickets: [
      { type: "standard", name: "Dîner Accord Mets & Saveurs", price: 20000, cur: "XOF", eur: 30, remaining: 6, desc: "Menu dégustation 4 plats, cocktail apéritif, boissons douces et vins du terroir inclus." },
      { type: "vip", name: "Dîner Grand Cru & Table Sommelier", price: 40000, cur: "XOF", eur: 60, remaining: 4, desc: "Menu 6 créations du chef, accords vins millésimés, placement terrasse panoramique." },
      { type: "table_prestige", name: "Table Épicurienne Privée (6 pers.)", price: 120000, cur: "XOF", eur: 180, remaining: 2, desc: "Table privatisée de 6 convives avec accord mets & vins d'exception et rencontre personnalisée avec les chefs." }
    ],
    highlights: ["Menu dégustation 4 à 6 plats", "Duo acoustique Kora & Violoncelle", "Accords Vins & Nectars tropicaux", "Cadre panoramique sur mer"]
  },
  {
    slug: "nuit-festive-reveillon",
    title: "Grande Nuit Festive & Rythmes Traditionnels du Réveillon",
    subtitle: "Le plus grand rassemblement festif de fin d'année : percussions royales, danses du monde, buffet géant & feu d'artifice",
    date: "2026-12-31",
    time: "21:00 - Aube",
    city: "Bassar & Lomé",
    venue: "Grande Esplanade Kàakpi & Pavillon Festif",
    category: "festive",
    badge: "Réveillon Féerique",
    remainingSeats: 26,
    image: "https://images.unsplash.com/photo-1492684223066-81342ee5ff30?auto=format&fit=crop&w=1200&q=80",
    description: "Célébrez le passage vers la nouvelle année dans une explosion de joie, de tambours royaux, de feux d'artifice spectaculaires et de rythmes dansants d'Afrique et de la diaspora internationale. Buffet de minuit somptueux, troupe de danseurs du feu de Bassar et DJ set international jusqu'au lever du soleil.",
    dressCode: "Festif éclatant, couleurs vives ou blanc royal",
    program: [
      { time: "21:00", title: "Ouverture des Portes & Rythmes de Tambours Royaux" },
      { time: "22:15", title: "Cérémonie Magique des Danseurs du Feu T'bol" },
      { time: "23:59", title: "Décompte du Nouvel An & Feu d'Artifice Monumental" },
      { time: "00:30", title: "Buffet Festif Impérial de Minuit & Soirée Dansante Jusqu'à l'Aube" }
    ],
    tickets: [
      { type: "standard", name: "Entrée Festive & Buffet", price: 15000, cur: "XOF", eur: 23, remaining: 15, desc: "Accès à la nuit festive, buffet gastronomique de minuit, coupe de champagne au décompte." },
      { type: "vip", name: "VIP Lounge Réveillon", price: 35000, cur: "XOF", eur: 53, remaining: 8, desc: "Espace lounge privatisé, service à table, buffet premium chaud/froid, champagne illimité jusqu'à 01h." },
      { type: "table_prestige", name: "Table Impériale Réveillon (8 pers.)", price: 150000, cur: "XOF", eur: 230, remaining: 3, desc: "Salon complet réservé pour 8 personnes avec 2 bouteilles de champagne, buffet dînatoire royal et service dédié." }
    ],
    highlights: ["Danseurs du Feu traditionnels", "Buffet géant de fête", "Feu d'artifice monumental à minuit", "Ambiance festive jusqu'à l'aube"]
  },
  {
    slug: "gala-entrepreneurs-createurs",
    title: "Soirée Culturelle & Gala des Bâtisseurs et Créateurs",
    subtitle: "Réseautage prestige, exposition d'art contemporain et hommage aux talents de la diaspora",
    date: "2027-01-16",
    time: "18:30 - 23:00",
    city: "Lomé",
    venue: "Grand Auditorium & Galerie d'Art Contemporain",
    category: "gala",
    badge: "Réseau & Culture",
    remainingSeats: 15,
    image: "https://images.unsplash.com/photo-1469371670807-013ccf25f16a?auto=format&fit=crop&w=1200&q=80",
    description: "Le rendez-vous d'affaires et de culture qui réunit les entrepreneurs, mécènes, artistes et créateurs engagés dans le développement économique et la préservation culturelle. Table ronde exclusive, vente aux enchères caritative d'œuvres d'art et de pièces uniques Kàakpi, cocktail dînatoire de prestige.",
    dressCode: "Business Chic / Tenue traditionnelle d'apparat",
    program: [
      { time: "18:30", title: "Accueil des Délégués & Networking B2B" },
      { time: "19:30", title: "Table Ronde : 'Cultures d'Afrique, Moteurs de Développement'" },
      { time: "20:45", title: "Vente aux Enchères Caritative d'Œuvres & Pièces Rares" },
      { time: "21:45", title: "Cocktail Dînatoire & Remise de l'Annuaire d'Honneur" }
    ],
    tickets: [
      { type: "standard", name: "Pass Conférence & Cocktail", price: 18000, cur: "XOF", eur: 27, remaining: 8, desc: "Accès conférence, networking exclusif, cocktail dînatoire raffiné et catalogue d'art." },
      { type: "vip", name: "Pass VIP Bâtisseur", price: 38000, cur: "XOF", eur: 58, remaining: 5, desc: "Accès salon VIP, dîner assis avec les conférenciers, mention dans l'annuaire d'honneur." },
      { type: "table_prestige", name: "Table Entreprise Partenaire (6 pers.)", price: 110000, cur: "XOF", eur: 168, remaining: 2, desc: "Table réservée au nom de votre entreprise, projection du logo, 6 accès VIP complets." }
    ],
    highlights: ["Conférence & Networking B2B", "Exposition & Enchères Kàakpi", "Cocktail dînatoire raffiné", "Annuaire des Bâtisseurs"]
  }
];

function generateBookingRef(): string {
  const now = new Date();
  const yr = String(now.getFullYear()).slice(-2);
  const mo = String(now.getMonth() + 1).padStart(2, "0");
  // 128-bit cryptographic entropy (16 bytes = 32 hexadecimal characters).
  // Uniqueness is guaranteed by the UNIQUE constraint on booking_ref.
  const rand128 = crypto.randomBytes(16).toString("hex").toUpperCase();
  return `RES-${yr}${mo}-${rand128.slice(0, 8)}-${rand128.slice(8, 16)}-${rand128.slice(16, 24)}-${rand128.slice(24, 32)}`;
}

// ==========================================
// RATE LIMITING (Netlify Database, atomic counter)
// ==========================================
// One row per (bucket, client) in "rate_limits". Each request performs a single
// INSERT ... ON CONFLICT DO UPDATE ... RETURNING statement: Postgres locks the
// row for the duration of the statement, so concurrent requests - on any number
// of function instances - are counted exactly and can never exceed the limit.
// The window starts at the first request and uses the database clock.
// If the database is unreachable, a per-instance in-memory counter is used:
// this is a DEGRADED mode that only limits traffic hitting the same instance
// (the protected endpoints themselves need the database anyway).
const MEMORY_RATE: Map<string, { count: number; resetAt: number }> = new Map();
let rateLimitBackend: "database" | "memory-degraded" = "database";

function memoryRateLimit(key: string, limit: number, windowMs: number): boolean {
  const now = Date.now();
  const entry = MEMORY_RATE.get(key);
  if (!entry || now > entry.resetAt) {
    MEMORY_RATE.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }
  if (entry.count >= limit) return false;
  entry.count++;
  return true;
}

async function checkRateLimit(bucket: string, id: string, limit: number, windowMs: number): Promise<boolean> {
  const key = `${bucket}/${String(id).replace(/[^a-zA-Z0-9_.:-]/g, "_").slice(0, 80)}`;
  const ms = Math.max(1000, Math.floor(windowMs));
  try {
    const r: any = await db.execute(sql`
      INSERT INTO rate_limits (key, hits, window_end)
      VALUES (${key}, 1, now() + (${ms}::int * interval '1 millisecond'))
      ON CONFLICT (key) DO UPDATE SET
        hits = CASE WHEN rate_limits.window_end <= now() THEN 1 ELSE rate_limits.hits + 1 END,
        window_end = CASE WHEN rate_limits.window_end <= now() THEN EXCLUDED.window_end ELSE rate_limits.window_end END
      RETURNING hits
    `);
    const row = (r.rows || r)[0];
    rateLimitBackend = "database";
    return Number(row?.hits) <= limit;
  } catch (err) {
    if (rateLimitBackend !== "memory-degraded") {
      console.warn("Rate limiter: database unavailable, using per-instance memory fallback (degraded).");
    }
    rateLimitBackend = "memory-degraded";
    return memoryRateLimit(key, limit, windowMs);
  }
}

function maskGuestName(name: string): string {
  const parts = String(name || "").trim().split(/\s+/);
  if (parts.length === 0 || !parts[0]) return "Convive";
  if (parts.length === 1) {
    const first = parts[0];
    return first.length > 2 ? first.slice(0, 2) + "***" : first + "***";
  }
  return parts[0] + " " + parts.slice(1).map((p) => p.charAt(0) + ".").join(" ");
}

// ==========================================
// RESERVATIONS & PAYMENTS
// ==========================================
// A reservation is NEVER marked paid by the browser or at creation time. It is
// created as "pending_payment" and only moves to "paid" when the payment
// provider sends a notification whose signature, amount and currency have been
// verified by this server.

const PAYMENT_METHODS = ["stripe", "paypal", "mobile_money", "on_site"];
// Delay to pay before a pending reservation expires.
const PAYMENT_WINDOW_MS: Record<string, number> = {
  stripe: 60 * 60 * 1000, // aligned with the Stripe Checkout session lifetime
  paypal: 72 * 60 * 60 * 1000,
  mobile_money: 72 * 60 * 60 * 1000,
  on_site: 72 * 60 * 60 * 1000,
};

function getStripeSecretKey(): string | null {
  const k = process.env.STRIPE_SECRET_KEY;
  return k && k.trim() ? k.trim() : null;
}
function getStripeWebhookSecret(): string | null {
  const k = process.env.STRIPE_WEBHOOK_SECRET;
  return k && k.trim() ? k.trim() : null;
}

function siteOrigin(c): string {
  const configured = process.env.URL_OVERRIDE || "";
  if (configured) return configured.replace(/\/$/, "");
  try { return new URL(c.req.url).origin; } catch { return "https://bassarkaakpi.com"; }
}

// Creates a Stripe Checkout Session with the amount computed by the server.
// Uses the Stripe REST API directly (no SDK dependency).
async function createStripeCheckout(c, r: any, event: any, ticket: any): Promise<{ id: string; url: string } | null> {
  const key = getStripeSecretKey();
  if (!key) return null;
  const origin = siteOrigin(c);
  const form = new URLSearchParams();
  form.set("mode", "payment");
  form.set("client_reference_id", r.bookingRef);
  form.set("metadata[booking_ref]", r.bookingRef);
  form.set("payment_intent_data[metadata][booking_ref]", r.bookingRef);
  form.set("customer_email", r.email);
  form.set("line_items[0][quantity]", String(r.placesCount));
  form.set("line_items[0][price_data][currency]", "xof"); // XOF is a zero-decimal currency in Stripe
  form.set("line_items[0][price_data][unit_amount]", String(r.unitPrice));
  form.set("line_items[0][price_data][product_data][name]", `${event.title} — ${ticket.name || ticket.type}`.slice(0, 250));
  form.set("expires_at", String(Math.floor((Date.now() + PAYMENT_WINDOW_MS.stripe) / 1000)));
  form.set("success_url", `${origin}/evenements-reservations.html?booking=${encodeURIComponent(r.bookingRef)}&payment=return`);
  form.set("cancel_url", `${origin}/evenements-reservations.html?booking=${encodeURIComponent(r.bookingRef)}&payment=cancel`);
  try {
    const res = await fetch("https://api.stripe.com/v1/checkout/sessions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/x-www-form-urlencoded",
        "Idempotency-Key": `checkout-${r.bookingRef}`,
      },
      body: form.toString(),
    });
    const data: any = await res.json();
    if (!res.ok || !data.id || !data.url) {
      console.error("Stripe checkout creation failed:", res.status, data?.error?.type || "unknown");
      return null;
    }
    return { id: data.id, url: data.url };
  } catch (err) {
    console.error("Stripe checkout creation error");
    return null;
  }
}

// Stripe signature: header "t=<ts>,v1=<hex>[,v1=...]", HMAC-SHA256 of "<ts>.<raw body>".
function verifyStripeSignature(rawBody: string, header: string | undefined, secret: string, toleranceS = 300): boolean {
  if (!header) return false;
  let ts = "";
  const sigs: string[] = [];
  for (const part of header.split(",")) {
    const [k, v] = part.split("=", 2).map((x) => (x || "").trim());
    if (k === "t") ts = v;
    if (k === "v1" && v) sigs.push(v);
  }
  if (!/^\d+$/.test(ts) || sigs.length === 0) return false;
  if (Math.abs(Math.floor(Date.now() / 1000) - Number(ts)) > toleranceS) return false;
  const expected = crypto.createHmac("sha256", secret).update(`${ts}.${rawBody}`, "utf8").digest();
  return sigs.some((sig) => {
    if (!/^[0-9a-f]+$/i.test(sig) || sig.length !== expected.length * 2) return false;
    return crypto.timingSafeEqual(Buffer.from(sig, "hex"), expected);
  });
}

// Marks pending reservations whose payment window has elapsed as expired.
async function expireOverdueReservations(): Promise<number> {
  const rows = await db
    .update(eventReservations)
    .set({ status: "expired", updatedAt: new Date() })
    .where(and(eq(eventReservations.status, "pending_payment"), lt(eventReservations.expiresAt, new Date())))
    .returning({ id: eventReservations.id });
  return rows.length;
}

// Get events list with calendar dates
app.get("/events", (c) => {
  return c.json({ events: GALA_EVENTS });
});

// Create event reservation (always pending until a verified payment notification)
app.post("/reservations", async (c) => {
  try {
    if (!(await checkRateLimit("reservation-create", getClientIp(c), 10, 60 * 60 * 1000))) {
      return c.json({ error: "Trop de réservations depuis cette connexion. Veuillez réessayer plus tard." }, 429);
    }

    const body = await c.req.json();
    const {
      eventSlug,
      guestName,
      email,
      phone,
      ticketType = "standard",
      placesCount = 1,
      paymentMethod = "stripe",
      dietaryRequests = "",
      specialRequests = "",
    } = body;

    if (!eventSlug || !guestName || !email || !phone) {
      return c.json({ error: "Événement, nom, e-mail et téléphone sont obligatoires." }, 400);
    }
    const cleanEmail = String(email).trim().toLowerCase();
    if (!/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(cleanEmail) || cleanEmail.length > 200) {
      return c.json({ error: "Adresse e-mail invalide." }, 400);
    }

    const event = GALA_EVENTS.find((e) => e.slug === eventSlug);
    if (!event) {
      return c.json({ error: "Événement sélectionné introuvable." }, 404);
    }

    const ticket = event.tickets.find((t) => t.type === ticketType) || event.tickets[0];
    const qty = Math.min(20, Math.max(1, parseInt(String(placesCount), 10) || 1));
    const unitPrice = ticket.price;
    const totalAmount = unitPrice * qty;
    const method = PAYMENT_METHODS.includes(paymentMethod) ? paymentMethod : "stripe";

    let inserted: any = null;
    for (let attempt = 0; attempt < 3 && !inserted; attempt++) {
      try {
        [inserted] = await db
          .insert(eventReservations)
          .values({
            bookingRef: generateBookingRef(),
            eventSlug: event.slug,
            eventTitle: event.title,
            eventDate: event.date,
            guestName: sanitizeText(guestName, 100),
            email: cleanEmail,
            phone: String(phone).replace(/[^\d+]/g, "").slice(0, 20),
            ticketType: ticket.type,
            placesCount: qty,
            unitPrice,
            totalAmount,
            currency: "XOF",
            paymentMethod: method,
            paymentStatus: "pending",
            status: "pending_payment",
            expiresAt: new Date(Date.now() + PAYMENT_WINDOW_MS[method]),
            dietaryRequests: dietaryRequests ? sanitizeText(dietaryRequests, 500) : "",
            specialRequests: specialRequests ? sanitizeText(specialRequests, 500) : "",
          })
          .returning();
      } catch (dbErr: any) {
        // 23505 = unique_violation on booking_ref (astronomically unlikely): retry with a new reference
        if (dbErr?.code === "23505" || dbErr?.cause?.code === "23505") continue;
        console.error("Reservation insert failed:", dbErr?.code || dbErr?.cause?.code || "unknown");
        // No fake reservation: the guest is told the booking was NOT registered.
        return c.json({ error: "La réservation n'a pas pu être enregistrée. Aucun paiement n'a été demandé. Veuillez réessayer." }, 503);
      }
    }
    if (!inserted) {
      return c.json({ error: "La réservation n'a pas pu être enregistrée. Veuillez réessayer." }, 503);
    }

    let checkoutUrl: string | null = null;
    if (method === "stripe") {
      const session = await createStripeCheckout(c, inserted, event, ticket);
      if (session) {
        await db
          .update(eventReservations)
          .set({ providerSessionId: session.id, paymentProvider: "stripe", updatedAt: new Date() })
          .where(eq(eventReservations.id, inserted.id));
        checkoutUrl = session.url;
      }
    }

    const { email: _e, phone: _p, ...publicRes } = inserted;
    return c.json(
      {
        success: true,
        reservation: { ...publicRes, guestName: inserted.guestName },
        event,
        ticket,
        bookingRef: inserted.bookingRef,
        status: "pending_payment",
        // Online payment is only offered when a verifiable checkout exists.
        checkoutUrl,
        onlinePaymentAvailable: Boolean(checkoutUrl),
        paymentInstructions:
          method === "mobile_money"
            ? "Règlement Mobile Money (T-Money / Flooz Togo) au +228 92 90 00 00. Indiquez la référence " + inserted.bookingRef + " en libellé. La réservation reste en attente jusqu'à vérification du paiement."
            : null,
        message: "Votre réservation est enregistrée et en attente de paiement. Elle sera validée après confirmation du paiement par le prestataire.",
      },
      201
    );
  } catch (error) {
    console.error("Create reservation error");
    return c.json({ error: "Erreur lors de la réservation." }, 500);
  }
});

// Stripe webhook: the only path that can mark a reservation as paid.
app.post("/payments/stripe/webhook", async (c) => {
  const secret = getStripeWebhookSecret();
  if (!secret) {
    return c.json({ error: "Webhook Stripe non configuré." }, 503);
  }
  const raw = await c.req.text();
  if (!verifyStripeSignature(raw, c.req.header("stripe-signature"), secret)) {
    return c.json({ error: "Signature invalide." }, 400);
  }

  let evt: any;
  try { evt = JSON.parse(raw); } catch { return c.json({ error: "Corps invalide." }, 400); }
  if (!evt || typeof evt.id !== "string" || typeof evt.type !== "string") {
    return c.json({ error: "Événement invalide." }, 400);
  }

  const obj = evt.data?.object || {};
  const bookingRef: string | null = obj.metadata?.booking_ref || obj.client_reference_id || null;

  // Idempotency: a notification resent by Stripe is recorded only once.
  const [logged] = await db
    .insert(paymentEvents)
    .values({ provider: "stripe", eventId: evt.id, eventType: evt.type, bookingRef })
    .onConflictDoNothing()
    .returning({ id: paymentEvents.id });
  if (!logged) {
    return c.json({ received: true, duplicate: true });
  }

  let outcome = "ignored";
  try {
    if (!bookingRef) {
      outcome = "no_booking_ref";
    } else if (evt.type === "checkout.session.completed" || evt.type === "checkout.session.async_payment_succeeded") {
      const [r] = await db.select().from(eventReservations).where(eq(eventReservations.bookingRef, bookingRef)).limit(1);
      if (!r) {
        outcome = "unknown_reservation";
      } else if (obj.payment_status !== "paid") {
        outcome = "awaiting_async_payment"; // e.g. bank debit in progress: stays pending
      } else if (r.providerSessionId && r.providerSessionId !== obj.id) {
        outcome = "session_mismatch";
      } else if (Number(obj.amount_total) !== Number(r.totalAmount) || String(obj.currency).toLowerCase() !== String(r.currency).toLowerCase()) {
        outcome = "amount_mismatch"; // never mark paid if the amount differs
      } else {
        const paymentId = typeof obj.payment_intent === "string" ? obj.payment_intent : obj.id;
        if (r.status === "paid" || r.status === "confirmed") {
          outcome = r.providerPaymentId === paymentId ? "already_applied" : "duplicate_payment_needs_refund_review";
        } else {
          const [usedElsewhere] = await db
            .select({ id: eventReservations.id })
            .from(eventReservations)
            .where(eq(eventReservations.providerPaymentId, paymentId))
            .limit(1);
          if (usedElsewhere && usedElsewhere.id !== r.id) {
            outcome = "payment_id_already_used_on_other_booking"; // never applied twice (UNIQUE constraint)
          } else {
          const updated = await db
            .update(eventReservations)
            .set({
              status: "paid",
              paymentStatus: "paid",
              paymentProvider: "stripe",
              providerSessionId: obj.id,
              providerPaymentId: paymentId,
              amountPaid: Number(obj.amount_total),
              paidAt: new Date(),
              updatedAt: new Date(),
            })
            .where(and(eq(eventReservations.id, r.id), inArray(eventReservations.status, ["pending_payment", "expired", "failed"])))
            .returning({ id: eventReservations.id });
          outcome = updated.length ? (r.status === "pending_payment" ? "marked_paid" : `marked_paid_after_${r.status}`) : "concurrent_update";
          }
        }
      }
    } else if (evt.type === "checkout.session.async_payment_failed") {
      const u = await db
        .update(eventReservations)
        .set({ status: "failed", paymentStatus: "failed", updatedAt: new Date() })
        .where(and(eq(eventReservations.bookingRef, bookingRef), eq(eventReservations.status, "pending_payment")))
        .returning({ id: eventReservations.id });
      outcome = u.length ? "marked_failed" : "no_change";
    } else if (evt.type === "checkout.session.expired") {
      const u = await db
        .update(eventReservations)
        .set({ status: "expired", updatedAt: new Date() })
        .where(and(eq(eventReservations.bookingRef, bookingRef), eq(eventReservations.status, "pending_payment")))
        .returning({ id: eventReservations.id });
      outcome = u.length ? "marked_expired" : "no_change";
    }
  } catch (err: any) {
    const code = err?.code || err?.cause?.code;
    // A unique violation means the payment id is already attached elsewhere:
    // definitive refusal, no retry needed.
    outcome = code === "23505" ? "payment_id_conflict" : "processing_error";
    console.error("Stripe webhook processing error");
  }

  await db.update(paymentEvents).set({ outcome }).where(eq(paymentEvents.id, logged.id));
  if (outcome === "processing_error") {
    // Let Stripe retry; remove the log entry so the retry is processed.
    await db.delete(paymentEvents).where(eq(paymentEvents.id, logged.id));
    return c.json({ error: "Traitement impossible, nouvelle tentative attendue." }, 500);
  }
  return c.json({ received: true, outcome });
});

// Lookup reservation by booking reference (with anti-enumeration and data protection)
app.get("/reservations/:ref", async (c) => {
  try {
    if (!(await checkRateLimit("reservation-lookup", getClientIp(c), 20, 60 * 1000))) {
      return c.json({ error: "Trop de requêtes. Veuillez patienter avant de réessayer." }, 429);
    }

    const ref = String(c.req.param("ref") || "").trim().toUpperCase();
    if (!/^RES-\d{4}-[0-9A-F]{8}(-[0-9A-F]{8}){3}$/.test(ref)) {
      return c.json({ error: "Réservation introuvable." }, 404);
    }
    const emailQuery = c.req.query("email") ? String(c.req.query("email")).trim().toLowerCase() : null;

    let [res] = await db.select().from(eventReservations).where(eq(eventReservations.bookingRef, ref)).limit(1);
    if (!res) {
      return c.json({ error: "Réservation introuvable." }, 404);
    }

    // Lazy expiry (also done hourly by the scheduled function)
    if (res.status === "pending_payment" && res.expiresAt && new Date(res.expiresAt).getTime() < Date.now()) {
      const [u] = await db
        .update(eventReservations)
        .set({ status: "expired", updatedAt: new Date() })
        .where(and(eq(eventReservations.id, res.id), eq(eventReservations.status, "pending_payment")))
        .returning();
      if (u) res = u;
    }

    // Rows created before the payment lifecycle carry status "confirmed" without
    // any verified payment: they are reported as awaiting payment verification.
    const paymentVerified = Boolean(res.paidAt && res.providerPaymentId);
    const displayStatus = res.status === "confirmed" && !paymentVerified ? "pending_payment" : res.status;
    const displayPayment = paymentVerified ? "paid" : res.paymentStatus === "failed" ? "failed" : "pending";

    const event = GALA_EVENTS.find((e) => e.slug === res.eventSlug) || GALA_EVENTS[0];
    const isEmailVerified = Boolean(emailQuery && res.email && emailQuery === res.email.toLowerCase());

    const base = {
      bookingRef: res.bookingRef,
      eventSlug: res.eventSlug,
      eventTitle: res.eventTitle,
      eventDate: res.eventDate,
      ticketType: res.ticketType,
      placesCount: res.placesCount,
      status: displayStatus,
      paymentStatus: displayPayment,
      paymentVerified,
    };

    if (isEmailVerified) {
      return c.json({
        reservation: {
          ...base,
          guestName: res.guestName,
          totalAmount: res.totalAmount,
          currency: res.currency,
          paymentMethod: res.paymentMethod,
          expiresAt: res.expiresAt,
          dietaryRequests: res.dietaryRequests,
          specialRequests: res.specialRequests,
          createdAt: res.createdAt,
        },
        event,
        verified: true,
      });
    }

    // Default public view: masked name, NEVER email, phone or dietary/special requests
    return c.json({ reservation: { ...base, guestName: maskGuestName(res.guestName) }, event, verified: false });
  } catch (error) {
    console.error("Lookup reservation error");
    return c.json({ error: "Erreur lors de la recherche." }, 500);
  }
});

// Configuration health check: booleans only, never any value.
app.get("/health", async (c) => {
  const checks: Record<string, boolean | string> = {
    jwtSecretConfigured: Boolean(getJwtSecret()),
    stripeSecretConfigured: Boolean(getStripeSecretKey()),
    stripeWebhookSecretConfigured: Boolean(getStripeWebhookSecret()),
    database: false,
    bookingRefUnique: false,
    paymentEventsIdempotency: false,
    rateLimitStore: false,
  };
  try {
    const r: any = await db.execute(sql`
      SELECT
        EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'event_reservations_booking_ref_key' AND contype = 'u') AS booking_unique,
        EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'payment_events_provider_event_id_key' AND contype = 'u') AS events_unique
    `);
    const row = (r.rows || r)[0] || {};
    checks.database = true;
    checks.bookingRefUnique = row.booking_unique === true;
    checks.paymentEventsIdempotency = row.events_unique === true;
  } catch {}
  try {
    const r: any = await db.execute(sql`SELECT to_regclass('public.rate_limits') IS NOT NULL AS ok`);
    checks.rateLimitStore = (r.rows || r)[0]?.ok === true;
  } catch {}
  checks.rateLimitBackend = checks.rateLimitStore ? "database" : "memory-degraded";
  const ok = checks.jwtSecretConfigured && checks.database && checks.bookingRefUnique && checks.rateLimitStore;
  return c.json({ status: ok ? "ok" : "degraded", checks }, ok ? 200 : 503);
});

// Netlify Functions v2 handler
export default async (req: Request) => {
  return app.fetch(req);
};

export const config = {
  path: "/api/*",
};
