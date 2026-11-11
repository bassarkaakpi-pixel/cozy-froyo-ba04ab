import { Hono } from "hono";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { eq, desc, and, sql } from "drizzle-orm";
import { db } from "../../db/index.js";
import { subscribers, listings } from "../../db/schema.js";

const app = new Hono().basePath("/api");

const JWT_SECRET = process.env.JWT_SECRET || "bassar-kaakpi-jwt-secret-2026-prod";
const COOKIE_NAME = "bk_subscriber_token";

// Helper: Authenticate subscriber from cookie or Bearer token
async function getAuthSubscriber(c) {
  try {
    const cookieToken = getCookie(c, COOKIE_NAME);
    const authHeader = c.req.header("Authorization");
    const bearerToken = authHeader && authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
    const token = cookieToken || bearerToken;

    if (!token) return null;

    const decoded = jwt.verify(token, JWT_SECRET) as { id: number; email: string };
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

    if (password.length < 6) {
      return c.json({ error: "Le mot de passe doit contenir au moins 6 caractères." }, 400);
    }

    const cleanEmail = String(email).trim().toLowerCase();

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
        fullName: String(fullName).trim(),
        businessName: businessName ? String(businessName).trim() : "",
        phone: String(phone).trim(),
        city: String(city).trim(),
        country: String(country).trim(),
        category,
        plan: ["free", "seller", "premium"].includes(plan) ? plan : "free",
        status: "active",
        isVerified: plan === "premium",
        bio: bio ? String(bio).trim() : "",
        website: website ? String(website).trim() : "",
        memberRef,
      })
      .returning();

    const token = jwt.sign({ id: newSub.id, email: newSub.email }, JWT_SECRET, {
      expiresIn: "30d",
    });

    setCookie(c, COOKIE_NAME, token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Lax",
      maxAge: 30 * 24 * 60 * 60,
    });

    const { passwordHash: _, ...safeUser } = newSub;
    return c.json({ success: true, subscriber: safeUser, token }, 201);
  } catch (error) {
    console.error("Register error:", error);
    return c.json({ error: "Erreur serveur lors de l'inscription." }, 500);
  }
});

// Login
app.post("/auth/login", async (c) => {
  try {
    const { email, password } = await c.req.json();
    if (!email || !password) {
      return c.json({ error: "E-mail et mot de passe requis." }, 400);
    }

    const cleanEmail = String(email).trim().toLowerCase();

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

    const token = jwt.sign({ id: subscriber.id, email: subscriber.email }, JWT_SECRET, {
      expiresIn: "30d",
    });

    setCookie(c, COOKIE_NAME, token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Lax",
      maxAge: 30 * 24 * 60 * 60,
    });

    const { passwordHash: _, ...safeUser } = subscriber;
    return c.json({ success: true, subscriber: safeUser, token });
  } catch (error) {
    console.error("Login error:", error);
    return c.json({ error: "Erreur serveur lors de la connexion." }, 500);
  }
});

// Current user profile
app.get("/auth/me", async (c) => {
  const subscriber = await getAuthSubscriber(c);
  if (!subscriber) {
    return c.json({ error: "Non connecté" }, 401);
  }
  return c.json({ subscriber });
});

// Logout
app.post("/auth/logout", (c) => {
  deleteCookie(c, COOKIE_NAME);
  return c.json({ success: true });
});

// Update profile
app.put("/auth/profile", async (c) => {
  const subscriber = await getAuthSubscriber(c);
  if (!subscriber) return c.json({ error: "Non connecté" }, 401);

  try {
    const body = await c.req.json();
    const { fullName, businessName, phone, city, country, category, bio, website, logoUrl } = body;

    const [updated] = await db
      .update(subscribers)
      .set({
        fullName: fullName ? String(fullName).trim() : subscriber.fullName,
        businessName: businessName !== undefined ? String(businessName).trim() : subscriber.businessName,
        phone: phone ? String(phone).trim() : subscriber.phone,
        city: city ? String(city).trim() : subscriber.city,
        country: country ? String(country).trim() : subscriber.country,
        category: category || subscriber.category,
        bio: bio !== undefined ? String(bio).trim() : subscriber.bio,
        website: website !== undefined ? String(website).trim() : subscriber.website,
        logoUrl: logoUrl !== undefined ? String(logoUrl).trim() : subscriber.logoUrl,
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
      if (count >= 1) {
        return c.json({
          error:
            "La formule Gratuite permet 1 annonce. Passez à la formule Vendeur (5 annonces) ou Premium pour publier davantage.",
        }, 403);
      }
    } else if (subscriber.plan === "seller") {
      const existingCount = await db
        .select({ count: sql`count(*)` })
        .from(listings)
        .where(eq(listings.subscriberId, subscriber.id));
      const count = Number(existingCount[0]?.count || 0);
      if (count >= 5) {
        return c.json({
          error: "La formule Vendeur permet jusqu'à 5 annonces. Passez à la formule Premium pour des annonces illimitées.",
        }, 403);
      }
    }

    const ref = generateListingRef();
    const parsedPrice = price !== null && price !== "" && !isNaN(Number(price)) ? Math.round(Number(price)) : null;

    const [newListing] = await db
      .insert(listings)
      .values({
        subscriberId: subscriber.id,
        ref,
        category: String(category).trim(),
        title: String(title).trim(),
        city: city ? String(city).trim() : subscriber.city,
        price: parsedPrice,
        currency: currency === "EUR" ? "EUR" : "XOF",
        description: String(description).trim(),
        imageUrl: imageUrl ? String(imageUrl).trim() : "",
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

    const parsedPrice = price !== null && price !== "" && !isNaN(Number(price)) ? Math.round(Number(price)) : null;

    const [updated] = await db
      .update(listings)
      .set({
        category: category || existing.category,
        title: title ? String(title).trim() : existing.title,
        city: city ? String(city).trim() : existing.city,
        price: parsedPrice !== undefined ? parsedPrice : existing.price,
        currency: currency || existing.currency,
        description: description ? String(description).trim() : existing.description,
        imageUrl: imageUrl !== undefined ? String(imageUrl).trim() : existing.imageUrl,
        status: status || existing.status,
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
      .where(condition)
      .limit(1);

    if (!member) {
      return c.json({ error: "Profil membre introuvable." }, 404);
    }

    const memberListings = await db
      .select()
      .from(listings)
      .where(and(eq(listings.subscriberId, member.id), eq(listings.status, "active")))
      .orderBy(desc(listings.isFeatured), desc(listings.createdAt));

    return c.json({ member, listings: memberListings });
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
      .where(condition)
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

// Netlify Functions v2 handler
export default async (req: Request) => {
  return app.fetch(req);
};

export const config = {
  path: "/api/*",
};
