import { Hono } from "hono";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { eq, desc, and, sql } from "drizzle-orm";
import { db } from "../../db/index.js";
import { subscribers, listings, culturalPublications, eventReservations } from "../../db/schema.js";

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
    title: "Le Tissu Kàakpi : L'étoffe royale des dignitaires et le savoir-faire des maîtres tisserands",
    continent: "Afrique",
    country: "Togo",
    countryCode: "TG",
    flagEmoji: "🇹🇬",
    category: "textile_attire",
    summary: "Tissé à la main sur des métiers traditionnels en bandes étroites, le Kàakpi incarne la dignité, la fierté et le prestige des grandes cérémonies.",
    content: "Le Kàakpi est bien plus qu'un textile : c'est un langage visuel et une armure symbolique de noblesse. Réalisé à partir de fils de coton pur filés à la main, teints avec des pigments végétaux et minéraux naturels, chaque rouleau de Kàakpi demande des semaines de travail minutieux. Les motifs géométriques rythmés racontent des proverbes, la lignée familiale et les victoires ancestrales. Porté lors des mariages coutumiers, intronisations de chefs traditionnels et grandes fêtes solennelles, le Kàakpi est aujourd'hui revisité par la haute couture contemporaine pour habiller les galas et événements prestigieux à travers le monde.",
    authorName: "Atelier des Maîtres Tisserands Kàakpi",
    imageUrl: "https://images.unsplash.com/photo-1607344645866-009c320c5ab8?auto=format&fit=crop&w=1200&q=80",
    videoUrl: "",
    tags: "Kàakpi, Tissage, Textile, Bassar, Togo, Haute Couture",
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
async function ensureCulturalPublications() {
  try {
    const existing = await db
      .select({ count: sql`count(*)` })
      .from(culturalPublications);
    const count = Number(existing[0]?.count || 0);
    if (count === 0) {
      await db.insert(culturalPublications).values(INITIAL_CULTURAL_PUBLICATIONS);
    }
  } catch (err) {
    console.error("Auto-seed cultural publications error:", err);
  }
}

// Get cultural publications (public with filters)
app.get("/cultural-publications", async (c) => {
  try {
    await ensureCulturalPublications();

    const continent = c.req.query("continent");
    const country = c.req.query("country");
    const category = c.req.query("category");
    const search = c.req.query("search");

    const posts = await db
      .select()
      .from(culturalPublications)
      .where(eq(culturalPublications.status, "published"))
      .orderBy(desc(culturalPublications.createdAt));

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
    return c.json({ publications: list });
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

    const finalAuthor = authorName || (subscriber ? (subscriber.businessName || subscriber.fullName) : "Membre de la Communauté");

    const [newPost] = await db
      .insert(culturalPublications)
      .values({
        title: String(title).trim(),
        continent: String(continent).trim(),
        country: String(country).trim(),
        countryCode: String(countryCode).trim().toUpperCase(),
        flagEmoji: String(flagEmoji).trim(),
        category: String(category).trim(),
        summary: String(summary).trim(),
        content: String(content).trim(),
        authorName: String(finalAuthor).trim(),
        imageUrl: imageUrl ? String(imageUrl).trim() : "",
        videoUrl: videoUrl ? String(videoUrl).trim() : "",
        tags: tags ? String(tags).trim() : "",
        status: "published",
        likesCount: 1,
      })
      .returning();

    return c.json({ success: true, publication: newPost }, 201);
  } catch (error) {
    console.error("Create cultural publication error:", error);
    return c.json({ error: "Erreur lors de l'enregistrement de la publication." }, 500);
  }
});

// Like a cultural publication
app.post("/cultural-publications/:id/like", async (c) => {
  try {
    const id = parseInt(c.req.param("id"), 10);
    const [existing] = await db
      .select()
      .from(culturalPublications)
      .where(eq(culturalPublications.id, id))
      .limit(1);

    if (!existing) {
      return c.json({ error: "Publication introuvable." }, 404);
    }

    const newLikes = (existing.likesCount || 0) + 1;
    await db
      .update(culturalPublications)
      .set({ likesCount: newLikes })
      .where(eq(culturalPublications.id, id));

    return c.json({ success: true, likesCount: newLikes });
  } catch (error) {
    console.error("Like error:", error);
    return c.json({ error: "Erreur lors du vote." }, 500);
  }
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

function generateBookingRef() {
  const now = new Date();
  const yr = String(now.getFullYear()).slice(-2);
  const mo = String(now.getMonth() + 1).padStart(2, "0");
  const rand = Math.floor(1000 + Math.random() * 9000);
  return `RES-${yr}${mo}-${rand}`;
}

// Get events list with calendar dates
app.get("/events", (c) => {
  return c.json({ events: GALA_EVENTS });
});

// Create event reservation
app.post("/reservations", async (c) => {
  try {
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
      return c.json(
        { error: "Événement, nom, e-mail et téléphone sont obligatoires." },
        400
      );
    }

    const event = GALA_EVENTS.find((e) => e.slug === eventSlug);
    if (!event) {
      return c.json({ error: "Événement sélectionné introuvable." }, 404);
    }

    const ticket = event.tickets.find((t) => t.type === ticketType) || event.tickets[0];
    const qty = Math.max(1, parseInt(String(placesCount), 10) || 1);
    const unitPrice = ticket.price;
    const totalAmount = unitPrice * qty;
    const bookingRef = generateBookingRef();

    const [newRes] = await db
      .insert(eventReservations)
      .values({
        bookingRef,
        eventSlug: event.slug,
        eventTitle: event.title,
        eventDate: event.date,
        guestName: String(guestName).trim(),
        email: String(email).trim().toLowerCase(),
        phone: String(phone).trim(),
        ticketType: ticket.type,
        placesCount: qty,
        unitPrice,
        totalAmount,
        currency: "XOF",
        paymentMethod: ["stripe", "paypal", "mobile_money", "on_site"].includes(paymentMethod) ? paymentMethod : "stripe",
        paymentStatus: "confirmed",
        dietaryRequests: dietaryRequests ? String(dietaryRequests).trim() : "",
        specialRequests: specialRequests ? String(specialRequests).trim() : "",
        status: "confirmed",
      })
      .returning();

    // Payment URLs
    const stripeUrl = "https://buy.stripe.com/aFa8wO23h0qifJq1uVf7i06";
    const paypalUrl = "https://www.paypal.com/webapps/billing/plans/subscribe?plan_id=P-6P2079447P973982BNLXFHYA";

    return c.json(
      {
        success: true,
        reservation: newRes,
        event,
        ticket,
        bookingRef,
        paymentUrl: paymentMethod === "paypal" ? paypalUrl : stripeUrl,
        paymentInstructions: paymentMethod === "mobile_money"
          ? "Règlement Mobile Money (T-Money / Flooz Togo) au +228 92 90 00 00. Indiquez la référence " + bookingRef + " en libellé."
          : null,
        message: "Votre réservation a été confirmée avec succès.",
      },
      201
    );
  } catch (error) {
    console.error("Create reservation error:", error);
    return c.json({ error: "Erreur lors de la réservation." }, 500);
  }
});

// Lookup reservation by booking reference
app.get("/reservations/:ref", async (c) => {
  try {
    const ref = c.req.param("ref");
    const [res] = await db
      .select()
      .from(eventReservations)
      .where(eq(eventReservations.bookingRef, ref))
      .limit(1);

    if (!res) {
      return c.json({ error: "Réservation introuvable." }, 404);
    }

    const event = GALA_EVENTS.find((e) => e.slug === res.eventSlug);
    return c.json({ reservation: res, event });
  } catch (error) {
    console.error("Lookup reservation error:", error);
    return c.json({ error: "Erreur lors de la recherche." }, 500);
  }
});

// Netlify Functions v2 handler
export default async (req: Request) => {
  return app.fetch(req);
};

export const config = {
  path: "/api/*",
};
