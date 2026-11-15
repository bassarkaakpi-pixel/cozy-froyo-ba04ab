import { pgTable, serial, text, timestamp, integer, boolean, check, unique, index } from "drizzle-orm/pg-core";
import { sql } from "drizzle-orm";

export const subscribers = pgTable("subscribers", {
  id: serial().primaryKey(),
  email: text("email").notNull().unique(),
  passwordHash: text("password_hash").notNull(),
  fullName: text("full_name").notNull(),
  businessName: text("business_name").default(""),
  phone: text("phone").notNull(),
  city: text("city").notNull(),
  country: text("country").notNull().default("Togo"),
  category: text("category").notNull().default("trade"),
  plan: text("plan").notNull().default("free"),
  status: text("status").notNull().default("active"),
  isVerified: boolean("is_verified").notNull().default(false),
  bio: text("bio").default(""),
  website: text("website").default(""),
  logoUrl: text("logo_url").default(""),
  memberRef: text("member_ref").notNull().unique(),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const listings = pgTable("listings", {
  id: serial().primaryKey(),
  subscriberId: integer("subscriber_id")
    .notNull()
    .references(() => subscribers.id, { onDelete: "cascade" }),
  ref: text("ref").notNull().unique(),
  category: text("category").notNull(),
  title: text("title").notNull(),
  city: text("city").notNull(),
  price: integer("price"),
  currency: text("currency").notNull().default("XOF"),
  description: text("description").notNull(),
  imageUrl: text("image_url").default(""),
  status: text("status").notNull().default("active"),
  isFeatured: boolean("is_featured").notNull().default(false),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const culturalPublications = pgTable("cultural_publications", {
  id: serial().primaryKey(),
  title: text("title").notNull(),
  continent: text("continent").notNull().default("Afrique"),
  country: text("country").notNull(),
  countryCode: text("country_code").notNull(),
  flagEmoji: text("flag_emoji").notNull(),
  category: text("category").notNull(),
  summary: text("summary").notNull(),
  content: text("content").notNull(),
  authorName: text("author_name").default("Communauté Bassar Kàakpi"),
  imageUrl: text("image_url").default(""),
  videoUrl: text("video_url").default(""),
  tags: text("tags").default(""),
  likesCount: integer("likes_count").default(0),
  status: text("status").notNull().default("published"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// Reservation lifecycle (column "status"):
//   pending_payment -> paid       payment verified server-side by the provider (signed webhook)
//   paid            -> confirmed  place confirmed by the organiser (administration, upcoming)
//   pending_payment -> failed     provider reported a failed payment
//   pending_payment -> expired    no verified payment before expires_at
//   any non-final   -> cancelled  cancelled by the organiser or the guest
// "confirmed" is kept as an accepted value for rows created before this model.
export const RESERVATION_STATUSES = ["pending_payment", "paid", "confirmed", "failed", "cancelled", "expired"] as const;

export const eventReservations = pgTable(
  "event_reservations",
  {
    id: serial().primaryKey(),
    bookingRef: text("booking_ref").notNull().unique(),
    eventSlug: text("event_slug").notNull(),
    eventTitle: text("event_title").notNull(),
    eventDate: text("event_date").notNull(),
    guestName: text("guest_name").notNull(),
    email: text("email").notNull(),
    phone: text("phone").notNull(),
    ticketType: text("ticket_type").notNull().default("standard"),
    placesCount: integer("places_count").notNull().default(1),
    unitPrice: integer("unit_price").notNull().default(0),
    totalAmount: integer("total_amount").notNull().default(0),
    currency: text("currency").notNull().default("XOF"),
    paymentMethod: text("payment_method").notNull().default("stripe"),
    paymentStatus: text("payment_status").notNull().default("pending"),
    dietaryRequests: text("dietary_requests").default(""),
    specialRequests: text("special_requests").default(""),
    status: text("status").notNull().default("pending_payment"),
    // Payment verification (filled only from a verified provider notification)
    paymentProvider: text("payment_provider"),
    providerSessionId: text("provider_session_id").unique(),
    providerPaymentId: text("provider_payment_id").unique(),
    amountPaid: integer("amount_paid"),
    paidAt: timestamp("paid_at", { withTimezone: true }),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow(),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (t) => [
    check(
      "event_reservations_status_check",
      sql`${t.status} IN ('pending_payment', 'paid', 'confirmed', 'failed', 'cancelled', 'expired')`
    ),
    check(
      "event_reservations_payment_status_check",
      sql`${t.paymentStatus} IN ('pending', 'paid', 'failed', 'refunded', 'confirmed')`
    ),
    index("event_reservations_pending_expiry_idx").on(t.status, t.expiresAt),
  ]
);

// Every provider notification is recorded once: the (provider, event_id) unique
// constraint makes webhook processing idempotent when a notification is resent.
export const paymentEvents = pgTable(
  "payment_events",
  {
    id: serial().primaryKey(),
    provider: text("provider").notNull(),
    eventId: text("event_id").notNull(),
    eventType: text("event_type").notNull(),
    bookingRef: text("booking_ref"),
    outcome: text("outcome").notNull().default("received"),
    receivedAt: timestamp("received_at", { withTimezone: true }).defaultNow(),
  },
  (t) => [unique("payment_events_provider_event_id_key").on(t.provider, t.eventId)]
);

// Rate limiting counters. One row per (bucket, client). Incremented with a
// single atomic INSERT ... ON CONFLICT DO UPDATE, so concurrent requests on
// any number of function instances are counted exactly.
export const rateLimits = pgTable(
  "rate_limits",
  {
    key: text("key").primaryKey(),
    hits: integer("hits").notNull().default(0),
    windowEnd: timestamp("window_end", { withTimezone: true }).notNull(),
  },
  (t) => [index("rate_limits_window_end_idx").on(t.windowEnd)]
);
