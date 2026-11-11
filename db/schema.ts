import { pgTable, serial, text, timestamp, integer, boolean } from "drizzle-orm/pg-core";

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
