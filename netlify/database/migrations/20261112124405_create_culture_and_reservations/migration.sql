CREATE TABLE "cultural_publications" (
	"id" serial PRIMARY KEY,
	"title" text NOT NULL,
	"country" text NOT NULL,
	"country_code" text NOT NULL,
	"flag_emoji" text NOT NULL,
	"category" text NOT NULL,
	"summary" text NOT NULL,
	"content" text NOT NULL,
	"author_name" text DEFAULT 'Communauté Bassar Kàakpi',
	"image_url" text DEFAULT '',
	"tags" text DEFAULT '',
	"likes_count" integer DEFAULT 0,
	"status" text DEFAULT 'published' NOT NULL,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "event_reservations" (
	"id" serial PRIMARY KEY,
	"booking_ref" text NOT NULL UNIQUE,
	"event_slug" text NOT NULL,
	"event_title" text NOT NULL,
	"event_date" text NOT NULL,
	"guest_name" text NOT NULL,
	"email" text NOT NULL,
	"phone" text NOT NULL,
	"ticket_type" text DEFAULT 'standard' NOT NULL,
	"places_count" integer DEFAULT 1 NOT NULL,
	"unit_price" integer DEFAULT 0 NOT NULL,
	"total_amount" integer DEFAULT 0 NOT NULL,
	"currency" text DEFAULT 'XOF' NOT NULL,
	"dietary_requests" text DEFAULT '',
	"special_requests" text DEFAULT '',
	"status" text DEFAULT 'confirmed' NOT NULL,
	"created_at" timestamp DEFAULT now()
);
