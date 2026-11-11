CREATE TABLE "listings" (
	"id" serial PRIMARY KEY,
	"subscriber_id" integer NOT NULL,
	"ref" text NOT NULL UNIQUE,
	"category" text NOT NULL,
	"title" text NOT NULL,
	"city" text NOT NULL,
	"price" integer,
	"currency" text DEFAULT 'XOF' NOT NULL,
	"description" text NOT NULL,
	"image_url" text DEFAULT '',
	"status" text DEFAULT 'active' NOT NULL,
	"is_featured" boolean DEFAULT false NOT NULL,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "subscribers" (
	"id" serial PRIMARY KEY,
	"email" text NOT NULL UNIQUE,
	"password_hash" text NOT NULL,
	"full_name" text NOT NULL,
	"business_name" text DEFAULT '',
	"phone" text NOT NULL,
	"city" text NOT NULL,
	"country" text DEFAULT 'Togo' NOT NULL,
	"category" text DEFAULT 'trade' NOT NULL,
	"plan" text DEFAULT 'free' NOT NULL,
	"status" text DEFAULT 'active' NOT NULL,
	"is_verified" boolean DEFAULT false NOT NULL,
	"bio" text DEFAULT '',
	"website" text DEFAULT '',
	"logo_url" text DEFAULT '',
	"member_ref" text NOT NULL UNIQUE,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
ALTER TABLE "listings" ADD CONSTRAINT "listings_subscriber_id_subscribers_id_fkey" FOREIGN KEY ("subscriber_id") REFERENCES "subscribers"("id") ON DELETE CASCADE;