ALTER TABLE "cultural_publications" ADD COLUMN "continent" text DEFAULT 'Afrique' NOT NULL;--> statement-breakpoint
ALTER TABLE "cultural_publications" ADD COLUMN "video_url" text DEFAULT '';--> statement-breakpoint
ALTER TABLE "event_reservations" ADD COLUMN "payment_method" text DEFAULT 'stripe' NOT NULL;--> statement-breakpoint
ALTER TABLE "event_reservations" ADD COLUMN "payment_status" text DEFAULT 'pending' NOT NULL;