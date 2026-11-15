CREATE TABLE "payment_events" (
	"id" serial PRIMARY KEY,
	"provider" text NOT NULL,
	"event_id" text NOT NULL,
	"event_type" text NOT NULL,
	"booking_ref" text,
	"outcome" text DEFAULT 'received' NOT NULL,
	"received_at" timestamp with time zone DEFAULT now(),
	CONSTRAINT "payment_events_provider_event_id_key" UNIQUE("provider","event_id")
);
--> statement-breakpoint
ALTER TABLE "event_reservations" ADD COLUMN "payment_provider" text;--> statement-breakpoint
ALTER TABLE "event_reservations" ADD COLUMN "provider_session_id" text;--> statement-breakpoint
ALTER TABLE "event_reservations" ADD COLUMN "provider_payment_id" text;--> statement-breakpoint
ALTER TABLE "event_reservations" ADD COLUMN "amount_paid" integer;--> statement-breakpoint
ALTER TABLE "event_reservations" ADD COLUMN "paid_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "event_reservations" ADD COLUMN "expires_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "event_reservations" ADD COLUMN "updated_at" timestamp with time zone DEFAULT now();--> statement-breakpoint
ALTER TABLE "event_reservations" ALTER COLUMN "status" SET DEFAULT 'pending_payment';--> statement-breakpoint
ALTER TABLE "event_reservations" ADD CONSTRAINT "event_reservations_provider_session_id_key" UNIQUE("provider_session_id");--> statement-breakpoint
ALTER TABLE "event_reservations" ADD CONSTRAINT "event_reservations_provider_payment_id_key" UNIQUE("provider_payment_id");--> statement-breakpoint
CREATE INDEX "event_reservations_pending_expiry_idx" ON "event_reservations" ("status","expires_at");--> statement-breakpoint
ALTER TABLE "event_reservations" ADD CONSTRAINT "event_reservations_status_check" CHECK ("status" IN ('pending_payment', 'paid', 'confirmed', 'failed', 'cancelled', 'expired'));--> statement-breakpoint
ALTER TABLE "event_reservations" ADD CONSTRAINT "event_reservations_payment_status_check" CHECK ("payment_status" IN ('pending', 'paid', 'failed', 'refunded', 'confirmed'));