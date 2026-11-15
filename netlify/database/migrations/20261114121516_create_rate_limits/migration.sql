CREATE TABLE "rate_limits" (
	"key" text PRIMARY KEY,
	"hits" integer DEFAULT 0 NOT NULL,
	"window_end" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE INDEX "rate_limits_window_end_idx" ON "rate_limits" ("window_end");