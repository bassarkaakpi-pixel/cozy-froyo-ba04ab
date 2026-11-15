import type { Config } from "@netlify/functions";
import { and, eq, lt, sql } from "drizzle-orm";
import { db } from "../../db/index.js";
import { eventReservations } from "../../db/schema.js";

// Hourly maintenance.
// 1. Reservations still awaiting payment after their payment window become
//    "expired". Only rows in "pending_payment" are touched; paid, confirmed,
//    failed and cancelled reservations are never modified here.
// 2. Rate-limit counters whose window ended more than an hour ago are deleted.
export default async () => {
  const rows = await db
    .update(eventReservations)
    .set({ status: "expired", updatedAt: new Date() })
    .where(and(eq(eventReservations.status, "pending_payment"), lt(eventReservations.expiresAt, new Date())))
    .returning({ id: eventReservations.id });
  console.log(`expire-reservations: ${rows.length} reservation(s) expired`);

  const purged: any = await db.execute(sql`DELETE FROM rate_limits WHERE window_end < now() - interval '1 hour'`);
  console.log(`expire-reservations: ${purged.rowCount ?? 0} rate-limit counter(s) removed`);
};

export const config: Config = {
  schedule: "@hourly",
};
