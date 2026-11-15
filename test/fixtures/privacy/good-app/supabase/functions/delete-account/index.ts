import { createClient } from "npm:@supabase/supabase-js@2";

// ✅ Rule 4: deletes the signed-in person's account (runs on the server, never in the browser)
Deno.serve(async (req) => {
  const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
  const token = req.headers.get("Authorization")!.replace("Bearer ", "");
  const { data } = await admin.auth.getUser(token);
  await admin.auth.admin.deleteUser(data.user!.id);
  return new Response(JSON.stringify({ ok: true }), { headers: { "Content-Type": "application/json" } });
});
