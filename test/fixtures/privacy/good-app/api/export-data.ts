import { createClient } from "@supabase/supabase-js";

// ✅ Rule 5: returns everything we store about the signed-in person as a JSON file
export default async function handler(req, res) {
  const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY, {
    global: { headers: { Authorization: req.headers.authorization } },
  });
  const { data: profile } = await supabase.from("profiles").select("*").single();
  const { data: workouts } = await supabase.from("workouts").select("*");
  res.setHeader("Content-Disposition", "attachment; filename=my-fittrack-data.json");
  res.json({ profile, workouts });
}
