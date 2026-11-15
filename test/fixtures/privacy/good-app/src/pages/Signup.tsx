import { useState } from "react";
import { supabase } from "../lib/supabase";
import posthog from "posthog-js";

export default function Signup() {
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [phone, setPhone] = useState("");
  const [password, setPassword] = useState("");

  async function handleSubmit(e) {
    e.preventDefault();
    await supabase.auth.signUp({
      email,
      password,
      options: { data: { full_name: fullName, phone } },
    });

    // ✅ Rule 6: the log message contains no personal data
    console.log("Signup complete");

    // ✅ Rule 3: only an event name goes to analytics, no personal data
    posthog.capture("signed_up");
  }

  return (
    <form onSubmit={handleSubmit}>
      <input name="full_name" placeholder="Full name" value={fullName} onChange={(e) => setFullName(e.target.value)} />
      <input type="email" name="email" placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)} />
      <input type="tel" name="phone" placeholder="Phone" value={phone} onChange={(e) => setPhone(e.target.value)} />
      <input type="password" name="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} />
      {/* ✅ Rule 1: link to the privacy policy */}
      <p>
        By signing up you agree to our <a href="/privacy">Privacy Policy</a>.
      </p>
      <button type="submit">Create account</button>
    </form>
  );
}
