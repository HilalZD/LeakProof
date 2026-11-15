import { useState } from "react";
import { supabase } from "../lib/supabase";
import posthog from "../lib/analytics";

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

    // Rule 6: prints the user's email and phone number to the logs
    console.log("New signup:", email, phone);

    // Rule 3: sends the user's email and name to an analytics company
    posthog.identify(email, { name: fullName });
  }

  return (
    <form onSubmit={handleSubmit}>
      <input name="full_name" placeholder="Full name" value={fullName} onChange={(e) => setFullName(e.target.value)} />
      <input type="email" name="email" placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)} />
      <input type="tel" name="phone" placeholder="Phone" value={phone} onChange={(e) => setPhone(e.target.value)} />
      <input type="password" name="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} />
      <button type="submit">Create account</button>
    </form>
  );
}
