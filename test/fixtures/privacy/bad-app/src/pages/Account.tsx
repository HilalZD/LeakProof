import { supabase } from "../lib/supabase";

// Rules 4 and 5: on this page the user can only log out, nothing else
export default function Account({ user }) {
  return (
    <div>
      <h1>My account</h1>
      <p>{user.email}</p>
      <button onClick={() => supabase.auth.signOut()}>Log out</button>
    </div>
  );
}
