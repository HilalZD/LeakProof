import { supabase } from "../lib/supabase";

export default function Account({ user }) {
  // ✅ Rule 5: users can get a copy of their data
  async function downloadMyData() {
    const res = await fetch("/api/export-data");
    const blob = await res.blob();
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "my-fittrack-data.json";
    link.click();
  }

  // ✅ Rule 4: users can delete their account
  async function deleteAccount() {
    if (!window.confirm("Delete your account and all your data? This cannot be undone.")) return;
    await supabase.functions.invoke("delete-account");
    await supabase.auth.signOut();
  }

  return (
    <div>
      <h1>My account</h1>
      <p>{user.email}</p>
      <button onClick={downloadMyData}>Download my data</button>
      <button onClick={deleteAccount}>Delete my account</button>
      <button onClick={() => supabase.auth.signOut()}>Log out</button>
    </div>
  );
}
