// ✅ Rule 3: the browser sends only the goal to our own server, never to OpenAI directly
export async function askCoach(goal) {
  const res = await fetch("/api/coach", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ goal }),
  });
  return res.json();
}
