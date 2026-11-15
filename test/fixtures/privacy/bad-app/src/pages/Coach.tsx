// Rule 3: sends the user's email and weight straight to OpenAI
export async function askCoach(user, goal) {
  const res = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model: "gpt-4o-mini",
      messages: [
        { role: "user", content: `Client ${user.email}, weight ${user.weight}kg, wants: ${goal}` },
      ],
    }),
  });
  return res.json();
}
