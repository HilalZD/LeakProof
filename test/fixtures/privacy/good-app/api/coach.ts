// ✅ Rule 3: only the workout goal reaches OpenAI, no name, email or weight
export default async function handler(req, res) {
  const { goal } = req.body;
  const response = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
    },
    body: JSON.stringify({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: `Suggest a workout plan for this goal: ${goal}` }],
    }),
  });
  res.json(await response.json());
}
