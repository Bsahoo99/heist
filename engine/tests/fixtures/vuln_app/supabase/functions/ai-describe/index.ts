Deno.serve(async (req) => {
  const { name, species } = await req.json()

  // HEIST-FIXTURE: m7 (no auth, no rate limit)
  const res = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${Deno.env.get('OPENAI_API_KEY')}`,
    },
    body: JSON.stringify({
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: `Write a short bio for a ${species} named ${name}.` }],
    }),
  })

  return new Response(await res.text(), { status: res.status })
})
