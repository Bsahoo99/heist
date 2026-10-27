// HEIST-FIXTURE: m5 (no Authorization check before sending mail)
Deno.serve(async (req) => {
  const { to, subject, html } = await req.json()

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${Deno.env.get('RESEND_API_KEY')}`,
    },
    body: JSON.stringify({ from: 'hello@pawfinder.test', to, subject, html }),
  })

  return new Response(await res.text(), { status: res.status })
})
