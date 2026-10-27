import { createClient } from 'npm:@supabase/supabase-js@2'

const DAILY_LIMIT = 20
const usage = new Map<string, { day: string; count: number }>()

Deno.serve(async (req) => {
  const supabase = createClient(
    Deno.env.get('SUPABASE_URL')!,
    Deno.env.get('SUPABASE_ANON_KEY')!,
    { global: { headers: { Authorization: req.headers.get('Authorization') ?? '' } } },
  )
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) return new Response('Unauthorized', { status: 401 })

  const today = new Date().toISOString().slice(0, 10)
  const entry = usage.get(user.id)
  const count = entry && entry.day === today ? entry.count : 0
  if (count >= DAILY_LIMIT) return new Response('Rate limit exceeded', { status: 429 })
  usage.set(user.id, { day: today, count: count + 1 })

  const { name, species } = await req.json()

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
