import { createClient } from 'npm:@supabase/supabase-js@2'

Deno.serve(async (req) => {
  const supabase = createClient(
    Deno.env.get('SUPABASE_URL')!,
    Deno.env.get('SUPABASE_ANON_KEY')!,
    { global: { headers: { Authorization: req.headers.get('Authorization') ?? '' } } },
  )
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) return new Response('Unauthorized', { status: 401 })

  const body = await req.json()

  const { error } = await supabase
    .from('adoption_requests')
    .update({ status: body.status })
    .eq('id', body.id)
    .eq('user_id', user.id)

  return new Response(JSON.stringify({ ok: !error }), { status: error ? 500 : 200 })
})
