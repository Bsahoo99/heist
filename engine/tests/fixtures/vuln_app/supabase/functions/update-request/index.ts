import { createClient } from 'npm:@supabase/supabase-js@2'

Deno.serve(async (req) => {
  const body = await req.json()

  const supabase = createClient(
    Deno.env.get('SUPABASE_URL')!,
    Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
  )

  // HEIST-FIXTURE: m6 (service role, no user filter, trusts body.id)
  const { error } = await supabase.from('adoption_requests').update(body).eq('id', body.id)

  return new Response(JSON.stringify({ ok: !error }), { status: error ? 500 : 200 })
})
