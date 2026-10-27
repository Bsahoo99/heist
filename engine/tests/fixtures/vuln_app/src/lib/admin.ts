import { createClient } from '@supabase/supabase-js'

// HEIST-FIXTURE: m2
export const admin = createClient(
  import.meta.env.VITE_SUPABASE_URL,
  import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY,
)
