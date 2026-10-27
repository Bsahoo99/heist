import { supabase } from './supabase'

// Privileged work happens in edge functions, never in the browser.
export const admin = supabase
