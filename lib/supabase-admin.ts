import 'server-only';
import { createClient } from '@supabase/supabase-js';
import { env } from './env';

const supabaseUrl =
  env.NEXT_PUBLIC_SUPABASE_URL || 'https://placeholder.supabase.co';
const supabaseServiceKey =
  env.SUPABASE_SERVICE_ROLE_KEY || 'placeholder-service-role-key-for-build-sandbox';

export const supabaseAdmin = createClient(
  supabaseUrl,
  supabaseServiceKey,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    },
  }
);
