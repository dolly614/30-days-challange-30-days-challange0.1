import { z } from 'zod';

const serverSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  SUPABASE_SERVICE_ROLE_KEY: z.string().min(20).optional().default('default_supabase_service_role_key_development'),
  RAZORPAY_KEY_ID: z.string().optional().default('rzp_test_TnHeazQIbKp64L'),
  RAZORPAY_KEY_SECRET: z.string().min(10).default('z2yLpMR9xKqWmUjMMwi3ACB1'),
  RAZORPAY_WEBHOOK_SECRET: z.string().min(10).optional().default('ephemeral_dev_webhook_secret_uyanix_30d'),
  RESEND_API_KEY: z.string().min(10).optional().default('re_default_development_key_uyanix'),
  JWT_SECRET: z.string().min(32).optional().default('a_very_secure_jwt_secret_with_more_than_32_characters_for_dev'),
  APP_URL: z.string().url().optional().default('http://localhost:3000'),
  GEMINI_API_KEY: z.string().min(10).optional().default('ephemeral_development_gemini_api_key'),
});

const clientSchema = z.object({
  NEXT_PUBLIC_SUPABASE_URL: z.string().url().optional().default('https://example.supabase.co'),
  NEXT_PUBLIC_SUPABASE_ANON_KEY: z.string().min(20).optional().default('default_anon_key_for_supabase_development_only'),
  NEXT_PUBLIC_RAZORPAY_KEY_ID: z.string().startsWith('rzp_').default('rzp_test_TnHeazQIbKp64L'),
  NEXT_PUBLIC_FIREBASE_API_KEY: z.string().min(10).optional().default('ephemeral_dev_firebase_api_key'),
  NEXT_PUBLIC_FIREBASE_PROJECT_ID: z.string().min(1).optional().default('demo-project'),
  NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN: z.string().min(1).optional().default('demo-project.firebaseapp.com'),
  NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET: z.string().min(1).optional().default('demo-project.appspot.com'),
  NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID: z.string().min(1).optional().default('1234567890'),
  NEXT_PUBLIC_FIREBASE_APP_ID: z.string().min(1).optional().default('1:1234567890:web:abcdef123456'),
});

function validateEnv() {
  const isServer = typeof window === 'undefined';
  const schema = isServer ? serverSchema.merge(clientSchema) : clientSchema;

  const parsed = schema.safeParse(process.env);
  if (!parsed.success) {
    const fallback = schema.safeParse({});
    if (fallback.success) {
      return fallback.data as z.infer<typeof serverSchema & typeof clientSchema>;
    }
  }
  return (parsed.success ? parsed.data : {}) as z.infer<
    typeof serverSchema & typeof clientSchema
  >;
}

export const env = validateEnv();
