import { z } from 'zod';

const serverSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  SUPABASE_SERVICE_ROLE_KEY: z.string().min(20, 'SUPABASE_SERVICE_ROLE_KEY is required'),
  RAZORPAY_KEY_SECRET: z.string().min(10, 'RAZORPAY_KEY_SECRET is required'),
  RAZORPAY_WEBHOOK_SECRET: z.string().min(10, 'RAZORPAY_WEBHOOK_SECRET is required'),
  RESEND_API_KEY: z.string().min(10, 'RESEND_API_KEY is required'),
  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters'),
  APP_URL: z.string().url('APP_URL must be a valid URL'),
  GEMINI_API_KEY: z.string().min(10, 'GEMINI_API_KEY is required'),
});

const clientSchema = z.object({
  NEXT_PUBLIC_SUPABASE_URL: z.string().url(),
  NEXT_PUBLIC_SUPABASE_ANON_KEY: z.string().min(20),
  NEXT_PUBLIC_RAZORPAY_KEY_ID: z.string().startsWith('rzp_'),
  NEXT_PUBLIC_FIREBASE_API_KEY: z.string().min(10),
  NEXT_PUBLIC_FIREBASE_PROJECT_ID: z.string().min(1),
  NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN: z.string().min(1),
  NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET: z.string().min(1),
  NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID: z.string().min(1),
  NEXT_PUBLIC_FIREBASE_APP_ID: z.string().min(1),
});

function validateEnv() {
  const isServer = typeof window === 'undefined';
  const schema = isServer ? serverSchema.merge(clientSchema) : clientSchema;

  const parsed = schema.safeParse(process.env);
  if (!parsed.success) {
    const errors = parsed.error.flatten().fieldErrors;
    console.error('❌ Invalid environment variables:', errors);
    if (isServer) {
      throw new Error(`Invalid env vars: ${Object.keys(errors).join(', ')}`);
    }
  }
  return parsed.data as z.infer<typeof serverSchema & typeof clientSchema>;
}

export const env = validateEnv();
