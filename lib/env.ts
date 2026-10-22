import { z } from 'zod';

const serverSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  SUPABASE_SERVICE_ROLE_KEY: z.string().min(20).optional(),
  RAZORPAY_KEY_ID: z.string().optional(),
  RAZORPAY_KEY_SECRET: z.string().optional(),
  RAZORPAY_WEBHOOK_SECRET: z.string().optional(),
  RESEND_API_KEY: z.string().min(10).optional(),
  JWT_SECRET: z.string().min(32).optional(),
  APP_URL: z.string().url().optional().default('http://localhost:3000'),
  GEMINI_API_KEY: z.string().min(10).optional(),
});

const clientSchema = z.object({
  NEXT_PUBLIC_SUPABASE_URL: z.string().url().optional(),
  NEXT_PUBLIC_SUPABASE_ANON_KEY: z.string().min(20).optional(),
  NEXT_PUBLIC_RAZORPAY_KEY_ID: z.string().startsWith('rzp_').optional(),
  NEXT_PUBLIC_FIREBASE_API_KEY: z.string().min(10).optional(),
  NEXT_PUBLIC_FIREBASE_PROJECT_ID: z.string().min(1).optional(),
  NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN: z.string().min(1).optional(),
  NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET: z.string().min(1).optional(),
  NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID: z.string().min(1).optional(),
  NEXT_PUBLIC_FIREBASE_APP_ID: z.string().min(1).optional(),
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
