import { z } from 'zod';

export const PhoneSchema = z.string().regex(/^[6-9]\d{9}$/, 'Invalid Indian mobile number');
export const OtpSchema = z.string().length(6).regex(/^\d+$/);

export const LoginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

export const OtpRequestSchema = z.object({
  phone: PhoneSchema,
});
