import { z } from 'zod';

export const VerifyReferralSchema = z.object({
  referralCode: z.string().min(6).max(20),
  referredStudentId: z.string().uuid(),
});
