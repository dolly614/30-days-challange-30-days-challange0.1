import { z } from 'zod';

export const CreateOrderSchema = z.object({
  amount: z.number().int().positive().max(1000000),
  currency: z.literal('INR'),
  receipt: z.string().min(1).max(40),
  studentId: z.string().uuid(),
});

export const VerifyPaymentSchema = z.object({
  razorpay_order_id: z.string().min(1),
  razorpay_payment_id: z.string().min(1),
  razorpay_signature: z.string().min(1),
});
