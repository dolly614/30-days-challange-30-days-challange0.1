'use client';

import React, { useState } from 'react';
import { CreditCard, Loader2 } from 'lucide-react';
import { toast } from 'sonner';

interface RazorpayPrefill {
  name?: string;
  email?: string;
  contact?: string;
}

export interface RazorpayCheckoutButtonProps {
  amount?: number; // In paise (e.g., 19900 = ₹199.00)
  currency?: string;
  name?: string;
  description?: string;
  prefill?: RazorpayPrefill;
  examType?: 'mid' | 'final';
  buttonText?: string;
  className?: string;
  variant?: 'primary' | 'secondary' | 'outline';
  disabled?: boolean;
  onSuccess?: (result: {
    order_id: string;
    payment_id: string;
    signature: string;
    verified: boolean;
  }) => void;
  onFailure?: (error: string) => void;
  children?: React.ReactNode;
}

interface RazorpaySuccessResponse {
  razorpay_payment_id: string;
  razorpay_order_id: string;
  razorpay_signature: string;
}

interface RazorpayFailureResponse {
  error?: {
    code?: string;
    description?: string;
    source?: string;
    step?: string;
    reason?: string;
    metadata?: {
      order_id?: string;
      payment_id?: string;
    };
  };
}

// Dynamically load the official Razorpay checkout script
function loadRazorpayScript(): Promise<boolean> {
  return new Promise((resolve) => {
    if (typeof window === 'undefined') {
      resolve(false);
      return;
    }

    if ((window as unknown as { Razorpay?: unknown }).Razorpay) {
      resolve(true);
      return;
    }

    const script = document.createElement('script');
    script.src = 'https://checkout.razorpay.com/v1/checkout.js';
    script.async = true;
    script.onload = () => resolve(true);
    script.onerror = () => {
      console.error('Failed to load Razorpay SDK from https://checkout.razorpay.com/v1/checkout.js');
      resolve(false);
    };
    document.body.appendChild(script);
  });
}

export function RazorpayCheckoutButton({
  amount = 19900, // Default ₹199.00 (19900 paise)
  currency = 'INR',
  name = 'Uyanix 30 Days Challenge',
  description = '30-Day Learning Challenge Exam Fee',
  prefill,
  examType,
  buttonText = 'Pay with Razorpay',
  className = '',
  variant = 'primary',
  disabled = false,
  onSuccess,
  onFailure,
  children,
}: RazorpayCheckoutButtonProps) {
  const [loading, setLoading] = useState(false);

  const handleCheckout = async () => {
    if (loading || disabled) return;
    setLoading(true);

    try {
      // 1. Ensure Razorpay Checkout SDK is loaded
      const isScriptLoaded = await loadRazorpayScript();
      if (!isScriptLoaded) {
        const errMsg = 'Failed to load Razorpay Checkout SDK. Please check your internet connection.';
        toast.error(errMsg);
        onFailure?.(errMsg);
        setLoading(false);
        return;
      }

      // 2. Step 1: Create Order via Backend Endpoint
      const createOrderRes = await fetch('/api/create-order', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          amount,
          currency,
          receipt: `rcpt_${examType || 'exam'}_${Date.now()}`,
          notes: {
            platform: 'Uyanix 30 Days Challenge',
            examType: examType || 'mid',
          },
        }),
      });

      const orderData = await createOrderRes.json();

      if (!createOrderRes.ok || !orderData?.success || !orderData?.order_id) {
        const errMsg = orderData?.error || 'Failed to initialize payment order. Please try again.';
        toast.error(errMsg);
        onFailure?.(errMsg);
        setLoading(false);
        return;
      }

      const keyId =
        orderData.key_id ||
        process.env.NEXT_PUBLIC_RAZORPAY_KEY_ID ||
        'rzp_test_TnHeazQIbKp64L';

      // 3. Step 2: Configure & Open Razorpay Modal
      const options = {
        key: keyId,
        amount: orderData.amount,
        currency: orderData.currency || currency,
        name,
        description,
        image: '/uyanix-logo.jpg',
        order_id: orderData.order_id,
        prefill: {
          name: prefill?.name || '',
          email: prefill?.email || '',
          contact: prefill?.contact || '',
        },
        theme: {
          color: '#7c3aed', // Purple brand accent
        },
        modal: {
          ondismiss: function () {
            toast.info('Payment window closed. Transaction was not completed.');
            onFailure?.('Payment cancelled by user');
            setLoading(false);
          },
        },
        handler: async function (response: RazorpaySuccessResponse) {
          // 4. Step 3: Verify Payment Signature via Backend Endpoint
          try {
            const verifyRes = await fetch('/api/verify-payment', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                order_id: response.razorpay_order_id,
                payment_id: response.razorpay_payment_id,
                signature: response.razorpay_signature,
                razorpay_order_id: response.razorpay_order_id,
                razorpay_payment_id: response.razorpay_payment_id,
                razorpay_signature: response.razorpay_signature,
                examType,
              }),
            });

            const verifyData = await verifyRes.json();

            if (!verifyRes.ok || !verifyData?.success) {
              const errMsg =
                verifyData?.error || 'Payment signature verification failed. Please contact support.';
              toast.error(errMsg);
              onFailure?.(errMsg);
              setLoading(false);
              return;
            }

            toast.success(
              `Payment of ₹${(amount / 100).toFixed(0)} verified successfully! Payment ID: ${response.razorpay_payment_id}`
            );

            onSuccess?.({
              order_id: response.razorpay_order_id,
              payment_id: response.razorpay_payment_id,
              signature: response.razorpay_signature,
              verified: true,
            });
          } catch (verifyErr) {
            console.error('Payment verification request failed:', verifyErr);
            const errMsg = 'Error verifying payment signature with server.';
            toast.error(errMsg);
            onFailure?.(errMsg);
          } finally {
            setLoading(false);
          }
        },
      };

      const razorpayInstance = new (window as unknown as {
        Razorpay: new (opts: typeof options) => {
          open: () => void;
          on: (event: string, callback: (res: RazorpayFailureResponse) => void) => void;
        };
      }).Razorpay(options);

      // Handle payment.failed event
      razorpayInstance.on('payment.failed', function (failureResponse: RazorpayFailureResponse) {
        console.error('Razorpay Payment Failed:', failureResponse);
        const errMsg =
          failureResponse?.error?.description ||
          failureResponse?.error?.reason ||
          'Payment failed. Please check your payment method and try again.';
        toast.error(`Payment Failed: ${errMsg}`);
        onFailure?.(errMsg);
        setLoading(false);
      });

      razorpayInstance.open();
    } catch (err: unknown) {
      console.error('Razorpay checkout error:', err);
      const errMsg = 'Unexpected error opening checkout modal. Please try again.';
      toast.error(errMsg);
      onFailure?.(errMsg);
      setLoading(false);
    }
  };

  const defaultStyles =
    variant === 'primary'
      ? 'bg-gradient-hero text-primary-foreground shadow-soft hover:opacity-95'
      : variant === 'outline'
      ? 'border border-border bg-card text-foreground hover:bg-accent'
      : 'bg-primary text-primary-foreground hover:bg-primary/90';

  return (
    <button
      type="button"
      onClick={handleCheckout}
      disabled={loading || disabled}
      className={`inline-flex items-center justify-center gap-2 rounded-full px-6 py-3 text-sm font-semibold transition-all disabled:opacity-60 disabled:cursor-not-allowed ${defaultStyles} ${className}`}
    >
      {loading ? (
        <>
          <Loader2 className="h-4 w-4 animate-spin" />
          <span>Opening Razorpay...</span>
        </>
      ) : children ? (
        children
      ) : (
        <>
          <CreditCard className="h-4 w-4" />
          <span>{buttonText}</span>
        </>
      )}
    </button>
  );
}
