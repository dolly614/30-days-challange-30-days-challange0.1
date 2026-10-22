'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { Header } from '@/components/site/Header';
import { Footer } from '@/components/site/Footer';
import { RazorpayCheckoutButton } from '@/components/payment/RazorpayCheckoutButton';
import { ShieldCheck, CheckCircle2, AlertCircle, ArrowLeft, RefreshCw } from 'lucide-react';

export default function RazorpayCheckoutDemoPage() {
  const [selectedAmount, setSelectedAmount] = useState<number>(100); // 100 paise = ₹1.00 (min amount)
  const [customAmountRupees, setCustomAmountRupees] = useState<string>('1');
  const [customerName, setCustomerName] = useState<string>('Test Student');
  const [customerEmail, setCustomerEmail] = useState<string>('student@example.com');
  const [customerPhone, setCustomerPhone] = useState<string>('9876543210');

  const [paymentResult, setPaymentResult] = useState<{
    order_id: string;
    payment_id: string;
    signature: string;
    verified: boolean;
  } | null>(null);

  const [lastError, setLastError] = useState<string | null>(null);

  const handleCustomAmountChange = (val: string) => {
    setCustomAmountRupees(val);
    const parsed = parseFloat(val);
    if (!isNaN(parsed) && parsed >= 1) {
      setSelectedAmount(Math.round(parsed * 100)); // convert to paise
    }
  };

  return (
    <div className="min-h-screen bg-background">
      <Header />

      <main className="mx-auto max-w-4xl px-4 py-12 sm:px-6">
        <div className="mb-6">
          <Link
            href="/"
            className="inline-flex items-center gap-1.5 text-xs font-semibold text-muted-foreground hover:text-foreground"
          >
            <ArrowLeft className="h-3.5 w-3.5" /> Back to Home
          </Link>
        </div>

        <div className="text-center max-w-2xl mx-auto mb-10">
          <div className="inline-flex items-center gap-2 rounded-full bg-primary/10 px-3.5 py-1 text-xs font-semibold text-primary">
            <ShieldCheck className="h-4 w-4" /> Razorpay Standard Web Checkout
          </div>
          <h1 className="mt-3 text-3xl font-extrabold sm:text-4xl tracking-tight">
            Razorpay Payment Gateway Integration
          </h1>
          <p className="mt-2 text-sm text-muted-foreground">
            Test the live 3-step checkout flow: Backend Order Creation (<code>/api/create-order</code>),
            Frontend Razorpay Modal, and HMAC-SHA256 Signature Verification (<code>/api/verify-payment</code>).
          </p>
        </div>

        <div className="grid gap-8 md:grid-cols-2">
          {/* Checkout Controls */}
          <div className="rounded-3xl border border-border bg-card p-6 sm:p-8 shadow-card flex flex-col justify-between">
            <div>
              <h2 className="text-lg font-bold">Select Payment Amount</h2>
              <p className="text-xs text-muted-foreground mt-1">
                Choose a preset or enter a custom amount (minimum ₹1 / 100 paise).
              </p>

              {/* Preset buttons */}
              <div className="mt-4 grid grid-cols-2 gap-2.5">
                {[
                  { label: '₹199 (Standard Exam Fee)', paise: 19900, rs: '199' },
                  { label: '₹99 (Mid-Term Exam Fee)', paise: 9900, rs: '99' },
                ].map((preset) => (
                  <button
                    key={preset.paise}
                    type="button"
                    onClick={() => {
                      setSelectedAmount(preset.paise);
                      setCustomAmountRupees(preset.rs);
                    }}
                    className={`rounded-2xl border px-3 py-2.5 text-xs font-semibold transition ${
                      selectedAmount === preset.paise
                        ? 'border-primary bg-primary/10 text-primary'
                        : 'border-border bg-muted/40 text-muted-foreground hover:bg-accent'
                    }`}
                  >
                    {preset.label}
                  </button>
                ))}
              </div>

              {/* Custom amount input */}
              <div className="mt-4">
                <label className="text-xs font-medium text-muted-foreground">
                  Custom Amount (in INR ₹)
                </label>
                <div className="relative mt-1">
                  <span className="absolute left-3.5 top-2.5 text-sm font-semibold text-muted-foreground">
                    ₹
                  </span>
                  <input
                    type="number"
                    min="1"
                    step="1"
                    value={customAmountRupees}
                    onChange={(e) => handleCustomAmountChange(e.target.value)}
                    className="w-full rounded-xl border border-border bg-muted/30 py-2 pl-8 pr-3 text-sm font-medium focus:border-primary focus:outline-none"
                    placeholder="199"
                  />
                </div>
              </div>

              {/* Customer details */}
              <div className="mt-5 space-y-3">
                <h3 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
                  Customer Prefill
                </h3>
                <div>
                  <label className="text-[11px] text-muted-foreground">Full Name</label>
                  <input
                    type="text"
                    value={customerName}
                    onChange={(e) => setCustomerName(e.target.value)}
                    className="mt-0.5 w-full rounded-xl border border-border bg-muted/30 px-3 py-1.5 text-xs focus:border-primary focus:outline-none"
                  />
                </div>
                <div>
                  <label className="text-[11px] text-muted-foreground">Email</label>
                  <input
                    type="email"
                    value={customerEmail}
                    onChange={(e) => setCustomerEmail(e.target.value)}
                    className="mt-0.5 w-full rounded-xl border border-border bg-muted/30 px-3 py-1.5 text-xs focus:border-primary focus:outline-none"
                  />
                </div>
                <div>
                  <label className="text-[11px] text-muted-foreground">Phone Number</label>
                  <input
                    type="tel"
                    value={customerPhone}
                    onChange={(e) => setCustomerPhone(e.target.value)}
                    className="mt-0.5 w-full rounded-xl border border-border bg-muted/30 px-3 py-1.5 text-xs focus:border-primary focus:outline-none"
                  />
                </div>
              </div>
            </div>

            {/* Checkout Action Button */}
            <div className="mt-8 border-t border-border pt-6">
              <div className="flex items-baseline justify-between mb-3 text-sm">
                <span className="text-muted-foreground">Total Payable:</span>
                <span className="text-xl font-extrabold text-primary">
                  ₹{(selectedAmount / 100).toFixed(2)} ({selectedAmount} paise)
                </span>
              </div>

              <RazorpayCheckoutButton
                amount={selectedAmount}
                currency="INR"
                name="Uyanix 30 Days Challenge"
                description={`Order for ₹${(selectedAmount / 100).toFixed(0)} - Test Checkout`}
                prefill={{
                  name: customerName,
                  email: customerEmail,
                  contact: customerPhone,
                }}
                buttonText={`Pay ₹${(selectedAmount / 100).toFixed(0)} via Razorpay Modal`}
                className="w-full h-12"
                onSuccess={(result) => {
                  setPaymentResult(result);
                  setLastError(null);
                }}
                onFailure={(err) => {
                  setLastError(err);
                }}
              />

              <p className="mt-2.5 text-center text-[10px] text-muted-foreground">
                Credentials: Key ID <code>rzp_test_...</code> • Test Mode Supported
              </p>
            </div>
          </div>

          {/* Verification & Result Panel */}
          <div className="rounded-3xl border border-border bg-card p-6 sm:p-8 shadow-card flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between">
                <h2 className="text-lg font-bold">Transaction Verification</h2>
                {paymentResult && (
                  <button
                    type="button"
                    onClick={() => {
                      setPaymentResult(null);
                      setLastError(null);
                    }}
                    className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
                  >
                    <RefreshCw className="h-3 w-3" /> Reset
                  </button>
                )}
              </div>
              <p className="text-xs text-muted-foreground mt-1">
                Real-time server signature check status via HMAC-SHA256.
              </p>

              {paymentResult ? (
                <div className="mt-6 space-y-4">
                  <div className="rounded-2xl border border-emerald-500/30 bg-emerald-500/10 p-4 text-emerald-600 dark:text-emerald-400">
                    <div className="flex items-center gap-2 font-bold text-sm">
                      <CheckCircle2 className="h-5 w-5" />
                      Payment Verified &amp; Captured!
                    </div>
                    <p className="mt-1 text-xs text-emerald-700 dark:text-emerald-300">
                      Signature verified using HMAC-SHA256(order_id + &quot;|&quot; + payment_id, KEY_SECRET).
                    </p>
                  </div>

                  <div className="space-y-2 rounded-2xl border border-border bg-muted/40 p-4 text-xs font-mono">
                    <div>
                      <span className="text-muted-foreground font-sans font-semibold">Order ID:</span>
                      <div className="text-foreground break-all">{paymentResult.order_id}</div>
                    </div>
                    <div>
                      <span className="text-muted-foreground font-sans font-semibold">Payment ID:</span>
                      <div className="text-foreground break-all">{paymentResult.payment_id}</div>
                    </div>
                    <div>
                      <span className="text-muted-foreground font-sans font-semibold">Razorpay Signature:</span>
                      <div className="text-foreground break-all">{paymentResult.signature}</div>
                    </div>
                    <div>
                      <span className="text-muted-foreground font-sans font-semibold">Verified Status:</span>
                      <div className="text-emerald-500 font-bold">SUCCESS (200 OK)</div>
                    </div>
                  </div>
                </div>
              ) : lastError ? (
                <div className="mt-6 rounded-2xl border border-destructive/30 bg-destructive/10 p-4 text-destructive">
                  <div className="flex items-center gap-2 font-bold text-sm">
                    <AlertCircle className="h-5 w-5" />
                    Transaction Notification
                  </div>
                  <p className="mt-1 text-xs">{lastError}</p>
                </div>
              ) : (
                <div className="mt-8 text-center py-10 px-4 rounded-2xl border border-dashed border-border bg-muted/20">
                  <ShieldCheck className="mx-auto h-8 w-8 text-muted-foreground/60" />
                  <p className="mt-2 text-xs font-medium text-muted-foreground">
                    No active transaction yet.
                  </p>
                  <p className="mt-1 text-[11px] text-muted-foreground/80">
                    Click the &quot;Pay via Razorpay Modal&quot; button on the left to test the integration.
                  </p>
                </div>
              )}
            </div>

            {/* Architecture Overview */}
            <div className="mt-8 border-t border-border pt-4 text-xs text-muted-foreground space-y-1.5">
              <div className="font-semibold text-foreground text-[11px] uppercase tracking-wider">
                Architecture Flow
              </div>
              <div className="flex items-center gap-2 text-[11px]">
                <span className="inline-block h-2 w-2 rounded-full bg-emerald-500" />
                <span>1. POST /api/create-order (server-validated pricing ₹199 / ₹99)</span>
              </div>
              <div className="flex items-center gap-2 text-[11px]">
                <span className="inline-block h-2 w-2 rounded-full bg-emerald-500" />
                <span>2. Razorpay.open() Modal Checkout</span>
              </div>
              <div className="flex items-center gap-2 text-[11px]">
                <span className="inline-block h-2 w-2 rounded-full bg-emerald-500" />
                <span>3. POST /api/verify-payment (HMAC-SHA256 signature check)</span>
              </div>
            </div>
          </div>
        </div>
      </main>

      <Footer />
    </div>
  );
}
