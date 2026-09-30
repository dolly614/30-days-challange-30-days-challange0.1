import React from 'react';
import { Header } from '@/components/site/Header';
import { Footer } from '@/components/site/Footer';

export default function TermsPage() {
  return (
    <div className="min-h-screen bg-background">
      <Header />
      <section className="mx-auto max-w-3xl px-4 py-12 sm:px-6">
        <h1 className="text-3xl font-bold sm:text-4xl">Terms &amp; Conditions</h1>
        <p className="mt-2 text-xs text-muted-foreground">
          Last updated: September 2026 • Uyanix 30 Days Challenge
        </p>

        <div className="mt-6 space-y-5 rounded-3xl border border-border bg-card p-6 text-sm leading-relaxed text-muted-foreground shadow-card sm:p-8">
          <div>
            <h2 className="text-base font-bold text-foreground">
              1. Eligibility &amp; Student Verification
            </h2>
            <p className="mt-1">
              Uyanix 30 Days Challenge India ke Class 1 se Class 12 tak ke school students ke liye open hai. Prize claim karne ke liye valid School ID Card ya Report Card verification mandatory hai.
            </p>
          </div>

          <div>
            <h2 className="text-base font-bold text-foreground">
              2. Pay-Later Pricing Model
            </h2>
            <p className="mt-1">
              Registration aur 30-day daily chapters + 5 MCQs bilkul FREE hain. ₹199 exam fee sirf tab lagu hoti hai jab student 15-Day Mid Exam ya 30-Day Final Exam attempt karna chahe.
            </p>
          </div>

          <div>
            <h2 className="text-base font-bold text-foreground">
              3. Prizes &amp; Ranking Rules
            </h2>
            <p className="mt-1">
              Top 3 All-India Rank holders ko 1st Prize (Laptop), 2nd Prize (Tablet), aur 3rd Prize (Smartphone) diya jaata hai. Tie-breaker ke liye daily streak consistency aur exam completion time consider kiya jayega.
            </p>
          </div>

          <div>
            <h2 className="text-base font-bold text-foreground">
              4. Teacher Referral Anti-Fraud Policy
            </h2>
            <p className="mt-1">
              Self-referral, duplicate device/IP/phone accounts, aur refunded exam fees par referral commission lagu nahi hoga.
            </p>
          </div>
        </div>
      </section>
      <Footer />
    </div>
  );
}
