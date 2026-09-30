import React from 'react';
import { Header } from '@/components/site/Header';
import { Footer } from '@/components/site/Footer';

export default function PrivacyPage() {
  return (
    <div className="min-h-screen bg-background">
      <Header />
      <section className="mx-auto max-w-3xl px-4 py-12 sm:px-6">
        <h1 className="text-3xl font-bold sm:text-4xl">
          Privacy Policy &amp; GDPR / DPDP Compliance
        </h1>
        <p className="mt-2 text-xs text-muted-foreground">
          Protecting Student &amp; Parent Data • India DPDP Act &amp; GDPR Compliant
        </p>

        <div className="mt-6 space-y-5 rounded-3xl border border-border bg-card p-6 text-sm leading-relaxed text-muted-foreground shadow-card sm:p-8">
          <div>
            <h2 className="text-base font-bold text-foreground">
              1. Data Collection &amp; Minors Protection
            </h2>
            <p className="mt-1">
              Hum sirf student ka naam, class, school, city, aur parent/student contact details collect karte hain taaki learning progress, leaderboard rank aur certificates issue kiye ja sakein.
            </p>
          </div>

          <div>
            <h2 className="text-base font-bold text-foreground">
              2. Payment Security (Razorpay PCI-DSS)
            </h2>
            <p className="mt-1">
              Saare payments Razorpay secure gateway ke zariye process hote hain. Uyanix kisi bhi card, UPI PIN ya bank password ko store nahi karta.
            </p>
          </div>

          <div>
            <h2 className="text-base font-bold text-foreground">
              3. Data Deletion &amp; Export Rights
            </h2>
            <p className="mt-1">
              Parents ya students kisi bhi samay <b className="text-foreground">dollysingh1268@gmail.com</b> par email karke apna data export ya permanent deletion request kar sakte hain.
            </p>
          </div>
        </div>
      </section>
      <Footer />
    </div>
  );
}
