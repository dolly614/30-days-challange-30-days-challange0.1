import React from 'react';
import Link from 'next/link';
import { Header } from '@/components/site/Header';
import { Footer } from '@/components/site/Footer';

export default function NotFound() {
  return (
    <div className="min-h-screen bg-background">
      <Header />
      <section className="mx-auto max-w-xl px-4 py-24 text-center sm:px-6">
        <div className="text-6xl font-extrabold text-gradient">404</div>
        <h1 className="mt-3 text-2xl font-bold sm:text-3xl">
          Oops! Yeh Page Nahi Mila 🔍
        </h1>
        <p className="mt-2 text-sm text-muted-foreground">
          Lagta hai aap galat link par aa gaye hain. Chaliye wapas home ya dashboard par chalte hain!
        </p>
        <div className="mt-6 flex justify-center gap-3">
          <Link
            href="/"
            className="inline-flex h-11 items-center rounded-full bg-gradient-hero px-6 text-xs font-semibold text-primary-foreground shadow-soft"
          >
            Go to Home
          </Link>
          <Link
            href="/dashboard"
            className="inline-flex h-11 items-center rounded-full border border-border bg-card px-6 text-xs font-semibold hover:bg-accent"
          >
            Student Dashboard
          </Link>
        </div>
      </section>
      <Footer />
    </div>
  );
}
