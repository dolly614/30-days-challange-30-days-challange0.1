'use client';

import React, { useEffect } from 'react';
import Link from 'next/link';
import { Header } from '@/components/site/Header';
import { Footer } from '@/components/site/Footer';
import { logRouteSecurityOrBoundaryEvent } from '@/lib/routing-access-control-governance';

export default function RouteErrorBoundary({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    logRouteSecurityOrBoundaryEvent({
      correlationId: error?.digest || `err-${Date.now()}`,
      route: typeof window !== 'undefined' ? window.location.pathname : '/unknown',
      errorClass: 'UNKNOWN_ERROR',
      errorCode: 'ROUTE_ERROR_BOUNDARY_CAUGHT',
      httpStatus: 500,
      rawMessage: error?.message || 'Unexpected route error caught by error boundary.',
    });
  }, [error]);

  return (
    <div className="min-h-screen bg-background">
      <Header />
      <section className="mx-auto max-w-xl px-4 py-24 text-center sm:px-6">
        <div className="text-4xl font-extrabold text-gradient">Temporary Issue</div>
        <h1 className="mt-3 text-2xl font-bold sm:text-3xl">
          Something went wrong while loading this page
        </h1>
        <p className="mt-2 text-sm text-muted-foreground">
          Your account and progress are safe. Please try reloading this section or return to the home page.
        </p>
        <div className="mt-6 flex justify-center gap-3">
          <button
            type="button"
            onClick={() => reset()}
            className="inline-flex h-11 items-center rounded-full bg-gradient-hero px-6 text-xs font-semibold text-primary-foreground shadow-soft"
          >
            Try Again
          </button>
          <Link
            href="/"
            className="inline-flex h-11 items-center rounded-full border border-border bg-card px-6 text-xs font-semibold hover:bg-accent"
          >
            Go to Home
          </Link>
        </div>
      </section>
      <Footer />
    </div>
  );
}
