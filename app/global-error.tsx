'use client';

import React from 'react';

export default function GlobalErrorBoundary({
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-background text-foreground flex items-center justify-center p-6">
        <div className="max-w-md text-center space-y-4">
          <h1 className="text-2xl font-bold">Uyanix 30 Days Challenge</h1>
          <p className="text-sm text-muted-foreground">
            An unexpected application error occurred. No private data was exposed.
          </p>
          <button
            type="button"
            onClick={() => reset()}
            className="inline-flex h-10 items-center rounded-full bg-primary px-6 text-xs font-semibold text-primary-foreground"
          >
            Reload Application
          </button>
        </div>
      </body>
    </html>
  );
}
