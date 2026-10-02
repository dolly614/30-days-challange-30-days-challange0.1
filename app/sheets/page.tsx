'use client';

import React, { useEffect } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { ArrowLeft, FileSpreadsheet } from 'lucide-react';
import { Header } from '@/components/site/Header';
import { Footer } from '@/components/site/Footer';
import { GoogleSheetsHub } from '@/components/sheets/GoogleSheetsHub';
import { useUyanixStore } from '@/lib/store';

export default function GoogleSheetsPage() {
  const router = useRouter();
  const { syncServerSession } = useUyanixStore();

  useEffect(() => {
    let active = true;
    syncServerSession().then((serverUser) => {
      if (!active) return;
      if (!serverUser) {
        router.replace('/login?redirect=/sheets');
      } else if (serverUser.role !== 'admin' && serverUser.role !== 'teacher') {
        router.replace('/dashboard?error=forbidden');
      }
    });
    return () => {
      active = false;
    };
  }, [syncServerSession, router]);
  return (
    <div className="min-h-screen bg-background">
      <Header />

      <section className="mx-auto max-w-7xl px-4 py-10 sm:px-6">
        <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
          <Link
            href="/admin"
            className="inline-flex items-center gap-1.5 text-sm font-semibold text-muted-foreground hover:text-foreground"
          >
            <ArrowLeft className="h-4 w-4" /> Back to Admin Dashboard
          </Link>

          <div className="inline-flex items-center gap-2 rounded-full bg-secondary/10 px-3.5 py-1 text-xs font-semibold text-secondary">
            <FileSpreadsheet className="h-3.5 w-3.5" /> Google Sheets + Drive API Enabled
          </div>
        </div>

        <GoogleSheetsHub />
      </section>

      <Footer />
    </div>
  );
}
