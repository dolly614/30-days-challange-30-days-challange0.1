'use client';

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { Award, Download, Printer, Share2, ShieldCheck } from 'lucide-react';
import { QRCodeSVG } from 'qrcode.react';
import { Header } from '@/components/site/Header';
import { Footer } from '@/components/site/Footer';
import { BrandMark } from '@/components/site/BrandMark';
import { useUyanixStore } from '@/lib/store';
import { buildCanonicalCertificatePublicVerificationUrl } from '@/lib/seo-canonical-url-governance';
import { toast } from 'sonner';

export default function CertificatePage() {
  const router = useRouter();
  const { currentUser, completedDays, examAttempts, syncServerSession } = useUyanixStore();
  const [customName, setCustomName] = useState(currentUser?.name || 'dollysingh');

  useEffect(() => {
    let active = true;
    syncServerSession().then((serverUser) => {
      if (active && !serverUser) {
        router.replace('/login?redirect=/certificate');
      }
    });
    return () => {
      active = false;
    };
  }, [syncServerSession, router]);

  const latestAttempt = examAttempts[0];
  const [serverCertId, setServerCertId] = useState<string>('UYX-CERT-A9F48E2C1B7D03E6');
  const [serverQrUrl, setServerQrUrl] = useState<string>(
    buildCanonicalCertificatePublicVerificationUrl('UYX-CERT-A9F48E2C1B7D03E6')
  );
  const [serverRecipientName, setServerRecipientName] = useState<string>('');
  const [serverScore, setServerScore] = useState<number | null>(null);
  const [serverRank, setServerRank] = useState<number | null>(null);

  useEffect(() => {
    let active = true;
    fetch('/api/certificate', { credentials: 'include' })
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (active && data?.publicCertificateId && data?.qrVerificationUrl) {
          setServerCertId(data.publicCertificateId);
          setServerQrUrl(data.qrVerificationUrl);
          if (data.recipientName) {
            setServerRecipientName(data.recipientName);
            setCustomName(data.recipientName);
          }
          if (typeof data.scoreSnapshot === 'number') {
            setServerScore(data.scoreSnapshot);
          }
          if (typeof data.rankSnapshot === 'number') {
            setServerRank(data.rankSnapshot);
          }
        }
      })
      .catch(() => {});
    return () => {
      active = false;
    };
  }, []);

  const certId = serverCertId;

  const handlePrintPdf = () => {
    toast.success('Opening Certificate PDF Print Dialog...');
    window.print();
  };

  return (
    <div className="min-h-screen bg-background">
      <Header />

      <section className="mx-auto max-w-4xl px-4 py-10 sm:px-6">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <div className="inline-flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-primary">
              <Award className="h-4 w-4" /> Official Digital Credential
            </div>
            <h1 className="mt-1 text-3xl font-bold sm:text-4xl">
              Certificate of Achievement 🎓
            </h1>
            <p className="mt-1 text-sm text-muted-foreground">
              Apna verified Uyanix 30 Days Challenge certificate download ya print karein.
            </p>
          </div>

          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={handlePrintPdf}
              className="inline-flex h-11 items-center gap-2 rounded-full bg-gradient-hero px-6 text-xs font-semibold text-primary-foreground shadow-soft transition hover:scale-[1.02]"
            >
              <Download className="h-4 w-4" /> Download PDF / Print
            </button>
            <button
              type="button"
              onClick={() => {
                navigator.clipboard.writeText(serverQrUrl);
                toast.success('Certificate verification link copied!');
              }}
              className="inline-flex h-11 items-center gap-2 rounded-full border border-border bg-card px-4 text-xs font-semibold hover:bg-accent"
            >
              <Share2 className="h-4 w-4" /> Share Link
            </button>
          </div>
        </div>

        {/* Name customizer bar */}
        <div className="mt-6 flex flex-wrap items-center gap-3 rounded-2xl border border-border bg-card p-4 shadow-card">
          <span className="text-xs font-semibold text-muted-foreground">
            Name on Certificate:
          </span>
          <input
            value={customName}
            onChange={(e) => setCustomName(e.target.value)}
            className="h-9 rounded-xl border border-input bg-background px-3 text-sm font-semibold outline-none focus:border-primary"
          />
          <span className="text-xs text-muted-foreground">
            · Certificate ID: <b className="font-mono text-foreground">{certId}</b>
          </span>
        </div>

        {/* Printable Certificate Frame */}
        <div className="mt-6 rounded-3xl bg-gradient-gold p-1.5 shadow-soft">
          <div className="relative overflow-hidden rounded-[20px] border border-amber-300/60 bg-card p-8 text-center sm:p-12">
            <div className="mx-auto flex items-center justify-center gap-2.5">
              <BrandMark size={44} />
              <div className="text-left">
                <div className="text-sm font-extrabold uppercase tracking-wider text-primary">
                  Uyanix 30 Days Challenge
                </div>
                <div className="text-[11px] text-muted-foreground">
                  National Daily Learning Competition • India 🇮🇳
                </div>
              </div>
            </div>

            <div className="mt-6 text-xs font-bold uppercase tracking-[0.25em] text-saffron">
              Certificate of Excellence
            </div>

            <p className="mt-4 text-sm text-muted-foreground">
              This is proudly presented to
            </p>

            <div className="mt-2 font-serif text-3xl font-bold tracking-tight text-foreground sm:text-5xl">
              {customName || 'Student Champion'}
            </div>

            <div className="mx-auto mt-3 h-1 w-40 rounded-full bg-gradient-india" />

            <p className="mx-auto mt-5 max-w-xl text-sm leading-relaxed text-muted-foreground">
              from <b className="text-foreground">{currentUser?.school || 'Delhi Public School'}</b> (Class{' '}
              <b className="text-foreground">{currentUser?.classNum || 12}</b>) for successfully completing{' '}
              <b className="text-secondary">{completedDays.length} Days</b> of consistent daily learning and achieving{' '}
              <b className="text-primary">
                Rank #{serverRank ?? (latestAttempt?.rank || 4)}
              </b>{' '}
              in the Uyanix 30 Days Challenge 2026.
            </p>

            <div className="mt-8 grid items-end gap-6 border-t border-border pt-6 sm:grid-cols-3">
              <div className="text-left text-xs">
                <div className="font-mono font-bold text-foreground">{certId}</div>
                <div className="text-muted-foreground">Verification ID</div>
                <div className="mt-1 inline-flex items-center gap-1 text-[11px] font-semibold text-secondary">
                  <ShieldCheck className="h-3.5 w-3.5" /> Digitally Verified
                </div>
              </div>

              <div className="flex flex-col items-center">
                <div className="rounded-xl border border-border bg-white p-2 shadow-sm">
                  <QRCodeSVG
                    value={serverQrUrl}
                    size={68}
                  />
                </div>
                <span className="mt-1 text-[10px] text-muted-foreground">Scan to Verify</span>
              </div>

              <div className="text-right text-xs">
                <div className="font-serif text-base font-bold italic text-foreground">
                  Uyanix Academic Board
                </div>
                <div className="text-muted-foreground">Program Director • 2026</div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <Footer />
    </div>
  );
}
