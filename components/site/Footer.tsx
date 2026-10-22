'use client';

import React from 'react';
import Link from 'next/link';
import { Instagram, Facebook, Youtube, Mail, Phone } from 'lucide-react';
import { BrandMark } from './BrandMark';

export function Footer() {
  return (
    <footer className="border-t border-border bg-muted/40">
      <div className="mx-auto grid max-w-7xl gap-8 px-4 py-12 sm:px-6 md:grid-cols-4">
        <div className="md:col-span-2">
          <div className="flex items-center gap-2 font-bold">
            <BrandMark size={36} />
            <span>Uyanix 30 Days Challenge</span>
          </div>
          <p className="mt-3 max-w-md text-sm text-muted-foreground">
            India&apos;s most exciting daily learning competition for Class 1–12 students. Seekho, Compete Karo, Jeeto!
          </p>
          <div className="mt-4 flex items-center gap-3">
            <a
              href="https://www.instagram.com/uyanix30dayschallange/"
              target="_blank"
              rel="noopener noreferrer"
              aria-label="Instagram"
              title="Instagram (@uyanix30dayschallange)"
              className="inline-flex h-9 w-9 items-center justify-center rounded-full bg-muted text-muted-foreground transition hover:bg-primary hover:text-primary-foreground"
            >
              <Instagram className="h-4 w-4" aria-hidden="true" />
            </a>
            <a
              href="https://www.facebook.com/"
              target="_blank"
              rel="noopener noreferrer"
              aria-label="Facebook"
              title="Facebook"
              className="inline-flex h-9 w-9 items-center justify-center rounded-full bg-muted text-muted-foreground transition hover:bg-primary hover:text-primary-foreground"
            >
              <Facebook className="h-4 w-4" aria-hidden="true" />
            </a>
            <a
              href="https://www.youtube.com/"
              target="_blank"
              rel="noopener noreferrer"
              aria-label="YouTube"
              title="YouTube"
              className="inline-flex h-9 w-9 items-center justify-center rounded-full bg-muted text-muted-foreground transition hover:bg-primary hover:text-primary-foreground"
            >
              <Youtube className="h-4 w-4" aria-hidden="true" />
            </a>
          </div>
        </div>

        <div>
          <h4 className="mb-3 text-sm font-semibold">Quick Links</h4>
          <ul className="space-y-2 text-sm text-muted-foreground">
            <li>
              <Link href="/" className="hover:text-foreground">
                Home
              </Link>
            </li>
            <li>
              <Link href="/leaderboard" className="hover:text-foreground">
                Leaderboard
              </Link>
            </li>
            <li>
              <Link href="/dashboard" className="hover:text-foreground">
                Dashboard
              </Link>
            </li>
            <li>
              <Link href="/teacher" className="hover:text-foreground">
                Teacher Portal
              </Link>
            </li>
            <li>
              <Link href="/certificate" className="hover:text-foreground">
                Verify Certificate
              </Link>
            </li>
          </ul>
        </div>

        <div>
          <h4 className="mb-3 text-sm font-semibold">Contact &amp; Legal</h4>
          <ul className="space-y-2 text-sm text-muted-foreground">
            <li className="flex items-center gap-2">
              <Mail className="h-4 w-4 shrink-0" aria-hidden="true" /> support@uyanix.in
            </li>
            <li className="flex items-center gap-2">
              <Phone className="h-4 w-4 shrink-0" aria-hidden="true" /> +91 1800-UYX-2026
            </li>
            <li className="pt-1">
              <Link href="/terms" className="text-xs hover:text-foreground underline-offset-4 hover:underline">
                Terms &amp; Conditions
              </Link>
              <span className="mx-1.5">·</span>
              <Link href="/privacy" className="text-xs hover:text-foreground underline-offset-4 hover:underline">
                Privacy &amp; GDPR
              </Link>
              <span className="mx-1.5">·</span>
              <Link href="/contact" className="text-xs hover:text-foreground underline-offset-4 hover:underline">
                Support
              </Link>
            </li>
          </ul>
        </div>
      </div>

      <div className="border-t border-border py-4 text-center text-xs text-muted-foreground">
        © 2026 Uyanix 30 Days Challenge. Made in India 🇮🇳
      </div>
    </footer>
  );
}
