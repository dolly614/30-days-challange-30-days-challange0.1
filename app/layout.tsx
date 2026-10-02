import type { Metadata, Viewport } from 'next';
import { Plus_Jakarta_Sans, Fraunces, JetBrains_Mono } from 'next/font/google';
import { Toaster } from 'sonner';
import { OfflineIndicator } from '@/components/site/PWAInstallButton';
import {
  PUBLIC_CANONICAL_ORIGIN,
  buildAuthoritativeSchemaOrgJsonLd,
} from '@/lib/seo-canonical-url-governance';
import './globals.css';

const jakarta = Plus_Jakarta_Sans({
  subsets: ['latin'],
  variable: '--font-jakarta',
  weight: ['400', '500', '600', '700', '800'],
  display: 'swap',
});

const fraunces = Fraunces({
  subsets: ['latin'],
  variable: '--font-fraunces',
  weight: ['600', '700'],
  display: 'swap',
});

const jetbrains = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-jetbrains',
  weight: ['400', '600', '700'],
  display: 'swap',
});

export const viewport: Viewport = {
  themeColor: '#7c3aed',
  width: 'device-width',
  initialScale: 1,
};

export const metadata: Metadata = {
  metadataBase: new URL(PUBLIC_CANONICAL_ORIGIN),
  title: 'Uyanix 30 Days Challenge — Seekho, Compete Karo, Jeeto!',
  description:
    "India's biggest 30-day daily learning competition for Class 1–12. FREE registration. Win Laptop, Tablet & Smartphone + certificate.",
  alternates: {
    canonical: PUBLIC_CANONICAL_ORIGIN,
  },
  authors: [{ name: 'Uyanix 30 Days Challenge' }],
  appleWebApp: {
    capable: true,
    statusBarStyle: 'default',
    title: 'Uyanix 30D',
  },
  icons: {
    apple: '/apple-touch-icon.png',
    icon: '/uyanix-logo.jpg',
  },
  openGraph: {
    title: 'Uyanix 30 Days Challenge — Seekho, Compete Karo, Jeeto!',
    description:
      'Seekho, Compete Karo, Jeeto! Daily learning challenge for Indian students in Class 1–12.',
    url: PUBLIC_CANONICAL_ORIGIN,
    type: 'website',
    siteName: 'Uyanix 30 Days Challenge',
    images: [`${PUBLIC_CANONICAL_ORIGIN}/uyanix-logo.jpg`],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Uyanix 30 Days Challenge',
    description:
      "India's biggest 30-day daily learning competition for Class 1–12. Register FREE, win Laptop, Tablet, Smartphone & Certificate.",
    images: [`${PUBLIC_CANONICAL_ORIGIN}/uyanix-logo.jpg`],
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const jsonLd = buildAuthoritativeSchemaOrgJsonLd();

  return (
    <html
      lang="en"
      className={`${jakarta.variable} ${fraunces.variable} ${jetbrains.variable}`}
      suppressHydrationWarning
    >
      <body suppressHydrationWarning>
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
        />
        {children}
        <OfflineIndicator />
        <Toaster richColors position="top-right" closeButton />
      </body>
    </html>
  );
}
