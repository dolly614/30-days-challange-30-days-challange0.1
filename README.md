# Uyanix 30 Days Challenge — Seekho, Compete Karo, Jeeto! 🇮🇳

India's biggest 30-day daily learning competition for Class 1–12 students. Built with Next.js App Router, TypeScript (strict mode), Tailwind CSS v4, Zustand persistent state, QRCode, Recharts, and Supabase PostgreSQL + Razorpay integration.

---

## 📁 Project Architecture

```text
├── app/
│   ├── globals.css                # Locked Design System CSS variables, gradients, animations
│   ├── layout.tsx                 # Root Layout with SEO, OpenGraph, JSON-LD, Sonner Toaster
│   ├── manifest.ts                # PWA Web App Manifest (Standalone Installable)
│   ├── robots.ts                  # SEO robots.txt
│   ├── sitemap.ts                 # Dynamic sitemap.xml
│   ├── page.tsx                   # Home Page (Hero, Live Streak Preview, Steps, Prizes, Countdown, FAQs)
│   ├── register/page.tsx          # 3-Step Free Registration + Student ID Verification + Referral support
│   ├── login/page.tsx             # Password Login, Mobile OTP Verification, Password Reset & Demo Role Switcher
│   ├── leaderboard/page.tsx       # Live Student & Teacher Leaderboard with Class Filters & Search
│   ├── dashboard/page.tsx         # Student 30-Day Challenge Tracker, Streak, Mid/Final Exam & Top 10
│   ├── daily/[day]/page.tsx       # Daily Chapter Notes + 5 Interactive MCQs + Explanations + Confetti
│   ├── exam/page.tsx              # Pay-Later ₹199 Razorpay Gate + 45-Min Timed Exam + Question Palette + Results
│   ├── certificate/page.tsx       # Printable/Downloadable PDF Digital Certificate with QR Code Verification
│   ├── profile/page.tsx           # Student Profile Editor, Streak Reminders & Payment Receipts
│   ├── teacher/page.tsx           # Teacher Referral Portal, QR Code, 14-Day Signup Chart, Withdrawals & KYC
│   ├── admin/
│   │   ├── page.tsx               # Admin Dashboard (KPIs, CSV Export, Bulk Import, Chapters, Verifications, Teachers, Brand Logo, Analytics)
│   │   └── exams/page.tsx         # Admin Exam Question Pool Manager & Submissions Viewer
│   ├── terms/page.tsx             # Terms & Conditions
│   ├── privacy/page.tsx           # Privacy Policy & GDPR / DPDP Compliance
│   ├── contact/page.tsx           # 24x7 Help & Support Ticket Desk
│   └── api/
│       ├── payment/route.ts       # Razorpay Order & HMAC SHA256 Signature Verification
│       └── verify/route.ts        # Rate-Limited Referral Anti-Fraud Verification
├── components/
│   ├── site/                      # Header, Footer, BrandMark, Countdown, PWAInstallButton
│   └── admin/                     # BulkImport, ChaptersManager, StudentVerifications, TeachersPanel, BrandPanel, AdminExtendedPanels
└── lib/
    ├── curriculum.ts              # 30-Day Curriculum & MCQs for Class 1–12
    ├── store.ts                   # Persistent Zustand Store (Users, Leaderboard, Chapters, Exams, Referrals)
    └── supabase-schema.sql        # Complete PostgreSQL Schema + Row Level Security (RLS) Policies
```

---

## 🚀 Setup & Deployment Guide

1. **Install Dependencies**:
   ```bash
   npm install
   ```
2. **Environment Variables**:
   Copy `.env.example` to `.env.local` and configure your Supabase & Razorpay keys.
3. **Database Migration (Supabase)**:
   Run the SQL script in `lib/supabase-schema.sql` inside the Supabase SQL Editor to create all 12 tables and enable Row Level Security (RLS) policies.
4. **Run Development Server**:
   ```bash
   npm run dev
   ```
5. **Production Build**:
   ```bash
   npm run build && npm start
   ```
