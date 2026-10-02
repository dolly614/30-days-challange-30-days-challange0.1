'use client';

import React, { useState, useRef, Suspense } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { ShieldCheck, Upload, CheckCircle2, Sparkles } from 'lucide-react';
import { Header } from '@/components/site/Header';
import { Footer } from '@/components/site/Footer';
import { BrandMark } from '@/components/site/BrandMark';
import { useUyanixStore } from '@/lib/store';
import { toast } from 'sonner';

function RegisterContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const refCode = searchParams.get('ref');

  const { login, syncServerSession, submitStudentIdVerification } = useUyanixStore();

  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [name, setName] = useState('');
  const [classNum, setClassNum] = useState('1');
  const [school, setSchool] = useState('');
  const [phone, setPhone] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [agreed, setAgreed] = useState(false);
  const [idFileName, setIdFileName] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const submittingLockRef = useRef(false);
  const idempotencyKeyRef = useRef<string>('');

  const handleStep1Submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (submittingLockRef.current || isSubmitting) {
      return;
    }
    if (!agreed) {
      toast.error('Kripya Terms & Conditions accept karein.');
      return;
    }
    if (password !== confirmPassword) {
      toast.error('Password aur Confirm Password match nahi kar rahe!');
      return;
    }
    if (phone.length !== 10) {
      toast.error('10-digit valid mobile number enter karein.');
      return;
    }

    submittingLockRef.current = true;
    setIsSubmitting(true);

    if (!idempotencyKeyRef.current) {
      idempotencyKeyRef.current = `reg_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
    }

    try {
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Idempotency-Key': idempotencyKeyRef.current,
        },
        credentials: 'include',
        body: JSON.stringify({
          name: name.trim(),
          classNum: Number(classNum),
          school: school.trim(),
          phone: phone.trim(),
          email: email.trim(),
          password,
          confirmPassword,
          agreed,
          referralCode: refCode || undefined,
          idempotencyKey: idempotencyKeyRef.current,
        }),
      });
      const data = await res.json();
      if (!res.ok || !data.user) {
        idempotencyKeyRef.current = '';
        toast.error(data.error || 'Registration failed. Please check your details.');
        return;
      }

      // Synchronize client state strictly from the verified backend session
      const authoritativeUser = (await syncServerSession()) || data.user;
      login(authoritativeUser);
      setPassword('');
      setConfirmPassword('');
      toast.success('Account ban gaya! Ab apna Student ID verify karein 🪪');
      setStep(2);
    } catch {
      idempotencyKeyRef.current = '';
      toast.error('Unable to create account right now. Please try again.');
    } finally {
      submittingLockRef.current = false;
      setIsSubmitting(false);
    }
  };

  const handleStep2Verify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (submittingLockRef.current || isSubmitting) {
      return;
    }
    submittingLockRef.current = true;
    setIsSubmitting(true);
    try {
      const doc = idFileName || 'school-id-card.jpg';
      await fetch('/api/user/profile', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ idCardName: doc }),
      }).catch(() => {});
      await fetch('/api/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          documentName: doc,
          classNum: Number(classNum),
        }),
      }).catch(() => {});
      submitStudentIdVerification(doc);
      await syncServerSession();
      toast.success('Student ID uploaded & verified! Challenge unlocked 🎉');
      setStep(3);
    } finally {
      submittingLockRef.current = false;
      setIsSubmitting(false);
    }
  };

  const steps = [
    { num: 1, label: 'Register' },
    { num: 2, label: 'Verify ID' },
    { num: 3, label: 'Start Challenge' },
  ];

  return (
    <section className="mx-auto grid max-w-6xl gap-10 px-4 py-12 sm:px-6 md:grid-cols-5">
      <div className="md:col-span-3">
        <div className="flex items-center gap-3">
          <BrandMark size={56} />
          <div>
            <div className="text-xs font-semibold uppercase tracking-wider text-primary">
              Uyanix 30 Days Challenge
            </div>
            <h1 className="text-3xl font-bold leading-tight sm:text-4xl">
              Free Registration 🚀
            </h1>
          </div>
        </div>

        <p className="mt-2 text-muted-foreground">
          Abhi register karo <b>FREE</b>. Exam fee sirf tab dena jab aap 15-day ya 30-day challenge complete karein.
        </p>

        {refCode && (
          <div className="mt-4 inline-flex items-center gap-2 rounded-full border border-secondary/30 bg-secondary/10 px-4 py-1.5 text-xs font-semibold text-secondary">
            <Sparkles className="h-3.5 w-3.5" /> Teacher Referral Code Applied: <span className="font-mono">{refCode}</span>
          </div>
        )}

        {/* 3-Step Indicator */}
        <div className="mt-8 flex items-start justify-center gap-2">
          {steps.map((s, idx) => {
            const isActive = step >= s.num;
            return (
              <div key={s.num} className="flex items-start">
                <div className="flex w-24 flex-col items-center gap-1.5">
                  <div
                    className={`flex h-8 w-8 items-center justify-center rounded-full text-xs font-bold tabular-nums ${
                      isActive
                        ? 'bg-gradient-hero text-primary-foreground'
                        : 'border border-border bg-background text-muted-foreground'
                    }`}
                  >
                    {s.num}
                  </div>
                  <span
                    className={`text-[11px] font-semibold ${
                      isActive ? 'text-foreground' : 'text-muted-foreground'
                    }`}
                  >
                    {s.label}
                  </span>
                </div>
                {idx < steps.length - 1 && (
                  <div className="mt-4 h-px w-8 bg-border sm:w-16" />
                )}
              </div>
            );
          })}
        </div>

        {/* STEP 1: Registration Form */}
        {step === 1 && (
          <form
            onSubmit={handleStep1Submit}
            className="mt-8 space-y-4 rounded-3xl border border-border bg-card p-6 shadow-card"
          >
            <div className="text-center">
              <h2 className="text-xl font-bold">Create Your Account</h2>
              <p className="text-xs text-muted-foreground">
                30-Day Challenge ke liye register karein
              </p>
            </div>

            <label className="block">
              <span className="mb-1.5 block text-xs font-semibold text-muted-foreground">
                Student Name
              </span>
              <input
                required
                placeholder="Enter your full name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="h-11 w-full rounded-xl border border-input bg-background px-4 text-sm outline-none ring-ring/30 transition focus:border-primary focus:ring-2"
              />
            </label>

            <div className="grid gap-4 sm:grid-cols-2">
              <label className="block">
                <span className="mb-1.5 block text-xs font-semibold text-muted-foreground">
                  Class
                </span>
                <select
                  value={classNum}
                  onChange={(e) => setClassNum(e.target.value)}
                  className="h-11 w-full rounded-xl border border-input bg-background px-4 text-sm outline-none ring-ring/30 transition focus:border-primary focus:ring-2"
                >
                  {Array.from({ length: 12 }, (_, i) => i + 1).map((c) => (
                    <option key={c} value={String(c)}>
                      Class {c}
                    </option>
                  ))}
                </select>
              </label>

              <label className="block">
                <span className="mb-1.5 block text-xs font-semibold text-muted-foreground">
                  School Name
                </span>
                <input
                  required
                  placeholder="Enter school name"
                  value={school}
                  onChange={(e) => setSchool(e.target.value)}
                  className="h-11 w-full rounded-xl border border-input bg-background px-4 text-sm outline-none ring-ring/30 transition focus:border-primary focus:ring-2"
                />
              </label>
            </div>

            <label className="block">
              <span className="mb-1.5 block text-xs font-semibold text-muted-foreground">
                Mobile Number
              </span>
              <div className="flex gap-2">
                <span className="inline-flex h-11 items-center rounded-xl border border-input bg-accent/50 px-3 text-sm font-semibold text-muted-foreground">
                  +91
                </span>
                <input
                  required
                  pattern="[0-9]{10}"
                  placeholder="Enter mobile number"
                  type="tel"
                  value={phone}
                  onChange={(e) => setPhone(e.target.value.replace(/\D/g, '').slice(0, 10))}
                  className="h-11 w-full rounded-xl border border-input bg-background px-4 text-sm outline-none ring-ring/30 transition focus:border-primary focus:ring-2"
                />
              </div>
            </label>

            <label className="block">
              <span className="mb-1.5 block text-xs font-semibold text-muted-foreground">
                Email (optional)
              </span>
              <input
                placeholder="parent@email.com"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="h-11 w-full rounded-xl border border-input bg-background px-4 text-sm outline-none ring-ring/30 transition focus:border-primary focus:ring-2"
              />
            </label>

            <div className="grid gap-4 sm:grid-cols-2">
              <label className="block">
                <span className="mb-1.5 block text-xs font-semibold text-muted-foreground">
                  Password
                </span>
                <input
                  required
                  minLength={6}
                  placeholder="Create password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="h-11 w-full rounded-xl border border-input bg-background px-4 text-sm outline-none ring-ring/30 transition focus:border-primary focus:ring-2"
                />
              </label>

              <label className="block">
                <span className="mb-1.5 block text-xs font-semibold text-muted-foreground">
                  Confirm Password
                </span>
                <input
                  required
                  minLength={6}
                  placeholder="Confirm password"
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="h-11 w-full rounded-xl border border-input bg-background px-4 text-sm outline-none ring-ring/30 transition focus:border-primary focus:ring-2"
                />
              </label>
            </div>

            <label className="flex items-center gap-2 text-xs text-muted-foreground">
              <input
                type="checkbox"
                checked={agreed}
                onChange={(e) => setAgreed(e.target.checked)}
                className="h-4 w-4 rounded border-input accent-primary"
              />
              I agree to the{' '}
              <Link href="/terms" className="font-semibold text-primary hover:underline">
                Terms &amp; Conditions
              </Link>
            </label>

            <button
              type="submit"
              disabled={isSubmitting}
              className="mt-2 inline-flex h-12 w-full items-center justify-center gap-2 rounded-full bg-gradient-hero text-sm font-semibold text-primary-foreground shadow-soft transition hover:scale-[1.01] disabled:opacity-60"
            >
              Create Account &amp; Continue →
            </button>

            <p className="text-center text-xs text-muted-foreground">
              Already registered?{' '}
              <button
                type="button"
                onClick={() => router.push('/login')}
                className="font-semibold text-primary hover:underline"
              >
                Login
              </button>
            </p>
          </form>
        )}

        {/* STEP 2: Verify Student ID */}
        {step === 2 && (
          <form
            onSubmit={handleStep2Verify}
            className="mt-8 space-y-5 rounded-3xl border border-border bg-card p-6 shadow-card"
          >
            <div className="text-center">
              <h2 className="text-xl font-bold">Verify Your Student ID 🪪</h2>
              <p className="mt-1 text-xs text-muted-foreground">
                School ID card, Report Card ya Aadhaar upload karein taaki aapki Class verify ho sake.
              </p>
            </div>

            <label className="flex cursor-pointer flex-col items-center justify-center rounded-2xl border-2 border-dashed border-primary/40 bg-accent/30 p-8 text-center transition hover:bg-accent/50">
              <Upload className="h-8 w-8 text-primary" />
              <span className="mt-2 text-sm font-semibold">
                {idFileName ? `Selected: ${idFileName}` : 'Click to upload School ID / Report Card'}
              </span>
              <span className="mt-1 text-xs text-muted-foreground">
                PNG, JPG or PDF (max 5MB)
              </span>
              <input
                type="file"
                accept="image/*,application/pdf"
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) setIdFileName(file.name);
                }}
                className="hidden"
              />
            </label>

            <div className="flex flex-wrap gap-3">
              <button
                type="submit"
                className="inline-flex h-12 flex-1 items-center justify-center gap-2 rounded-full bg-gradient-hero px-6 text-sm font-semibold text-primary-foreground shadow-soft"
              >
                Verify &amp; Unlock Challenge →
              </button>
              <button
                type="button"
                onClick={() => {
                  toast.info('Skipped for now — aap baad mein Dashboard se upload kar sakte hain.');
                  setStep(3);
                }}
                className="inline-flex h-12 items-center justify-center rounded-full border border-border px-5 text-xs font-semibold hover:bg-accent"
              >
                Verify Later
              </button>
            </div>
          </form>
        )}

        {/* STEP 3: Start Challenge */}
        {step === 3 && (
          <div className="mt-8 rounded-3xl border border-border bg-card p-8 text-center shadow-card">
            <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-secondary/15 text-secondary">
              <CheckCircle2 className="h-9 w-9" />
            </div>
            <h2 className="mt-4 text-2xl font-bold">Badhai Ho! Aapka Challenge Ready Hai 🎉</h2>
            <p className="mx-auto mt-2 max-w-md text-sm text-muted-foreground">
              Aapka FREE registration complete ho gaya hai. Aaj se apna Day 1 chapter aur 5 MCQs shuru karein!
            </p>
            <div className="mt-6 flex flex-wrap justify-center gap-3">
              <Link
                href="/dashboard"
                className="inline-flex h-12 items-center rounded-full bg-gradient-hero px-7 text-sm font-semibold text-primary-foreground shadow-soft"
              >
                Go to Student Dashboard →
              </Link>
              <Link
                href="/daily/1"
                className="inline-flex h-12 items-center rounded-full border border-border bg-card px-7 text-sm font-semibold hover:bg-accent"
              >
                Start Day 1 Chapter
              </Link>
            </div>
          </div>
        )}
      </div>

      {/* Right Sidebar */}
      <aside className="md:col-span-2">
        <div className="sticky top-24 space-y-4">
          <div className="rounded-3xl border border-border bg-card p-6 shadow-card">
            <div className="text-sm font-semibold text-primary">Pay-Later Pricing</div>
            <div className="mt-4 flex justify-between text-sm">
              <span>Registration</span>
              <span className="font-bold text-secondary">FREE</span>
            </div>
            <div className="mt-2 flex justify-between text-sm">
              <span>15-Day Mid Exam (optional)</span>
              <span className="tabular-nums">₹199</span>
            </div>
            <div className="mt-2 flex justify-between text-sm">
              <span>30-Day Final Exam</span>
              <span className="tabular-nums">₹199</span>
            </div>
            <div className="mt-4 border-t border-border pt-4 text-xs text-muted-foreground">
              Exam fee sirf tab jab aap exam dena chaho. Challenge complete karne ke baad pay karein.
            </div>
          </div>

          <div className="rounded-3xl border border-border bg-accent/60 p-6">
            <div className="flex items-center gap-2 text-sm font-semibold">
              <ShieldCheck className="h-4 w-4 text-secondary" aria-hidden="true" /> Aapko milega:
            </div>
            <ul className="mt-3 space-y-2 text-sm text-muted-foreground">
              <li>✅ FREE registration — abhi shuru karein</li>
              <li>✅ 15-day Mid exam ya 30-day Final exam — choose karo</li>
              <li>✅ Exam fee sirf challenge complete karne ke baad</li>
              <li>✅ Digital certificate</li>
              <li>✅ Top 3 winners win Laptop, Tablet &amp; Phone</li>
              <li>✅ Special participation gift</li>
            </ul>
          </div>
        </div>
      </aside>
    </section>
  );
}

export default function RegisterPage() {
  return (
    <div className="min-h-screen bg-background">
      <Header />
      <Suspense fallback={<div className="py-20 text-center text-sm text-muted-foreground">Loading registration...</div>}>
        <RegisterContent />
      </Suspense>
      <Footer />
    </div>
  );
}
