'use client';

import React, { useState, useRef, Suspense, useEffect } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import {
  ShieldCheck,
  Upload,
  CheckCircle2,
  Sparkles,
  AlertCircle,
  GraduationCap,
  Users,
  Check,
} from 'lucide-react';
import { Header } from '@/components/site/Header';
import { Footer } from '@/components/site/Footer';
import { BrandMark } from '@/components/site/BrandMark';
import { useUyanixStore } from '@/lib/store';
import { toast } from 'sonner';
import confetti from 'canvas-confetti';

const WEAK_PASSWORDS = new Set([
  '123456',
  '1234567',
  '12345678',
  '123456789',
  'password',
  'password123',
  'admin123',
  'qwerty',
  'abc123',
  '000000',
  '111111',
]);

function RegisterContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const refCode = searchParams.get('ref');

  const { currentUser, login, submitStudentIdVerification } = useUyanixStore();

  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [accountType, setAccountType] = useState<'student' | 'teacher'>('student');
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
  const [isVerifying, setIsVerifying] = useState(false);

  // Field-level error validation mapping
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [serverError, setServerError] = useState<string>('');

  const submittingLockRef = useRef(false);

  useEffect(() => {
    if (currentUser?.id && !currentUser.idVerified && step === 1) {
      setStep(2);
    }
  }, [currentUser, step]);

  useEffect(() => {
    if (step === 3) {
      try {
        confetti({
          particleCount: 90,
          spread: 75,
          origin: { y: 0.6 },
          colors: ['#7c3aed', '#10b981', '#f97316', '#fde047'],
        });
      } catch {}
    }
  }, [step]);

  const validateForm = () => {
    const errors: Record<string, string> = {};
    const trimmedName = name.trim();
    if (!trimmedName || trimmedName.length < 2) {
      errors.name = 'Pura naam likhein (kam se kam 2 akshar).';
    } else if (/[<>`$\\{};[\]|^~]/.test(trimmedName)) {
      errors.name = 'Naam mein special characters allow nahi hain.';
    }

    const trimmedSchool = school.trim();
    if (!trimmedSchool || trimmedSchool.length < 2) {
      errors.school = accountType === 'teacher' ? 'School / Institute ka naam likhein.' : 'School ka naam enter karein.';
    }

    const cleanPhone = phone.trim().replace(/\D/g, '');
    if (!cleanPhone || cleanPhone.length !== 10) {
      errors.phone = '10-digit valid mobile number enter karein.';
    } else if (!/^[6-9]\d{9}$/.test(cleanPhone)) {
      errors.phone = 'Mobile number 6, 7, 8 ya 9 se shuru hona chahiye.';
    }

    if (email.trim() && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
      errors.email = 'Valid email address enter karein (e.g. name@gmail.com).';
    }

    const trimmedPassword = password.trim();
    if (!trimmedPassword || trimmedPassword.length < 6) {
      errors.password = 'Password kam se kam 6 characters ka hona chahiye.';
    } else if (WEAK_PASSWORDS.has(trimmedPassword.toLowerCase())) {
      errors.password = 'Yeh password bahut aasan hai. Koi strong password chunein (jaise Student@123).';
    }

    if (password !== confirmPassword) {
      errors.confirmPassword = 'Password aur Confirm Password match nahi kar rahe.';
    }

    if (!agreed) {
      errors.agreed = 'Aage badhne ke liye Terms & Conditions accept karein.';
    }

    setFieldErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const handleStep1Submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setServerError('');

    if (!validateForm()) {
      toast.error('Kripya form ki galtiyan theek karein (red me highlighted fields dekhein).');
      return;
    }

    if (submittingLockRef.current || isSubmitting) return;

    submittingLockRef.current = true;
    setIsSubmitting(true);

    const idempotencyKey = `reg_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;

    try {
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Idempotency-Key': idempotencyKey,
        },
        credentials: 'include',
        body: JSON.stringify({
          name: name.trim(),
          classNum: Number(classNum),
          school: school.trim(),
          phone: phone.trim().replace(/\D/g, '').slice(-10),
          email: email.trim() || undefined,
          password,
          confirmPassword,
          agreed,
          referralCode: refCode || undefined,
          idempotencyKey,
        }),
      });

      const data = await res.json();

      if (!res.ok || !data.user) {
        const errorMsg = data?.error || 'Registration failed. Please check your details.';
        setServerError(errorMsg);

        if (errorMsg.toLowerCase().includes('mobile') || errorMsg.toLowerCase().includes('phone')) {
          setFieldErrors((prev) => ({ ...prev, phone: errorMsg }));
        } else if (errorMsg.toLowerCase().includes('password')) {
          setFieldErrors((prev) => ({ ...prev, password: errorMsg }));
        } else if (errorMsg.toLowerCase().includes('name')) {
          setFieldErrors((prev) => ({ ...prev, name: errorMsg }));
        } else if (errorMsg.toLowerCase().includes('school')) {
          setFieldErrors((prev) => ({ ...prev, school: errorMsg }));
        }

        toast.error(errorMsg);
        return;
      }

      login(data.user);
      setPassword('');
      setConfirmPassword('');

      if (accountType === 'teacher') {
        toast.success('Teacher Account ban gaya! Welcome to Educator Hub 👩‍🏫');
        router.push('/teacher');
        router.refresh();
        return;
      }

      toast.success('Account ban gaya! Step 2: Apna Student ID verify karein 🪪');
      setStep(2);
    } catch {
      const netError = 'Network error during registration. Please check your internet connection.';
      setServerError(netError);
      toast.error(netError);
    } finally {
      submittingLockRef.current = false;
      setIsSubmitting(false);
    }
  };

  const handleStep2Verify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isVerifying) return;
    setIsVerifying(true);

    try {
      const doc = idFileName || 'school-id-card.jpg';

      await fetch('/api/user/profile', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ idCardName: doc }),
      }).catch(() => {});

      const verifyRes = await fetch('/api/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          documentName: doc,
          classNum: Number(classNum),
        }),
      });

      const verifyData = await verifyRes.json();
      if (!verifyRes.ok && verifyData?.error) {
        toast.error(verifyData.error || 'Verification upload failed. Aap dashboard se baad me try kar sakte hain.');
      } else {
        toast.success('Student ID uploaded & submitted for verification! 🎉');
      }

      submitStudentIdVerification(doc);
      setStep(3);
    } catch {
      toast.info('Student ID saved locally! Challenge unlocked 🎉');
      setStep(3);
    } finally {
      setIsVerifying(false);
    }
  };

  const steps = [
    { num: 1, label: 'Register' },
    { num: 2, label: 'Verify ID' },
    { num: 3, label: 'Start Challenge' },
  ];

  return (
    <section className="animate-fade-up mx-auto grid max-w-6xl gap-10 px-4 py-12 sm:px-6 md:grid-cols-5">
      <div className="md:col-span-3">
        <div className="flex items-center gap-3">
          <div className="transition-transform hover:scale-105">
            <BrandMark size={56} />
          </div>
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

        {/* 3-Step Indicator */}
        <div className="mt-8 flex items-start justify-center gap-2">
          {steps.map((s, idx) => {
            const isActive = step >= s.num;
            return (
              <div key={s.num} className="flex items-start">
                <div className="flex w-24 flex-col items-center gap-1.5">
                  <div
                    className={`flex h-8 w-8 items-center justify-center rounded-full text-xs font-bold tabular-nums transition-all duration-300 ${
                      isActive
                        ? 'bg-gradient-hero text-primary-foreground scale-110 shadow-soft'
                        : 'border border-border bg-background text-muted-foreground'
                    }`}
                  >
                    {step > s.num ? <Check className="h-4 w-4" /> : s.num}
                  </div>
                  <span
                    className={`text-[11px] font-semibold transition-colors duration-200 ${
                      isActive ? 'text-foreground' : 'text-muted-foreground'
                    }`}
                  >
                    {s.label}
                  </span>
                </div>
                {idx < steps.length - 1 && (
                  <div className={`mt-4 h-0.5 w-8 sm:w-16 transition-colors duration-300 ${step > s.num ? 'bg-secondary' : 'bg-border'}`} />
                )}
              </div>
            );
          })}
        </div>

        {/* STEP 1: Registration Form */}
        {step === 1 && (
          <form
            onSubmit={handleStep1Submit}
            noValidate
            className="card-interactive mt-8 space-y-4 rounded-3xl border border-border bg-card p-6 shadow-card"
          >
            {/* Account Type Toggle */}
            <div className="flex rounded-2xl border border-border bg-muted/60 p-1 text-xs font-semibold">
              <button
                type="button"
                onClick={() => setAccountType('student')}
                className={`btn-interactive flex-1 flex items-center justify-center gap-1.5 rounded-xl py-2.5 transition ${
                  accountType === 'student' ? 'bg-card text-foreground shadow-sm' : 'text-muted-foreground'
                }`}
              >
                <GraduationCap className="h-4 w-4 text-primary" /> Student (Class 1–12)
              </button>
              <button
                type="button"
                onClick={() => setAccountType('teacher')}
                className={`btn-interactive flex-1 flex items-center justify-center gap-1.5 rounded-xl py-2.5 transition ${
                  accountType === 'teacher' ? 'bg-card text-foreground shadow-sm' : 'text-muted-foreground'
                }`}
              >
                <Users className="h-4 w-4 text-saffron" /> Teacher / Mentor
              </button>
            </div>

            <div className="text-center pt-2">
              <h2 className="text-xl font-bold">
                {accountType === 'student' ? 'Student Registration' : 'Teacher / Mentor Registration'}
              </h2>
              <p className="text-xs text-muted-foreground">
                {accountType === 'student'
                  ? '30-Day Learning Challenge ke liye register karein'
                  : 'Referral program aur student progress monitor karne ke liye'}
              </p>
            </div>

            {/* Server Error Alert Banner */}
            {serverError && (
              <div className="animate-shake-x flex items-start gap-2.5 rounded-2xl border border-destructive/40 bg-destructive/10 p-3.5 text-xs text-destructive">
                <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
                <div>
                  <b>Registration Error:</b> {serverError}
                </div>
              </div>
            )}

            {/* Name */}
            <label className="block">
              <span className="mb-1.5 block text-xs font-semibold text-muted-foreground">
                {accountType === 'student' ? 'Student Full Name' : 'Teacher Full Name'} *
              </span>
              <input
                required
                placeholder={accountType === 'student' ? 'e.g. Aarav Sharma' : 'e.g. Sunita Verma'}
                value={name}
                onChange={(e) => {
                  setName(e.target.value);
                  if (fieldErrors.name) setFieldErrors((prev) => ({ ...prev, name: '' }));
                }}
                className={`h-11 w-full rounded-xl border bg-background px-4 text-sm outline-none transition-all ${
                  fieldErrors.name
                    ? 'border-destructive ring-2 ring-destructive/20'
                    : 'border-input focus:border-primary focus:ring-2 focus:ring-primary/20'
                }`}
              />
              {fieldErrors.name && (
                <span className="mt-1 block text-xs text-destructive font-medium">{fieldErrors.name}</span>
              )}
            </label>

            {/* Class & School */}
            <div className="grid gap-4 sm:grid-cols-2">
              {accountType === 'student' ? (
                <label className="block">
                  <span className="mb-1.5 block text-xs font-semibold text-muted-foreground">
                    Class *
                  </span>
                  <select
                    value={classNum}
                    onChange={(e) => setClassNum(e.target.value)}
                    className="h-11 w-full rounded-xl border border-input bg-background px-4 text-sm outline-none transition-all focus:border-primary focus:ring-2 focus:ring-primary/20"
                  >
                    {Array.from({ length: 12 }, (_, i) => i + 1).map((c) => (
                      <option key={c} value={String(c)}>
                        Class {c}
                      </option>
                    ))}
                  </select>
                </label>
              ) : (
                <label className="block">
                  <span className="mb-1.5 block text-xs font-semibold text-muted-foreground">
                    Role Title
                  </span>
                  <input
                    disabled
                    value="Educator / Mentor"
                    className="h-11 w-full rounded-xl border border-input bg-muted px-4 text-sm text-muted-foreground"
                  />
                </label>
              )}

              <label className="block">
                <span className="mb-1.5 block text-xs font-semibold text-muted-foreground">
                  {accountType === 'student' ? 'School Name' : 'School / Institute Name'} *
                </span>
                <input
                  required
                  placeholder="e.g. Delhi Public School"
                  value={school}
                  onChange={(e) => {
                    setSchool(e.target.value);
                    if (fieldErrors.school) setFieldErrors((prev) => ({ ...prev, school: '' }));
                  }}
                  className={`h-11 w-full rounded-xl border bg-background px-4 text-sm outline-none transition-all ${
                    fieldErrors.school
                      ? 'border-destructive ring-2 ring-destructive/20'
                      : 'border-input focus:border-primary focus:ring-2 focus:ring-primary/20'
                  }`}
                />
                {fieldErrors.school && (
                  <span className="mt-1 block text-xs text-destructive font-medium">{fieldErrors.school}</span>
                )}
              </label>
            </div>

            {/* Mobile Number */}
            <label className="block">
              <span className="mb-1.5 block text-xs font-semibold text-muted-foreground">
                Mobile Number (10 Digits) *
              </span>
              <div className="flex gap-2">
                <span className="inline-flex h-11 items-center rounded-xl border border-input bg-accent/50 px-3 text-sm font-semibold text-muted-foreground">
                  +91
                </span>
                <input
                  required
                  pattern="[0-9]{10}"
                  placeholder="e.g. 9876543210 (starts with 6-9)"
                  type="tel"
                  maxLength={10}
                  value={phone}
                  onChange={(e) => {
                    setPhone(e.target.value.replace(/\D/g, '').slice(0, 10));
                    if (fieldErrors.phone) setFieldErrors((prev) => ({ ...prev, phone: '' }));
                  }}
                  className={`h-11 w-full rounded-xl border bg-background px-4 text-sm outline-none transition-all ${
                    fieldErrors.phone
                      ? 'border-destructive ring-2 ring-destructive/20'
                      : 'border-input focus:border-primary focus:ring-2 focus:ring-primary/20'
                  }`}
                />
              </div>
              {fieldErrors.phone ? (
                <span className="mt-1 block text-xs text-destructive font-medium">{fieldErrors.phone}</span>
              ) : (
                <span className="mt-1 block text-[11px] text-muted-foreground">Indian mobile number starting with 6, 7, 8, or 9</span>
              )}
            </label>

            {/* Email */}
            <label className="block">
              <span className="mb-1.5 block text-xs font-semibold text-muted-foreground">
                Email Address (Optional)
              </span>
              <input
                placeholder="e.g. student@gmail.com"
                type="email"
                value={email}
                onChange={(e) => {
                  setEmail(e.target.value);
                  if (fieldErrors.email) setFieldErrors((prev) => ({ ...prev, email: '' }));
                }}
                className={`h-11 w-full rounded-xl border bg-background px-4 text-sm outline-none transition-all ${
                  fieldErrors.email
                    ? 'border-destructive ring-2 ring-destructive/20'
                    : 'border-input focus:border-primary focus:ring-2 focus:ring-primary/20'
                }`}
              />
              {fieldErrors.email && (
                <span className="mt-1 block text-xs text-destructive font-medium">{fieldErrors.email}</span>
              )}
            </label>

            {/* Passwords */}
            <div className="grid gap-4 sm:grid-cols-2">
              <label className="block">
                <span className="mb-1.5 block text-xs font-semibold text-muted-foreground">
                  Password (min 6 characters) *
                </span>
                <input
                  required
                  placeholder="e.g. Uyanix@2026"
                  type="password"
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value);
                    if (fieldErrors.password) setFieldErrors((prev) => ({ ...prev, password: '' }));
                  }}
                  className={`h-11 w-full rounded-xl border bg-background px-4 text-sm outline-none transition-all ${
                    fieldErrors.password
                      ? 'border-destructive ring-2 ring-destructive/20'
                      : 'border-input focus:border-primary focus:ring-2 focus:ring-primary/20'
                  }`}
                />
                {fieldErrors.password && (
                  <span className="mt-1 block text-xs text-destructive font-medium">{fieldErrors.password}</span>
                )}
              </label>

              <label className="block">
                <span className="mb-1.5 block text-xs font-semibold text-muted-foreground">
                  Confirm Password *
                </span>
                <input
                  required
                  placeholder="Repeat password"
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => {
                    setConfirmPassword(e.target.value);
                    if (fieldErrors.confirmPassword) setFieldErrors((prev) => ({ ...prev, confirmPassword: '' }));
                  }}
                  className={`h-11 w-full rounded-xl border bg-background px-4 text-sm outline-none transition-all ${
                    fieldErrors.confirmPassword
                      ? 'border-destructive ring-2 ring-destructive/20'
                      : 'border-input focus:border-primary focus:ring-2 focus:ring-primary/20'
                  }`}
                />
                {fieldErrors.confirmPassword && (
                  <span className="mt-1 block text-xs text-destructive font-medium">{fieldErrors.confirmPassword}</span>
                )}
              </label>
            </div>

            {/* Terms checkbox */}
            <label className="flex items-start gap-2 text-xs text-muted-foreground pt-1">
              <input
                type="checkbox"
                checked={agreed}
                onChange={(e) => {
                  setAgreed(e.target.checked);
                  if (fieldErrors.agreed) setFieldErrors((prev) => ({ ...prev, agreed: '' }));
                }}
                className="mt-0.5 h-4 w-4 rounded border-input accent-primary"
              />
              <span>
                I agree to the{' '}
                <Link href="/terms" className="font-semibold text-primary hover:underline">
                  Terms &amp; Conditions
                </Link>{' '}
                and Privacy Notice.
              </span>
            </label>
            {fieldErrors.agreed && (
              <span className="block text-xs text-destructive font-medium">{fieldErrors.agreed}</span>
            )}

            <button
              type="submit"
              disabled={isSubmitting}
              className="btn-interactive animate-aura mt-2 inline-flex h-12 w-full items-center justify-center gap-2 rounded-full bg-gradient-hero text-sm font-semibold text-primary-foreground shadow-soft disabled:opacity-60"
            >
              {isSubmitting ? 'Verifying Details...' : 'Create Account & Continue →'}
            </button>

            <p className="text-center text-xs text-muted-foreground pt-1">
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
            className="animate-pop-in card-interactive mt-8 space-y-5 rounded-3xl border border-border bg-card p-6 shadow-card"
          >
            <div className="text-center">
              <span className="inline-flex items-center gap-1.5 rounded-full bg-primary/10 px-3 py-1 text-xs font-semibold text-primary">
                Student: {currentUser?.name || name} (Class {currentUser?.classNum || classNum})
              </span>
              <h2 className="mt-2 text-xl font-bold">Verify Your Student ID 🪪</h2>
              <p className="mt-1 text-xs text-muted-foreground">
                School ID card, Report Card ya School Dress ki photo upload karein taaki aapki Class confirm ho sake.
              </p>
            </div>

            <label className="flex cursor-pointer flex-col items-center justify-center rounded-2xl border-2 border-dashed border-primary/40 bg-accent/30 p-8 text-center transition-all duration-200 hover:bg-accent/50 hover:border-primary">
              <Upload className="animate-bounce-subtle h-8 w-8 text-primary" />
              <span className="mt-2 text-sm font-semibold">
                {idFileName ? `Selected: ${idFileName}` : 'Click to upload School ID / Report Card / Uniform Photo'}
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
                disabled={isVerifying}
                className="btn-interactive inline-flex h-12 flex-1 items-center justify-center gap-2 rounded-full bg-gradient-hero px-6 text-sm font-semibold text-primary-foreground shadow-soft disabled:opacity-60"
              >
                {isVerifying ? 'Uploading & Verifying...' : 'Upload & Unlock Challenge →'}
              </button>
              <button
                type="button"
                onClick={() => {
                  toast.info('Verification deferred — aap baad mein Dashboard se bhi upload kar sakte hain.');
                  setStep(3);
                }}
                className="btn-interactive inline-flex h-12 items-center justify-center rounded-full border border-border px-5 text-xs font-semibold hover:bg-accent"
              >
                Verify Later
              </button>
            </div>
          </form>
        )}

        {/* STEP 3: Start Challenge */}
        {step === 3 && (
          <div className="animate-pop-in card-interactive mt-8 rounded-3xl border border-border bg-card p-8 text-center shadow-card">
            <div className="animate-trophy-glow mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-secondary/15 text-secondary">
              <CheckCircle2 className="h-9 w-9" />
            </div>
            <h2 className="mt-4 text-2xl font-bold">Badhai Ho! Aapka Challenge Ready Hai 🎉</h2>
            <p className="mx-auto mt-2 max-w-md text-sm text-muted-foreground leading-relaxed">
              Aapka FREE registration complete ho gaya hai. Aaj se apna Day 1 chapter aur 5 MCQs shuru karein!
            </p>
            <div className="mt-6 flex flex-wrap justify-center gap-3">
              <Link
                href="/dashboard"
                className="btn-interactive inline-flex h-12 items-center rounded-full bg-gradient-hero px-7 text-sm font-semibold text-primary-foreground shadow-soft"
              >
                Go to Student Dashboard →
              </Link>
              <Link
                href="/daily/1"
                className="btn-interactive inline-flex h-12 items-center rounded-full border border-border bg-card px-7 text-sm font-semibold hover:bg-accent"
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
          <div className="card-interactive rounded-3xl border border-border bg-card p-6 shadow-card">
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

          <div className="card-interactive rounded-3xl border border-border bg-accent/60 p-6">
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
