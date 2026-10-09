'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { KeyRound, Smartphone, Mail, ShieldCheck, ArrowRight } from 'lucide-react';
import { Header } from '@/components/site/Header';
import { Footer } from '@/components/site/Footer';
import { BrandMark } from '@/components/site/BrandMark';
import { GoogleSignInButton } from '@/components/site/GoogleSignInButton';
import { googleSignIn } from '@/lib/google-auth';
import { useUyanixStore } from '@/lib/store';
import { validateSafeInternalRedirect } from '@/lib/seo-canonical-url-governance';
import { toast } from 'sonner';

export default function LoginPage() {
  const router = useRouter();
  const { login, syncServerSession } = useUyanixStore();

  const [mode, setMode] = useState<'password' | 'otp' | 'forgot'>('password');
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [otpSent, setOtpSent] = useState(false);
  const [otpCode, setOtpCode] = useState('');
  const [resetSent, setResetSent] = useState(false);
  const [googleLoading, setGoogleLoading] = useState(false);

  const handleGoogleAuth = async () => {
    setGoogleLoading(true);
    try {
      const res = await googleSignIn();
      if (res?.user && res?.serverUser) {
        login(res.serverUser);
        toast.success('Signed in with Google Workspace & Sheets access! 🚀');
        const dest =
          res.serverUser.role === 'admin'
            ? '/admin'
            : res.serverUser.role === 'teacher'
            ? '/teacher'
            : '/dashboard';
        router.push(dest);
        router.refresh();
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Google Sign-In failed';
      toast.error(message);
    } finally {
      setGoogleLoading(false);
    }
  };

  const handlePasswordLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ identifier, password }),
      });
      const data = await res.json();
      if (!res.ok || !data.user) {
        toast.error(data.error || 'Invalid email/mobile or password.');
        return;
      }
      const authoritativeUser = (await syncServerSession()) || data.user;
      login(authoritativeUser);
      setPassword('');
      toast.success('Welcome back to Uyanix 30 Days Challenge! 🚀');
      const params = new URLSearchParams(window.location.search);
      const defaultDest =
        authoritativeUser?.role === 'admin'
          ? '/admin'
          : authoritativeUser?.role === 'teacher'
          ? '/teacher'
          : '/dashboard';
      const rawRedirect = params.get('redirect') || defaultDest;
      const redirectValidation = validateSafeInternalRedirect(
        rawRedirect,
        defaultDest
      );
      const redirectTo = redirectValidation.ok
        ? redirectValidation.safeRedirectPath
        : redirectValidation.safeFallbackPath;
      router.push(redirectTo as any);
      router.refresh();
    } catch {
      toast.error('Authentication failed. Please try again.');
    }
  };

  const handleOtpSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const targetPhone = identifier.replace(/\D/g, '') || '9000012345';
      if (!otpSent) {
        const res = await fetch('/api/auth/otp', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ action: 'send', phone: targetPhone }),
        });
        const data = await res.json();
        if (!res.ok) {
          toast.error(data.error || 'Unable to send OTP.');
          return;
        }
        setOtpSent(true);
        toast.success(
          '6-digit OTP aapke registered mobile number par bhej diya gaya hai!'
        );
        return;
      }

      const trimmedOtp = otpCode.trim();
      if (!/^\d{6}$/.test(trimmedOtp)) {
        toast.error('Valid 6-digit OTP enter karein.');
        return;
      }

      const verifyRes = await fetch('/api/auth/otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          action: 'verify',
          phone: targetPhone,
          otpCode: trimmedOtp,
        }),
      });
      const verifyData = await verifyRes.json();
      if (!verifyRes.ok || !verifyData.user) {
        toast.error(verifyData.error || 'Invalid or expired OTP.');
        return;
      }

      const authoritativeUser = (await syncServerSession()) || verifyData.user;
      login(authoritativeUser);
      setOtpCode('');
      toast.success('Mobile OTP Verified! Redirecting...');
      const defaultDest =
        authoritativeUser?.role === 'admin'
          ? '/admin'
          : authoritativeUser?.role === 'teacher'
          ? '/teacher'
          : '/dashboard';
      router.push(defaultDest as any);
      router.refresh();
    } catch {
      toast.error('OTP verification failed. Please try again.');
    }
  };

  const handleForgotSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch('/api/auth/forgot', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identifier }),
      });
      const data = await res.json();
      if (!res.ok) {
        toast.error(data.error || 'Unable to send password reset link.');
        return;
      }
      setResetSent(true);
      toast.success('Password reset link aapke email/SMS par bhej diya gaya hai!');
    } catch {
      toast.error('Unable to process password reset request.');
    }
  };

  const handleDemoAttempt = async (requestedRole: 'student' | 'teacher' | 'admin') => {
    try {
      const res = await fetch('/api/auth/demo', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role: requestedRole }),
      });
      const data = await res.json();
      if (!res.ok || !data.user) {
        toast.error(
          data.error ||
            'Quick Demo login is currently unavailable. Please sign in with registered credentials.'
        );
        return;
      }
      const authoritativeUser = (await syncServerSession()) || data.user;
      login(authoritativeUser);
      toast.success(`Welcome in Demo Mode as ${authoritativeUser.name}! 🚀`);
      const dest =
        authoritativeUser.role === 'admin'
          ? '/admin'
          : authoritativeUser.role === 'teacher'
          ? '/teacher'
          : '/dashboard';
      router.push(dest as any);
      router.refresh();
    } catch {
      toast.error('Demo login failed. Please try again.');
    }
  };

  return (
    <div className="min-h-screen bg-background">
      <Header />

      <section className="mx-auto max-w-md px-4 py-14 sm:px-6">
        <div className="text-center">
          <div className="mx-auto inline-flex">
            <BrandMark size={52} />
          </div>
          <h1 className="mt-3 text-3xl font-extrabold">Welcome Back 👋</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Apne Uyanix 30 Days Challenge account mein login karein
          </p>
        </div>

        {/* Mode Switcher Tabs */}
        <div className="mt-6 grid grid-cols-3 gap-1 rounded-2xl border border-border bg-muted/60 p-1 text-xs font-semibold">
          <button
            type="button"
            onClick={() => setMode('password')}
            className={`rounded-xl py-2 transition ${
              mode === 'password' ? 'bg-card text-foreground shadow-sm' : 'text-muted-foreground'
            }`}
          >
            Password
          </button>
          <button
            type="button"
            onClick={() => setMode('otp')}
            className={`rounded-xl py-2 transition ${
              mode === 'otp' ? 'bg-card text-foreground shadow-sm' : 'text-muted-foreground'
            }`}
          >
            Mobile OTP
          </button>
          <button
            type="button"
            onClick={() => setMode('forgot')}
            className={`rounded-xl py-2 transition ${
              mode === 'forgot' ? 'bg-card text-foreground shadow-sm' : 'text-muted-foreground'
            }`}
          >
            Reset Pass
          </button>
        </div>

        <div className="mt-6 rounded-3xl border border-border bg-card p-6 shadow-card">
          {mode === 'password' && (
            <form onSubmit={handlePasswordLogin} className="space-y-4">
              <label className="block">
                <span className="mb-1.5 block text-xs font-semibold text-muted-foreground">
                  Email or 10-Digit Mobile
                </span>
                <div className="relative">
                  <Mail className="absolute left-3.5 top-3.5 h-4 w-4 text-muted-foreground" />
                  <input
                    required
                    value={identifier}
                    onChange={(e) => setIdentifier(e.target.value)}
                    placeholder="dollysingh1268@gmail.com"
                    className="h-11 w-full rounded-xl border border-input bg-background pl-10 pr-4 text-sm outline-none focus:border-primary"
                  />
                </div>
              </label>

              <label className="block">
                <span className="mb-1.5 block text-xs font-semibold text-muted-foreground">
                  Password
                </span>
                <div className="relative">
                  <KeyRound className="absolute left-3.5 top-3.5 h-4 w-4 text-muted-foreground" />
                  <input
                    required
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••"
                    className="h-11 w-full rounded-xl border border-input bg-background pl-10 pr-4 text-sm outline-none focus:border-primary"
                  />
                </div>
              </label>

              <button
                type="submit"
                className="inline-flex h-12 w-full items-center justify-center gap-2 rounded-full bg-gradient-hero text-sm font-semibold text-primary-foreground shadow-soft transition hover:scale-[1.01]"
              >
                Login to Dashboard <ArrowRight className="h-4 w-4" />
              </button>
            </form>
          )}

          {mode === 'otp' && (
            <form onSubmit={handleOtpSubmit} className="space-y-4">
              <label className="block">
                <span className="mb-1.5 block text-xs font-semibold text-muted-foreground">
                  Registered Mobile Number
                </span>
                <div className="flex gap-2">
                  <span className="inline-flex h-11 items-center rounded-xl border border-input bg-accent/50 px-3 text-sm font-semibold text-muted-foreground">
                    +91
                  </span>
                  <input
                    required
                    type="tel"
                    placeholder="9000012345"
                    value={identifier.replace(/\D/g, '') || '9000012345'}
                    onChange={(e) => setIdentifier(e.target.value)}
                    className="h-11 w-full rounded-xl border border-input bg-background px-4 text-sm outline-none focus:border-primary"
                  />
                </div>
              </label>

              {otpSent && (
                <label className="block">
                  <span className="mb-1.5 block text-xs font-semibold text-muted-foreground">
                    Enter 6-Digit OTP (Demo: 123456)
                  </span>
                  <input
                    required
                    placeholder="123456"
                    maxLength={6}
                    value={otpCode}
                    onChange={(e) => setOtpCode(e.target.value)}
                    className="h-11 w-full rounded-xl border border-input bg-background px-4 text-center font-mono text-base tracking-widest outline-none focus:border-primary"
                  />
                </label>
              )}

              <button
                type="submit"
                className="inline-flex h-12 w-full items-center justify-center gap-2 rounded-full bg-gradient-hero text-sm font-semibold text-primary-foreground shadow-soft"
              >
                <Smartphone className="h-4 w-4" />
                {otpSent ? 'Verify OTP & Login' : 'Send OTP on SMS'}
              </button>
            </form>
          )}

          {mode === 'forgot' && (
            <form onSubmit={handleForgotSubmit} className="space-y-4">
              <p className="text-xs text-muted-foreground">
                Apna registered email ya mobile number daalein. Hum aapko instant password reset link bhejenge.
              </p>
              <input
                required
                placeholder="Enter email or mobile"
                value={identifier}
                onChange={(e) => setIdentifier(e.target.value)}
                className="h-11 w-full rounded-xl border border-input bg-background px-4 text-sm outline-none focus:border-primary"
              />
              {resetSent && (
                <div className="rounded-xl bg-secondary/15 p-3 text-xs font-medium text-secondary">
                  ✅ Reset instructions sent! Check your inbox or SMS.
                </div>
              )}
              <button
                type="submit"
                className="inline-flex h-12 w-full items-center justify-center rounded-full bg-primary text-sm font-semibold text-primary-foreground shadow-soft"
              >
                Send Password Reset Link
              </button>
            </form>
          )}

          {/* Google Workspace Sign-In */}
          <div className="mt-6 border-t border-border pt-4 text-center">
            <div className="mb-2.5 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
              Google Workspace &amp; Sheets Sync
            </div>
            <div className="flex justify-center">
              <GoogleSignInButton
                onClick={handleGoogleAuth}
                disabled={googleLoading}
                label={googleLoading ? 'Signing in with Google...' : 'Sign in with Google'}
              />
            </div>
          </div>

          {/* Quick Demo Role Login */}
          <div className="mt-5 border-t border-border pt-4">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground text-center">
              Quick Demo Access (1-Click)
            </div>
            <div className="mt-2.5 grid grid-cols-3 gap-2">
              <button
                type="button"
                onClick={() => handleDemoAttempt('student')}
                className="rounded-xl border border-border bg-muted/40 py-2 text-xs font-semibold hover:bg-accent"
              >
                🎓 Student
              </button>
              <button
                type="button"
                onClick={() => handleDemoAttempt('teacher')}
                className="rounded-xl border border-border bg-muted/40 py-2 text-xs font-semibold hover:bg-accent"
              >
                👩‍🏫 Teacher
              </button>
              <button
                type="button"
                onClick={() => handleDemoAttempt('admin')}
                className="rounded-xl border border-border bg-muted/40 py-2 text-xs font-semibold hover:bg-accent"
              >
                🛡️ Admin
              </button>
            </div>
          </div>

          <p className="mt-5 text-center text-xs text-muted-foreground">
            Naya account banana hai?{' '}
            <Link href="/register" className="font-semibold text-primary hover:underline">
              Register FREE
            </Link>
          </p>
        </div>

        <div className="mt-4 flex items-center justify-center gap-2 text-xs text-muted-foreground">
          <ShieldCheck className="h-4 w-4 text-secondary" />
          256-bit JWT Encrypted Session &amp; Rate-Limited Auth
        </div>
      </section>

      <Footer />
    </div>
  );
}
