'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import {
  ShieldCheck,
  Star,
  Trophy,
  Flame,
  Users,
  GraduationCap,
  ClipboardList,
  Sparkles,
  ChevronDown,
} from 'lucide-react';
import { Header } from '@/components/site/Header';
import { Footer } from '@/components/site/Footer';
import { Countdown } from '@/components/site/Countdown';
import { PrizesSection } from '@/components/site/PrizesSection';

const FAQS = [
  {
    q: 'Yeh challenge kya hai?',
    a: 'Uyanix 30 Days Challenge India ka sabse exciting daily learning competition hai Class 1 se Class 12 ke students ke liye. Har roz aapko apne class ke hisaab se 1 short chapter aur 5 MCQs milte hain (~10 mins). 30 din complete karne ke baad aap Final Exam dekar Laptop, Tablet, Smartphone aur Guaranteed Certificate jeet sakte hain!',
  },
  {
    q: 'Registration fee kitni hai?',
    a: 'Registration bilkul FREE (₹0) hai! Aap bina kisi payment ke apna account bana sakte hain aur 30 days tak roz daily chapters aur quizzes solve kar sakte hain. ₹199 exam fee sirf tab deni hoti hai jab aap 15-day Mid Exam ya 30-day Final Exam mein baithna chahein (Pay-Later model).',
  },
  {
    q: 'Prizes kab milenge?',
    a: '30-Day Final Exam khatam hone ke 7 working days ke andar Live Leaderboard par final verified results announce hote hain. Top 3 winners ko Laptop (1st), Tablet (2nd), aur Smartphone (3rd) unke ghar ke address par courier kiya jaata hai, aur har participant ko instant Digital Certificate + participation gift milta hai.',
  },
  {
    q: 'Kaun participate kar sakta hai?',
    a: 'India ke kisi bhi school/board (CBSE, ICSE, State Boards) ke Class 1 se Class 12 tak ke students participate kar sakte hain. Har student ko apni class ke level ka curriculum aur exam milta hai.',
  },
  {
    q: 'Agar koi din miss ho gaya toh?',
    a: 'Chinta mat karo! Agar kisi din school ya bimaari ki wajah se aapka daily task miss ho jaata hai, toh aap Dashboard ke 30-Day Tracker se pichle din ka chapter aur quiz agle din complete karke apna 30/30 progress poora kar sakte hain.',
  },
];

export default function HomePage() {
  const [openFaqIndex, setOpenFaqIndex] = useState<number | null>(0);

  return (
    <div className="min-h-screen bg-background">
      <Header />

      {/* Hero Section */}
      <section className="relative overflow-hidden">
        <div className="absolute inset-0 -z-10 bg-gradient-to-b from-accent/60 via-background to-background" />
        <div className="absolute left-1/2 top-10 -z-10 h-72 w-[40rem] -translate-x-1/2 rounded-full bg-primary/20 blur-3xl" />

        <div className="mx-auto grid max-w-7xl gap-10 px-4 py-16 sm:px-6 md:grid-cols-2 md:py-24">
          <div className="animate-fade-up">
            <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-border bg-card px-3 py-1 text-xs font-medium shadow-card">
              <span className="h-2 w-2 animate-pulse rounded-full bg-secondary" />
              Registrations Open • Class 1–12
            </div>

            <h1 className="text-4xl font-extrabold leading-[1.05] tracking-tight sm:text-5xl md:text-6xl">
              Seekho. <span className="text-gradient">Compete Karo.</span>{' '}
              <span className="text-secondary">Jeeto!</span>
            </h1>

            <p className="mt-5 max-w-lg text-base text-muted-foreground sm:text-lg">
              India ka sabse exciting 30-day learning challenge. Roz ek topic, ek exam aur jeeto Laptop, Tablet ya Smartphone — registration FREE, exam fee sirf challenge complete karne ke baad.
            </p>

            <div className="mt-7 flex flex-wrap items-center gap-3">
              <Link
                href="/register"
                className="inline-flex h-12 items-center rounded-full bg-gradient-hero px-7 text-sm font-semibold text-primary-foreground shadow-soft transition hover:scale-[1.03] whitespace-nowrap"
              >
                Register FREE
              </Link>
              <Link
                href="/leaderboard"
                className="inline-flex h-12 items-center rounded-full border border-border bg-card px-7 text-sm font-semibold transition hover:bg-accent whitespace-nowrap"
              >
                View Leaderboard
              </Link>
            </div>

            <div className="mt-6 flex items-center gap-4 text-xs text-muted-foreground">
              <div className="flex items-center gap-1.5">
                <ShieldCheck className="h-4 w-4 text-secondary" aria-hidden="true" />
                Secure Razorpay payment
              </div>
              <div className="flex items-center gap-1.5">
                <Star className="h-4 w-4 text-saffron" aria-hidden="true" />
                4.8/5 from parents
              </div>
            </div>

            <div className="mt-6 h-1.5 w-48 rounded-full bg-gradient-india" />
          </div>

          {/* Right Interactive Streak Preview Card */}
          <div className="relative animate-fade-up">
            <div className="card-interactive relative mx-auto w-full max-w-md rounded-3xl bg-card p-6 shadow-soft">
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-xs text-muted-foreground">Today&apos;s Streak</div>
                  <div className="mt-1 flex items-center gap-1 text-2xl font-bold tabular-nums">
                    <span className="animate-streak-fire inline-block">🔥</span> 12 days
                  </div>
                </div>
                <div className="rounded-full bg-secondary/10 px-3 py-1 text-xs font-semibold text-secondary animate-pulse-glow">
                  Live
                </div>
              </div>

              <div className="mt-6 grid grid-cols-6 gap-1.5">
                {Array.from({ length: 30 }, (_, i) => {
                  const dayNum = i + 1;
                  const isDone = dayNum <= 12;
                  const isToday = dayNum === 13;
                  return (
                    <Link
                      key={dayNum}
                      href={`/daily/${dayNum}`}
                      title={`Go to Day ${dayNum}`}
                      className={`aspect-square rounded-md transition-all duration-150 hover:scale-125 ${
                        isDone
                          ? 'bg-secondary'
                          : isToday
                          ? 'bg-primary ring-2 ring-primary/50 ring-offset-1 animate-pulse-glow'
                          : 'bg-muted hover:bg-muted-foreground/30'
                      }`}
                    />
                  );
                })}
              </div>

              <Link
                href="/daily/13"
                className="mt-6 block rounded-2xl bg-accent p-4 transition hover:opacity-95"
              >
                <div className="text-xs font-medium text-primary">Aaj ka task</div>
                <div className="mt-1 font-semibold">Day 13: Indian Constitution Basics</div>
                <div className="mt-1 text-xs text-muted-foreground">5 MCQs • ~10 mins</div>
              </Link>

              <div className="mt-4 grid grid-cols-3 gap-2 text-center">
                <div className="rounded-xl bg-muted/60 p-3">
                  <div className="mx-auto mb-1 flex h-7 w-7 items-center justify-center rounded-full bg-card text-primary">
                    <Trophy className="h-4 w-4" aria-hidden="true" />
                  </div>
                  <div className="text-sm font-bold tabular-nums">#7</div>
                  <div className="text-[10px] uppercase text-muted-foreground">Rank</div>
                </div>

                <div className="rounded-xl bg-muted/60 p-3">
                  <div className="mx-auto mb-1 flex h-7 w-7 items-center justify-center rounded-full bg-card text-primary">
                    <Flame className="h-4 w-4" aria-hidden="true" />
                  </div>
                  <div className="text-sm font-bold tabular-nums">40%</div>
                  <div className="text-[10px] uppercase text-muted-foreground">Done</div>
                </div>

                <div className="rounded-xl bg-muted/60 p-3">
                  <div className="mx-auto mb-1 flex h-7 w-7 items-center justify-center rounded-full bg-card text-primary">
                    <Users className="h-4 w-4" aria-hidden="true" />
                  </div>
                  <div className="text-sm font-bold tabular-nums">2,184</div>
                  <div className="text-[10px] uppercase text-muted-foreground">Live</div>
                </div>
              </div>
            </div>

            <div className="absolute -right-4 top-6 hidden rounded-2xl bg-gradient-gold p-3 text-xs font-bold text-foreground shadow-soft md:block animate-float">
              🥇 Win a Laptop
            </div>
          </div>
        </div>
      </section>

      {/* Social Proof Stats Bar */}
      <section className="border-y border-border bg-card/60">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-around gap-4 px-4 py-5 text-sm text-muted-foreground sm:px-6">
          <div className="flex items-center gap-2">
            <Users className="h-4 w-4 text-primary" aria-hidden="true" />
            <span>
              <b className="text-foreground tabular-nums">12,847</b> students already registered
            </span>
          </div>
          <div className="hidden h-6 w-px bg-border sm:block" />
          <div className="flex items-center gap-2">
            <GraduationCap className="h-4 w-4 text-primary" aria-hidden="true" />
            <span>
              Across <b className="text-foreground tabular-nums">320+</b> cities in India
            </span>
          </div>
          <div className="hidden h-6 w-px bg-border sm:block" />
          <div className="flex items-center gap-2">
            <Trophy className="h-4 w-4 text-primary" aria-hidden="true" />
            <span>
              Top 3 win <b className="text-foreground">Laptop, Tablet &amp; Smartphone</b>
            </span>
          </div>
        </div>
      </section>

      {/* How It Works — 4 Easy Steps */}
      <section className="mx-auto max-w-7xl px-4 py-20 sm:px-6">
        <div className="mx-auto max-w-2xl text-center">
          <p className="text-sm font-semibold uppercase tracking-widest text-primary">
            How it works
          </p>
          <h2 className="mt-2 text-3xl font-bold sm:text-4xl">
            4 easy steps to <span className="text-gradient">jeet</span>
          </h2>
        </div>

        <div className="mt-12 grid gap-5 md:grid-cols-4">
          <div className="relative rounded-3xl border border-border bg-card p-6 shadow-card transition hover:-translate-y-1 hover:shadow-soft">
            <div className="mb-4 inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-gradient-hero text-primary-foreground">
              <ClipboardList className="h-6 w-6" aria-hidden="true" />
            </div>
            <div className="text-xs font-bold text-primary">STEP 1</div>
            <div className="mt-1 text-lg font-semibold">Register</div>
            <p className="mt-1 text-sm text-muted-foreground">
              Account banao bilkul FREE — koi payment nahi.
            </p>
          </div>

          <div className="relative rounded-3xl border border-border bg-card p-6 shadow-card transition hover:-translate-y-1 hover:shadow-soft">
            <div className="mb-4 inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-gradient-hero text-primary-foreground">
              <Sparkles className="h-6 w-6" aria-hidden="true" />
            </div>
            <div className="text-xs font-bold text-primary">STEP 2</div>
            <div className="mt-1 text-lg font-semibold">30 Days Learning</div>
            <p className="mt-1 text-sm text-muted-foreground">
              Roz ek naya topic + 5 MCQs.
            </p>
          </div>

          <div className="relative rounded-3xl border border-border bg-card p-6 shadow-card transition hover:-translate-y-1 hover:shadow-soft">
            <div className="mb-4 inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-gradient-hero text-primary-foreground">
              <GraduationCap className="h-6 w-6" aria-hidden="true" />
            </div>
            <div className="text-xs font-bold text-primary">STEP 3</div>
            <div className="mt-1 text-lg font-semibold">Final Exam</div>
            <p className="mt-1 text-sm text-muted-foreground">
              150 questions, 45 minutes.
            </p>
          </div>

          <div className="relative rounded-3xl border border-border bg-card p-6 shadow-card transition hover:-translate-y-1 hover:shadow-soft">
            <div className="mb-4 inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-gradient-hero text-primary-foreground">
              <Trophy className="h-6 w-6" aria-hidden="true" />
            </div>
            <div className="text-xs font-bold text-primary">STEP 4</div>
            <div className="mt-1 text-lg font-semibold">Win Prizes</div>
            <p className="mt-1 text-sm text-muted-foreground">
              Laptop, Tablet, Phone + certificate.
            </p>
          </div>
        </div>
      </section>

      {/* Prizes Section */}
      <PrizesSection />

      {/* Countdown Banner */}
      <section className="mx-auto max-w-7xl px-4 py-16 sm:px-6">
        <div className="overflow-hidden rounded-3xl bg-gradient-hero p-8 text-primary-foreground shadow-soft md:p-12">
          <div className="grid items-center gap-8 md:grid-cols-2">
            <div>
              <p className="text-sm font-semibold uppercase tracking-widest opacity-80">
                Hurry up!
              </p>
              <h2 className="mt-2 text-3xl font-bold sm:text-4xl">
                Registration closes in
              </h2>
              <p className="mt-2 max-w-md opacity-90">
                Next batch shuru hone wala hai. Apni seat aaj hi book kar lo.
              </p>
              <Link
                href="/register"
                className="mt-6 inline-flex h-12 items-center rounded-full bg-card px-7 text-sm font-semibold text-primary shadow-soft transition hover:scale-[1.03] whitespace-nowrap"
              >
                Register FREE
              </Link>
            </div>
            <div className="flex justify-center md:justify-end">
              <Countdown />
            </div>
          </div>
        </div>
      </section>

      {/* Real Stories / Testimonials */}
      <section className="mx-auto max-w-7xl px-4 py-20 sm:px-6">
        <div className="mx-auto max-w-2xl text-center">
          <p className="text-sm font-semibold uppercase tracking-widest text-primary">
            Real Stories
          </p>
          <h2 className="mt-2 text-3xl font-bold sm:text-4xl">
            Students kya keh rahe hain
          </h2>
        </div>

        <div className="mt-12 grid gap-5 md:grid-cols-3">
          <div className="rounded-3xl border border-border bg-card p-6 shadow-card">
            <div className="text-3xl">🌟</div>
            <p className="mt-3 text-sm leading-relaxed">
              &quot;Bahut maza aaya! Roz kuch naya seekha aur naya tablet bhi jeeta. 💜&quot;
            </p>
            <div className="mt-5 border-t border-border pt-4">
              <div className="font-semibold">Riya Agarwal</div>
              <div className="text-xs text-muted-foreground">Class 7, Jaipur</div>
            </div>
          </div>

          <div className="rounded-3xl border border-border bg-card p-6 shadow-card">
            <div className="text-3xl">🚀</div>
            <p className="mt-3 text-sm leading-relaxed">
              &quot;30 din ka challenge ne meri study habit hi badal di. Highly recommended!&quot;
            </p>
            <div className="mt-5 border-t border-border pt-4">
              <div className="font-semibold">Mohammed Faizan</div>
              <div className="text-xs text-muted-foreground">Class 10, Hyderabad</div>
            </div>
          </div>

          <div className="rounded-3xl border border-border bg-card p-6 shadow-card">
            <div className="text-3xl">🎉</div>
            <p className="mt-3 text-sm leading-relaxed">
              &quot;Mujhe certificate aur gift dono mile. Mummy bhi bahut khush hain!&quot;
            </p>
            <div className="mt-5 border-t border-border pt-4">
              <div className="font-semibold">Sneha Kulkarni</div>
              <div className="text-xs text-muted-foreground">Class 5, Pune</div>
            </div>
          </div>
        </div>
      </section>

      {/* FAQs Accordion */}
      <section className="bg-accent/40 py-20">
        <div className="mx-auto max-w-3xl px-4 sm:px-6">
          <div className="text-center">
            <p className="text-sm font-semibold uppercase tracking-widest text-primary">
              FAQs
            </p>
            <h2 className="mt-2 text-3xl font-bold sm:text-4xl">
              Aapke sawaal, hamare jawaab
            </h2>
          </div>

          <div className="mt-10 space-y-3">
            {FAQS.map((faq, idx) => {
              const isOpen = openFaqIndex === idx;
              return (
                <div
                  key={faq.q}
                  className="rounded-2xl border border-border bg-card px-5"
                >
                  <h3 className="flex">
                    <button
                      type="button"
                      aria-expanded={isOpen}
                      onClick={() => setOpenFaqIndex(isOpen ? null : idx)}
                      className="flex flex-1 items-center justify-between py-4 text-left text-sm font-semibold transition-all hover:text-primary cursor-pointer"
                    >
                      {faq.q}
                      <ChevronDown
                        className={`h-4 w-4 shrink-0 text-muted-foreground transition-transform duration-300 ease-out ${
                          isOpen ? 'rotate-180 text-primary' : ''
                        }`}
                        aria-hidden="true"
                      />
                    </button>
                  </h3>
                  <div
                    className={`grid transition-all duration-300 ease-out ${
                      isOpen ? 'grid-rows-[1fr] opacity-100 pb-4' : 'grid-rows-[0fr] opacity-0 pb-0'
                    }`}
                  >
                    <div className="overflow-hidden text-sm text-muted-foreground leading-relaxed">
                      {faq.a}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* Bottom CTA */}
      <section className="mx-auto max-w-7xl px-4 py-20 sm:px-6">
        <div className="rounded-3xl border border-border bg-card p-10 text-center shadow-card">
          <h2 className="text-3xl font-bold sm:text-4xl">
            Ready ho? <span className="text-gradient">Challenge accept karo!</span>
          </h2>
          <p className="mx-auto mt-3 max-w-xl text-muted-foreground">
            12,847+ students already in. Aap kab join karoge?
          </p>
          <Link
            href="/register"
            className="mt-7 inline-flex h-12 items-center rounded-full bg-gradient-hero px-8 text-sm font-semibold text-primary-foreground shadow-soft transition hover:scale-[1.03] whitespace-nowrap"
          >
            Register FREE
          </Link>
        </div>
      </section>

      <Footer />

      {/* Mobile Floating CTA */}
      <Link
        href="/register"
        className="fixed bottom-4 left-1/2 z-50 inline-flex h-12 -translate-x-1/2 items-center gap-2 rounded-full bg-gradient-hero px-6 text-sm font-semibold text-primary-foreground shadow-soft md:hidden whitespace-nowrap"
      >
        <Trophy className="h-4 w-4" aria-hidden="true" /> Register FREE
      </Link>
    </div>
  );
}
