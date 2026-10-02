'use client';

import React, { useState } from 'react';
import { Mail, Phone, Send, MessageSquare } from 'lucide-react';
import { Header } from '@/components/site/Header';
import { Footer } from '@/components/site/Footer';
import { toast } from 'sonner';

export default function ContactSupportPage() {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [issueType, setIssueType] = useState('Exam / Quiz Help');
  const [message, setMessage] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch('/api/health', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          action: 'CREATE_SUPPORT_TICKET',
          name,
          contactEmailOrPhone: email,
          issueType,
          message,
        }),
      });
      const data = await res.json();
      if (!res.ok || !data?.ticket?.ticketId) {
        toast.error(data?.error || 'Unable to submit support ticket. Please try again.');
        return;
      }
      toast.success(
        `Support ticket (${data.ticket.ticketId}) submitted! Hamari team 2 ghante mein reply karegi 🚀`
      );
      setName('');
      setEmail('');
      setMessage('');
    } catch {
      toast.error('Network error while submitting support ticket. Please try again.');
    }
  };

  return (
    <div className="min-h-screen bg-background">
      <Header />

      <section className="mx-auto max-w-4xl px-4 py-12 sm:px-6">
        <div className="text-center">
          <p className="text-xs font-bold uppercase tracking-widest text-primary">
            Help &amp; Support Desk
          </p>
          <h1 className="mt-1 text-3xl font-bold sm:text-4xl">
            Koi Sawaal Hai? Humse Sampark Karein 💬
          </h1>
          <p className="mt-2 text-sm text-muted-foreground">
            Students, Parents aur Teachers ke liye 24×7 dedicated support.
          </p>
        </div>

        <div className="mt-8 grid gap-6 md:grid-cols-3">
          <div className="space-y-4">
            <div className="rounded-3xl border border-border bg-card p-5 shadow-card">
              <Mail className="h-5 w-5 text-primary" />
              <div className="mt-2 text-sm font-bold">Email Support</div>
              <p className="mt-1 text-xs text-muted-foreground">
                dollysingh1268@gmail.com
              </p>
            </div>

            <div className="rounded-3xl border border-border bg-card p-5 shadow-card">
              <Phone className="h-5 w-5 text-secondary" />
              <div className="mt-2 text-sm font-bold">Helpline &amp; WhatsApp</div>
              <p className="mt-1 text-xs text-muted-foreground">
                +91 90000 12345 (9 AM – 9 PM IST)
              </p>
            </div>
          </div>

          <form
            onSubmit={handleSubmit}
            className="space-y-4 rounded-3xl border border-border bg-card p-6 shadow-card md:col-span-2"
          >
            <div className="flex items-center gap-2 text-base font-bold">
              <MessageSquare className="h-4 w-4 text-primary" /> Raise a Support Ticket
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <input
                required
                placeholder="Your Name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="h-11 rounded-xl border border-input bg-background px-3 text-sm outline-none focus:border-primary"
              />
              <input
                required
                type="email"
                placeholder="Email or Mobile"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="h-11 rounded-xl border border-input bg-background px-3 text-sm outline-none focus:border-primary"
              />
            </div>

            <select
              value={issueType}
              onChange={(e) => setIssueType(e.target.value)}
              className="h-11 w-full rounded-xl border border-input bg-background px-3 text-sm outline-none focus:border-primary"
            >
              <option>Exam / Quiz Help</option>
              <option>Student ID Verification</option>
              <option>Razorpay Payment / Refund</option>
              <option>Teacher Referral Payout</option>
              <option>Certificate Download Issue</option>
            </select>

            <textarea
              required
              rows={4}
              placeholder="Apni problem detail mein likhein..."
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              className="w-full rounded-xl border border-input bg-background p-3 text-sm outline-none focus:border-primary"
            />

            <button
              type="submit"
              className="inline-flex h-11 items-center gap-2 rounded-full bg-gradient-hero px-6 text-xs font-semibold text-primary-foreground shadow-soft"
            >
              <Send className="h-4 w-4" /> Submit Ticket
            </button>
          </form>
        </div>
      </section>

      <Footer />
    </div>
  );
}
