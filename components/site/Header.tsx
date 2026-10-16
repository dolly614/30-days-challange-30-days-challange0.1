'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import {
  LogOut,
  LogIn,
  Bell,
  Moon,
  Sun,
  User,
  Menu,
  X,
  CheckCheck,
} from 'lucide-react';
import { BrandMark } from './BrandMark';
import { PWAInstallButton } from './PWAInstallButton';
import { useUyanixStore } from '@/lib/store';
import { logout as googleLogout } from '@/lib/google-auth';
import { testFirestoreConnection } from '@/lib/firebase';
import { toast } from 'sonner';

export function Header() {
  const pathname = usePathname();
  const router = useRouter();
  const {
    isAuthenticated,
    currentUser,
    darkMode,
    toggleDarkMode,
    logout,
    syncServerSession,
    notifications,
    markAllNotificationsRead,
  } = useUyanixStore();

  const [showNotifs, setShowNotifs] = useState(false);
  const [showLogoutConfirm, setShowLogoutConfirm] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  useEffect(() => {
    useUyanixStore.persist?.rehydrate?.();
    syncServerSession?.();
    testFirestoreConnection?.();
  }, [syncServerSession]);

  useEffect(() => {
    if (typeof document !== 'undefined') {
      document.documentElement.classList.toggle('dark', darkMode);
    }
  }, [darkMode]);

  const unreadCount = notifications.filter((n) => !n.read).length;

  const navItems = [
    { href: '/', label: 'Home' },
    { href: '/leaderboard', label: 'Leaderboard' },
    { href: '/dashboard', label: 'Dashboard' },
    { href: '/teacher', label: 'Teacher' },
    { href: '/admin', label: 'Admin' },
    { href: '/checkout', label: 'Checkout' },
    { href: '/sheets', label: 'Google Sheets' },
  ] as const;

  const handleConfirmLogout = async () => {
    await googleLogout().catch(() => {});
    await logout();
    setShowLogoutConfirm(false);
    toast.success('Successfully logged out! Fir milenge Champion 👋');
    router.push('/login');
    router.refresh();
  };

  return (
    <>
      <header className="sticky top-0 z-40 w-full border-b border-border/60 bg-background/80 backdrop-blur-lg">
        <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6">
          <Link
            href="/"
            className="group flex items-center gap-2 font-bold whitespace-nowrap shrink-0 transition-transform duration-200 hover:scale-105 hover:rotate-[2deg]"
          >
            <BrandMark size={36} />
            <span className="text-base sm:text-lg leading-tight">
              Uyanix <span className="text-primary">30 Days</span>
            </span>
          </Link>

          <nav className="hidden items-center gap-6 text-sm font-medium md:flex">
            {navItems.map((item) => {
              const isActive =
                item.href === '/'
                  ? pathname === '/'
                  : pathname?.startsWith(item.href);
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  aria-current={isActive ? 'page' : undefined}
                  className={`group relative py-1 transition-colors whitespace-nowrap ${
                    isActive
                      ? 'text-foreground font-semibold'
                      : 'text-muted-foreground hover:text-foreground'
                  }`}
                >
                  {item.label}
                  <span
                    className={`absolute bottom-0 left-0 h-0.5 rounded-full bg-primary transition-all duration-300 ${
                      isActive
                        ? 'w-full'
                        : 'w-0 group-hover:w-full opacity-60 group-hover:opacity-100'
                    }`}
                  />
                </Link>
              );
            })}
          </nav>

          <div className="flex items-center gap-2">
            <PWAInstallButton />

            {/* Dark Mode Toggle */}
            <button
              type="button"
              onClick={toggleDarkMode}
              aria-label="Toggle dark mode"
              className="btn-interactive inline-flex h-10 w-10 items-center justify-center rounded-full border border-border bg-background text-muted-foreground transition duration-200 active:rotate-45 hover:bg-accent hover:text-foreground"
            >
              {darkMode ? <Sun className="h-4 w-4 text-saffron transition-transform duration-300" /> : <Moon className="h-4 w-4 transition-transform duration-300" />}
            </button>

            {/* Notifications Bell */}
            <div className="relative">
              <button
                type="button"
                onClick={() => setShowNotifs((prev) => !prev)}
                aria-label="Notifications"
                className={`btn-interactive relative inline-flex h-10 w-10 items-center justify-center rounded-full border border-border bg-background text-muted-foreground transition hover:bg-accent hover:text-foreground ${
                  unreadCount > 0 ? 'animate-pulse-glow' : ''
                }`}
              >
                <Bell className="h-4 w-4" />
                {unreadCount > 0 && (
                  <span className="absolute right-2 top-2 h-2 w-2 rounded-full bg-primary" />
                )}
              </button>

              {showNotifs && (
                <div className="animate-pop-in absolute right-0 mt-2 w-80 rounded-3xl border border-border bg-card p-4 shadow-soft z-50">
                  <div className="flex items-center justify-between border-b border-border pb-2.5">
                    <span className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
                      Notifications ({unreadCount} unread)
                    </span>
                    <button
                      type="button"
                      onClick={() => {
                        markAllNotificationsRead();
                        toast.success('Saare notifications read mark ho gaye');
                      }}
                      className="inline-flex items-center gap-1 text-xs font-semibold text-primary hover:underline"
                    >
                      <CheckCheck className="h-3.5 w-3.5" /> Mark all read
                    </button>
                  </div>
                  <div className="mt-2 max-h-64 space-y-2 overflow-y-auto">
                    {notifications.length === 0 ? (
                      <p className="py-4 text-center text-xs text-muted-foreground">
                        Koi naya notification nahi hai.
                      </p>
                    ) : (
                      notifications.map((n) => (
                        <div
                          key={n.id}
                          className={`rounded-2xl p-3 text-xs transition ${
                            n.read ? 'bg-muted/40 text-muted-foreground' : 'bg-accent/60 text-foreground'
                          }`}
                        >
                          <div className="font-semibold">{n.title}</div>
                          <p className="mt-0.5 text-muted-foreground leading-relaxed">{n.body}</p>
                          <div className="mt-1 text-[10px] opacity-75">{n.createdAt}</div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              )}
            </div>

            {/* Profile Link */}
            {isAuthenticated && (
              <Link
                href="/profile"
                title={`Profile (${currentUser?.name || 'Student'})`}
                className="hidden sm:inline-flex h-10 w-10 items-center justify-center rounded-full border border-border bg-background text-muted-foreground transition hover:bg-accent hover:text-foreground"
              >
                <User className="h-4 w-4" />
              </Link>
            )}

            {/* Logout / Login Button matching original HTML */}
            {isAuthenticated ? (
              <button
                type="button"
                onClick={() => setShowLogoutConfirm(true)}
                className="inline-flex h-10 items-center gap-2 rounded-full border border-border bg-background px-4 text-sm font-semibold transition hover:bg-accent whitespace-nowrap"
              >
                <LogOut className="h-4 w-4" aria-hidden="true" /> Logout
              </button>
            ) : (
              <Link
                href="/login"
                className="inline-flex h-10 items-center gap-2 rounded-full bg-gradient-hero px-4 text-sm font-semibold text-primary-foreground shadow-soft transition hover:opacity-95 whitespace-nowrap"
              >
                <LogIn className="h-4 w-4" aria-hidden="true" /> Login
              </Link>
            )}

            {/* Mobile Hamburger Button */}
            <button
              type="button"
              onClick={() => setMobileMenuOpen((o) => !o)}
              aria-label="Toggle Menu"
              className="inline-flex h-10 w-10 items-center justify-center rounded-full border border-border bg-background md:hidden"
            >
              {mobileMenuOpen ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
            </button>
          </div>
        </div>

        {/* Mobile Navigation Drawer */}
        {mobileMenuOpen && (
          <div className="animate-fade-up border-t border-border bg-card px-4 py-4 md:hidden">
            <nav className="flex flex-col space-y-2 text-sm font-medium">
              {navItems.map((item) => (
                <Link
                  key={item.href}
                  href={item.href}
                  onClick={() => setMobileMenuOpen(false)}
                  className={`rounded-xl px-3 py-2 transition ${
                    pathname === item.href
                      ? 'bg-accent font-semibold text-primary'
                      : 'text-muted-foreground hover:bg-muted'
                  }`}
                >
                  {item.label}
                </Link>
              ))}
              <Link
                href="/profile"
                onClick={() => setMobileMenuOpen(false)}
                className="rounded-xl px-3 py-2 text-muted-foreground hover:bg-muted"
              >
                My Profile ({currentUser?.name || 'Guest'})
              </Link>
              <Link
                href="/certificate"
                onClick={() => setMobileMenuOpen(false)}
                className="rounded-xl px-3 py-2 text-muted-foreground hover:bg-muted"
              >
                Certificate Portal
              </Link>
            </nav>
          </div>
        )}
      </header>

      {/* Logout Confirmation Modal */}
      {showLogoutConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-md animate-fade-up">
          <div className="animate-pop-in w-full max-w-sm rounded-3xl border border-border bg-card p-6 shadow-soft">
            <h3 className="text-lg font-bold">Logout Confirm Karein?</h3>
            <p className="mt-1.5 text-sm text-muted-foreground">
              Kya aap sach mein apne Uyanix 30 Days Challenge account se logout karna chahte hain? Aapka progress safe rahega.
            </p>
            <div className="mt-5 flex items-center justify-end gap-2">
              <button
                type="button"
                onClick={() => setShowLogoutConfirm(false)}
                className="btn-interactive h-10 rounded-full border border-border px-4 text-xs font-semibold hover:bg-accent"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleConfirmLogout}
                className="btn-interactive h-10 rounded-full bg-destructive px-5 text-xs font-semibold text-destructive-foreground shadow-soft hover:opacity-90"
              >
                Yes, Logout
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
