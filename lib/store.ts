'use client';

import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { MCQQuestion } from './curriculum';
import {
  beginAuthOrNavigationRequest,
  invalidateInFlightNavigationOnAuthBoundary,
  shouldAcceptAsyncNavigationResponse,
} from './routing-access-control-governance';

function generateCryptographicOpaqueRecordId(
  prefix: 'TKT' | 'WD' | 'VER' | 'PAY' | 'ATT' | 'REF' | 'CERT' | 'AUD' | 'NOTIF'
): string {
  const bytes = new Uint8Array(8);
  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.getRandomValues) {
    globalThis.crypto.getRandomValues(bytes);
  }
  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
  return `${prefix}-UYX-${hex}`;
}

export interface StudentLeader {
  id: string;
  rank: number;
  name: string;
  classNum: number;
  city: string;
  score: number;
  total: number;
  prizePaid?: boolean;
  email?: string;
  phone?: string;
  school?: string;
  status?: 'active' | 'banned';
}

export interface UserProfile {
  id: string;
  name: string;
  teacherShortName: string;
  email: string;
  phone: string;
  classNum: number;
  school: string;
  city: string;
  role: 'student' | 'teacher' | 'admin';
  avatar?: string;
  idCardUrl?: string;
  idVerificationStatus?: string;
  idVerified: boolean;
  idCardName?: string;
  streakReminders: boolean;
  onboardingRequired?: boolean;
  createdAt: string;
}

export interface TeacherRecord {
  id: string;
  name: string;
  email: string;
  code: string;
  tier: 'Beginner Teacher' | 'Active Mentor' | 'Super Educator';
  status: 'pending' | 'approved' | 'rejected';
  balance: number;
  totalEarned: number;
  thisMonthEarned: number;
  referredCount: number;
  pendingReferrals: number;
  paidActiveCount: number;
  riskScore: number;
  upiId: string;
  bankDetails?: string;
  kycPan?: string;
  kycVerified?: boolean;
  dailySignups: { dayLabel: string; count: number }[];
}

export interface ReferralItem {
  id: string;
  teacherCode: string;
  studentName: string;
  studentClass: number;
  status: 'pending' | 'verified' | 'flagged_fraud';
  commission: number;
  date: string;
}

export interface WithdrawalRequest {
  id: string;
  teacherId: string;
  teacherName: string;
  date: string;
  method: 'UPI' | 'Bank';
  destination: string;
  amount: number;
  status: 'pending' | 'paid' | 'rejected';
  invoiceId: string;
}

export interface StudentVerificationItem {
  id: string;
  studentName: string;
  classNum: number;
  school: string;
  documentName: string;
  submittedAt: string;
  status: 'pending' | 'approved' | 'rejected';
}

export interface ExamAttempt {
  id: string;
  type: 'mid' | 'final';
  score: number;
  total: number;
  answers: Record<string, number>;
  completedAt: string;
  rank: number;
}

export interface PaymentRecord {
  id: string;
  userId: string;
  userName: string;
  amount: number;
  type: 'mid_exam' | 'final_exam';
  razorpayId: string;
  status: 'captured' | 'refunded';
  createdAt: string;
}

export interface NotificationItem {
  id: string;
  title: string;
  body: string;
  read: boolean;
  createdAt: string;
}

export interface AuditLogItem {
  id: string;
  actor: string;
  action: string;
  target: string;
  timestamp: string;
}

export interface SavedChapterOverride {
  classNum: number;
  day: number;
  title: string;
  content: string;
  updatedAt: string;
}

interface UyanixState {
  currentUser: UserProfile | null;
  isAuthenticated: boolean;
  authChecked: boolean;
  darkMode: boolean;
  brandLogo: string;
  completedDays: number[];
  dailyScores: Record<number, number>;
  leaderboard: StudentLeader[];
  teachers: TeacherRecord[];
  referrals: ReferralItem[];
  withdrawals: WithdrawalRequest[];
  fraudLogs: string[];
  verifications: StudentVerificationItem[];
  savedChapters: Record<string, SavedChapterOverride>;
  customExamQuestions: MCQQuestion[];
  examPaid: { mid: boolean; final: boolean };
  examAttempts: ExamAttempt[];
  payments: PaymentRecord[];
  notifications: NotificationItem[];
  auditLogs: AuditLogItem[];

  // Actions
  syncServerSession: () => Promise<UserProfile | null>;
  login: (user: UserProfile) => void;
  logout: () => Promise<void>;
  updateProfile: (updates: Partial<UserProfile>) => Promise<boolean>;
  toggleDarkMode: () => void;
  setBrandLogo: (url: string) => Promise<boolean>;
  resetBrandLogo: () => Promise<boolean>;
  completeDay: (day: number, score: number) => void;
  syncStudentProgress: () => Promise<boolean>;
  syncLeaderboard: () => Promise<boolean>;
  submitDailyQuiz: (day: number, answers: number[]) => Promise<{ ok: boolean; score?: number; error?: string; status?: string }>;
  refreshLeaderboard: () => void;
  markPrizePaid: (studentId: string) => Promise<boolean>;
  toggleBanStudent: (studentId: string) => Promise<boolean>;

  // Chapters Admin (Server Authoritative)
  refreshChapters: (classNum?: number) => Promise<void>;
  saveChapter: (classNum: number, day: number, title: string, content: string) => Promise<boolean>;
  bulkSaveChapters: (classNum: number, days: { day: number; title: string; content: string }[], overwrite: boolean) => Promise<number>;
  deleteClassChapters: (classNum: number) => Promise<boolean>;
  resetAllChapters: () => Promise<boolean>;

  // Teacher & Admin Actions
  updateTeacherStatus: (teacherId: string, status: 'approved' | 'rejected' | 'pending') => Promise<boolean>;
  syncTeacherData: () => Promise<void>;
  requestWithdrawal: (method: 'UPI' | 'Bank', destination: string, amount: number) => Promise<boolean>;
  processWithdrawal: (withdrawalId: string, status: 'paid' | 'rejected') => Promise<boolean>;
  submitTeacherKyc: (pan: string, upiId: string) => void;
  simulateTeacherReferral: () => void;

  // Verifications
  syncAdminVerifications: () => Promise<void>;
  submitStudentIdVerification: (docName: string) => void;
  handleVerification: (id: string, status: 'approved' | 'rejected') => Promise<boolean>;

  // Exams & Payments
  payForExam: (type: 'mid' | 'final', razorpayId: string) => void;
  submitExamAttempt: (type: 'mid' | 'final', score: number, total: number, answers: Record<string, number>) => ExamAttempt;
  refundPayment: (paymentId: string) => Promise<boolean>;
  addCustomExamQuestion: (q: MCQQuestion) => Promise<boolean>;
  bulkImportExamQuestions: (questions: MCQQuestion[]) => Promise<number>;
  deleteCustomExamQuestion: (id: string) => Promise<boolean>;
  importLeaderboardFromSheet: (students: StudentLeader[]) => void;

  // Notifications
  markAllNotificationsRead: () => void;
  broadcastNotification: (title: string, body: string) => Promise<{ ok: boolean; recipientCount?: number }>;
}

const DEFAULT_LOGO = '/uyanix-logo.jpg';

const INITIAL_LEADERBOARD: StudentLeader[] = [
  { id: 'st-1', rank: 1, name: 'Aarav Sharma', classNum: 8, city: 'Mumbai', score: 30, total: 30, prizePaid: false, email: 'aarav.sharma@gmail.com', phone: '9820112233', school: 'Dhirubhai Ambani International', status: 'active' },
  { id: 'st-2', rank: 2, name: 'Diya Patel', classNum: 7, city: 'Ahmedabad', score: 29, total: 30, prizePaid: false, email: 'diya.patel@gmail.com', phone: '9825011223', school: 'Udgam School for Children', status: 'active' },
  { id: 'st-3', rank: 3, name: 'Vihaan Singh', classNum: 9, city: 'Delhi', score: 29, total: 30, prizePaid: false, email: 'vihaan.singh@gmail.com', phone: '9811099887', school: 'Delhi Public School RK Puram', status: 'active' },
  { id: 'st-4', rank: 4, name: 'Ananya Iyer', classNum: 6, city: 'Chennai', score: 28, total: 30, prizePaid: false, email: 'ananya.iyer@gmail.com', phone: '9840123456', school: 'PSBB Senior Secondary', status: 'active' },
  { id: 'st-5', rank: 5, name: 'Arjun Reddy', classNum: 10, city: 'Hyderabad', score: 28, total: 30, prizePaid: false, email: 'arjun.reddy@gmail.com', phone: '9848022334', school: 'Oakridge International', status: 'active' },
  { id: 'st-6', rank: 6, name: 'Saanvi Kapoor', classNum: 5, city: 'Pune', score: 27, total: 30, prizePaid: false, email: 'saanvi.k@gmail.com', phone: '9822055667', school: 'Symbiosis Primary School', status: 'active' },
  { id: 'st-7', rank: 7, name: 'Krishna Mehta', classNum: 8, city: 'Jaipur', score: 27, total: 30, prizePaid: false, email: 'krishna.m@gmail.com', phone: '9829033445', school: 'Maharaja Sawai Man Singh Vidyalaya', status: 'active' },
  { id: 'st-8', rank: 8, name: 'Ishaan Verma', classNum: 11, city: 'Lucknow', score: 26, total: 30, prizePaid: false, email: 'ishaan.v@gmail.com', phone: '9415066778', school: 'City Montessori School', status: 'active' },
  { id: 'st-9', rank: 9, name: 'Myra Joshi', classNum: 4, city: 'Kolkata', score: 26, total: 30, prizePaid: false, email: 'myra.joshi@gmail.com', phone: '9830077889', school: 'La Martiniere for Girls', status: 'active' },
  { id: 'st-10', rank: 10, name: 'Kabir Nair', classNum: 12, city: 'Bengaluru', score: 25, total: 30, prizePaid: false, email: 'kabir.nair@gmail.com', phone: '9845088990', school: 'National Public School Indiranagar', status: 'active' },
];

const INITIAL_DAILY_SIGNUPS = [
  '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24',
].map((dayLabel) => ({ dayLabel, count: 0 }));

async function verifyServerAdminAction(
  action: string,
  payload: Record<string, unknown>,
  onUnauthorized: () => void
): Promise<boolean> {
  try {
    const res = await fetch('/api/admin/action', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ action, ...payload }),
    });
    if (res.status === 401 || res.status === 403) {
      onUnauthorized();
      return false;
    }
    return res.ok;
  } catch {
    return false;
  }
}

async function verifyServerTeacherAction(
  action: string,
  payload: Record<string, unknown>,
  onUnauthorized: () => void
): Promise<boolean> {
  try {
    const res = await fetch('/api/teacher/action', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ action, ...payload }),
    });
    if (res.status === 401 || res.status === 403) {
      onUnauthorized();
      return false;
    }
    return res.ok;
  } catch {
    return false;
  }
}

export const useUyanixStore = create<UyanixState>()(
  persist(
    (set, get) => ({
      currentUser: null,
      isAuthenticated: false,
      authChecked: false,
      darkMode: false,
      brandLogo: DEFAULT_LOGO,
      completedDays: [],
      dailyScores: {},
      leaderboard: [],
      teachers: [
        {
          id: 'teacher-dolly',
          name: 'dolly',
          email: 'dollysingh1268@gmail.com',
          code: 'DOLLOXW0',
          tier: 'Beginner Teacher',
          status: 'rejected',
          balance: 0,
          totalEarned: 0,
          thisMonthEarned: 0,
          referredCount: 0,
          pendingReferrals: 0,
          paidActiveCount: 0,
          riskScore: 0,
          upiId: 'shiv9897320579@gmail.com',
          kycVerified: false,
          dailySignups: INITIAL_DAILY_SIGNUPS,
        },
      ],
      referrals: [],
      withdrawals: [],
      fraudLogs: [],
      verifications: [],
      savedChapters: {},
      customExamQuestions: [],
      examPaid: { mid: false, final: false },
      examAttempts: [],
      payments: [
        {
          id: 'pay-101',
          userId: 'st-1',
          userName: 'Aarav Sharma',
          amount: 199,
          type: 'final_exam',
          razorpayId: 'pay_Rzp998123Aarav',
          status: 'captured',
          createdAt: '2026-09-25 14:22',
        },
        {
          id: 'pay-102',
          userId: 'st-2',
          userName: 'Diya Patel',
          amount: 199,
          type: 'final_exam',
          razorpayId: 'pay_Rzp998124Diya',
          status: 'captured',
          createdAt: '2026-09-26 11:10',
        },
        {
          id: 'pay-103',
          userId: 'st-3',
          userName: 'Vihaan Singh',
          amount: 199,
          type: 'mid_exam',
          razorpayId: 'pay_Rzp998125Vihaan',
          status: 'captured',
          createdAt: '2026-09-27 09:05',
        },
      ],
      notifications: [
        {
          id: 'notif-1',
          title: '🔥 15-Day Streak Completed!',
          body: 'Badhai ho! Aapka 15-Day Mid Exam ab unlock ho chuka hai.',
          read: false,
          createdAt: 'Just now',
        },
        {
          id: 'notif-2',
          title: '📚 Aaj ka Task: Day 16 Globalization',
          body: 'Apna 16th day streak maintain karne ke liye aaj ke 5 MCQs solve karein!',
          read: false,
          createdAt: '2 hours ago',
        },
      ],
      auditLogs: [
        {
          id: 'aud-1',
          actor: 'system',
          action: 'SYSTEM_INIT',
          target: 'Uyanix 30 Days Batch #4',
          timestamp: '2026-09-27 08:00',
        },
      ],

      syncServerSession: async () => {
        const { requestEpoch } = beginAuthOrNavigationRequest(
          get().currentUser?.id ?? null
        );
        try {
          const res = await fetch('/api/auth/session', {
            method: 'GET',
            credentials: 'include',
            cache: 'no-store',
          });
          const epochCheck = shouldAcceptAsyncNavigationResponse({
            requestEpoch,
          });
          if (!epochCheck.accept) {
            return get().currentUser;
          }
          if (!res.ok) {
            invalidateInFlightNavigationOnAuthBoundary({
              reason: 'SESSION_EXPIRED',
              nextUserId: null,
            });
            set({
              currentUser: null,
              isAuthenticated: false,
              authChecked: true,
              examPaid: { mid: false, final: false },
            });
            return null;
          }
          const data = await res.json();
          const postJsonEpochCheck = shouldAcceptAsyncNavigationResponse({
            requestEpoch,
            responseUserId: data?.user?.id ?? null,
          });
          if (!postJsonEpochCheck.accept) {
            return get().currentUser;
          }
          if (data?.authenticated && data?.user) {
            const incomingUser = data.user as UserProfile;
            const prevUser = get().currentUser;
            const isUserSwitch =
              prevUser !== null && prevUser.id !== incomingUser.id;
            if (isUserSwitch) {
              invalidateInFlightNavigationOnAuthBoundary({
                reason: 'USER_SWITCH',
                nextUserId: incomingUser.id,
              });
            }
            set((state) => ({
              currentUser: incomingUser,
              isAuthenticated: true,
              authChecked: true,
              completedDays: isUserSwitch ? [] : state.completedDays,
              dailyScores: isUserSwitch ? {} : state.dailyScores,
              examPaid: isUserSwitch
                ? { mid: false, final: false }
                : state.examPaid,
            }));
            // Load authoritative daily progress from database
            get().syncStudentProgress();
            return incomingUser;
          }
          set({
            currentUser: null,
            isAuthenticated: false,
            authChecked: true,
            completedDays: [],
            dailyScores: {},
            examPaid: { mid: false, final: false },
          });
          return null;
        } catch {
          // Network error: fail-closed for authentication (never fabricate authorized state)
          const fallbackCheck = shouldAcceptAsyncNavigationResponse({
            requestEpoch,
          });
          if (fallbackCheck.accept) {
            set({ currentUser: null, isAuthenticated: false, authChecked: true });
          }
          return null;
        }
      },

      login: (serverVerifiedUser) => {
        const prevUser = get().currentUser;
        const isUserSwitch =
          prevUser !== null && prevUser.id !== serverVerifiedUser.id;
        invalidateInFlightNavigationOnAuthBoundary({
          reason: 'USER_SWITCH',
          nextUserId: serverVerifiedUser.id,
        });
        if (typeof window !== 'undefined' && 'BroadcastChannel' in window) {
          try {
            const bc = new BroadcastChannel('uyanix-auth-channel');
            bc.postMessage({
              type: 'LOGIN_OR_SWITCH',
              userId: serverVerifiedUser.id,
            });
            bc.close();
          } catch {
            // ignore BroadcastChannel errors in restricted contexts
          }
        }
        set((state) => ({
          currentUser: serverVerifiedUser,
          isAuthenticated: true,
          authChecked: true,
          examPaid: isUserSwitch
            ? { mid: false, final: false }
            : state.examPaid,
          auditLogs: [
            {
              id: `aud-${Date.now()}`,
              actor: serverVerifiedUser.email || serverVerifiedUser.phone,
              action: 'USER_LOGIN',
              target: serverVerifiedUser.name,
              timestamp: new Date().toISOString().slice(0, 16).replace('T', ' '),
            },
            ...state.auditLogs,
          ],
        }));
      },

      logout: async () => {
        const actor = get().currentUser?.email || 'user';
        const target = get().currentUser?.name || 'session';
        // Immediately invalidate any in-flight navigation/session requests so stale responses cannot restore auth
        invalidateInFlightNavigationOnAuthBoundary({
          reason: 'LOGOUT',
          nextUserId: null,
        });
        set((state) => ({
          currentUser: null,
          isAuthenticated: false,
          authChecked: true,
          completedDays: [],
          dailyScores: {},
          examPaid: { mid: false, final: false },
          auditLogs: [
            {
              id: `aud-${Date.now()}`,
              actor,
              action: 'USER_LOGOUT',
              target,
              timestamp: new Date().toISOString().slice(0, 16).replace('T', ' '),
            },
            ...state.auditLogs,
          ],
        }));
        if (typeof window !== 'undefined' && 'BroadcastChannel' in window) {
          try {
            const bc = new BroadcastChannel('uyanix-auth-channel');
            bc.postMessage({ type: 'LOGOUT' });
            bc.close();
          } catch {
            // ignore BroadcastChannel errors
          }
        }
        try {
          await fetch('/api/auth/logout', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ action: 'logout' }),
          });
        } catch {
          // Local state is already cleared authoritatively
        }
      },

      updateProfile: async (updates) => {
        try {
          // Strip any role or privilege fields before sending to server
          const safeUpdates = { ...updates };
          delete (safeUpdates as Partial<UserProfile>).role;
          delete (safeUpdates as Partial<UserProfile>).id;
          delete (safeUpdates as Partial<UserProfile>).idVerified;

          const res = await fetch('/api/user/profile', {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify(safeUpdates),
          });
          if (res.status === 401) {
            set({ currentUser: null, isAuthenticated: false, authChecked: true });
            return false;
          }
          if (!res.ok) {
            return false;
          }
          const data = await res.json();
          if (data?.user) {
            set({
              currentUser: data.user as UserProfile,
              isAuthenticated: true,
              authChecked: true,
            });
            return true;
          }
          return false;
        } catch {
          return false;
        }
      },

      toggleDarkMode: () =>
        set((state) => {
          const next = !state.darkMode;
          if (typeof document !== 'undefined') {
            document.documentElement.classList.toggle('dark', next);
          }
          return { darkMode: next };
        }),

      setBrandLogo: async (url) => {
        if (get().currentUser?.role !== 'admin') {
          get().syncServerSession();
          return false;
        }
        try {
          const res = await fetch('/api/admin/action', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ action: 'SET_BRAND_LOGO', logoUrl: url }),
          });
          const data = await res.json();
          if (res.ok && (data.ok || data.authorized)) {
            set({ brandLogo: url });
            return true;
          }
          return false;
        } catch {
          return false;
        }
      },

      resetBrandLogo: async () => {
        if (get().currentUser?.role !== 'admin') {
          get().syncServerSession();
          return false;
        }
        try {
          const res = await fetch('/api/admin/action', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ action: 'RESET_BRAND_LOGO' }),
          });
          const data = await res.json();
          if (res.ok && (data.ok || data.authorized)) {
            set({ brandLogo: DEFAULT_LOGO });
            return true;
          }
          return false;
        } catch {
          return false;
        }
      },

      completeDay: (day, score) =>
        set((state) => {
          const already = state.completedDays.includes(day);
          const nextDays = already ? state.completedDays : [...state.completedDays, day].sort((a, b) => a - b);
          return {
            completedDays: nextDays,
            dailyScores: { ...state.dailyScores, [day]: score },
            notifications: [
              {
                id: `notif-${Date.now()}`,
                title: `✅ Day ${day} Completed (${score}/5)!`,
                body: `Shandar! Aapne Day ${day} quiz complete kiya (${score}/5). Streak: ${nextDays.length} days!`,
                read: false,
                createdAt: 'Just now',
              },
              ...state.notifications,
            ],
          };
        }),

      syncStudentProgress: async () => {
        try {
          const res = await fetch('/api/student/progress', {
            method: 'GET',
            credentials: 'include',
            cache: 'no-store',
          });
          if (!res.ok) return false;
          const data = await res.json();
          if (data?.ok && data?.progress) {
            set({
              completedDays: Array.isArray(data.progress.completedDays) ? data.progress.completedDays : [],
              dailyScores: data.progress.dailyScores && typeof data.progress.dailyScores === 'object' ? data.progress.dailyScores : {},
            });
            return true;
          }
          return false;
        } catch {
          return false;
        }
      },

      syncLeaderboard: async () => {
        try {
          const res = await fetch('/api/leaderboard', {
            method: 'GET',
            credentials: 'include',
            cache: 'no-store',
          });
          if (!res.ok) return false;
          const data = await res.json();
          if (data?.ok && Array.isArray(data?.entries)) {
            set({
              leaderboard: data.entries,
            });
            return true;
          }
          return false;
        } catch {
          return false;
        }
      },

      submitDailyQuiz: async (day: number, answers: number[]) => {
        try {
          const res = await fetch(`/api/daily/${day}/submit`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ answers }),
          });
          const data = await res.json();
          if (data?.ok && data?.status === 'SUCCESS') {
            get().completeDay(day, data.score);
            if (Array.isArray(data.completedDays)) {
              set({ completedDays: data.completedDays });
            }
            return data;
          }
          return data;
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : 'Network error';
          return { ok: false, error: msg, errorCode: 'NETWORK_ERROR' };
        }
      },

      refreshLeaderboard: () => {
        get().syncLeaderboard();
        set((state) => ({
          leaderboard: [...state.leaderboard].sort((a, b) => b.score - a.score || a.rank - b.rank),
        }));
      },

      markPrizePaid: async (studentId) => {
        if (get().currentUser?.role !== 'admin') {
          get().syncServerSession();
          return false;
        }
        try {
          const idempotencyKey = `idemp_prz_${studentId}_${Date.now()}`;
          const res = await fetch('/api/admin/action', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'x-idempotency-key': idempotencyKey,
            },
            credentials: 'include',
            body: JSON.stringify({
              action: 'MARK_PRIZE_PAID',
              target: studentId,
              studentId,
              targetStatus: 'PAID',
              idempotencyKey,
            }),
          });
          const data = await res.json();
          if (res.ok && (data.ok || data.authorized)) {
            set((state) => ({
              leaderboard: state.leaderboard.map((s) =>
                s.id === studentId ? { ...s, prizePaid: true } : s
              ),
            }));
            return true;
          }
          return false;
        } catch {
          return false;
        }
      },

      toggleBanStudent: async (studentId) => {
        if (get().currentUser?.role !== 'admin') {
          get().syncServerSession();
          return false;
        }
        const targetStudent = get().leaderboard.find((s) => s.id === studentId);
        const nextBanned = targetStudent?.status !== 'banned';
        try {
          const res = await fetch('/api/admin/action', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({
              action: 'TOGGLE_BAN_STUDENT',
              target: studentId,
              targetUserId: studentId,
              banned: nextBanned,
            }),
          });
          const data = await res.json();
          if (res.ok && (data.ok || data.authorized)) {
            set((state) => ({
              leaderboard: state.leaderboard.map((s) =>
                s.id === studentId ? { ...s, status: nextBanned ? 'banned' : 'active' } : s
              ),
            }));
            return true;
          }
          return false;
        } catch {
          return false;
        }
      },

      refreshChapters: async (classNum) => {
        try {
          const url = typeof classNum === 'number' ? `/api/admin/chapters?class=${classNum}` : '/api/admin/chapters';
          const res = await fetch(url, { credentials: 'include' });
          if (res.ok) {
            const data = await res.json();
            if (data.ok && Array.isArray(data.chapters)) {
              set((state) => {
                const nextChapters = { ...state.savedChapters };
                for (const c of data.chapters) {
                  const key = `${c.class_num}-${c.day}`;
                  nextChapters[key] = {
                    classNum: c.class_num,
                    day: c.day,
                    title: c.title,
                    content: c.content,
                    updatedAt: c.updated_at,
                  };
                }
                return { savedChapters: nextChapters };
              });
            }
          }
        } catch {
          // preserve state
        }
      },

      saveChapter: async (classNum, day, title, content) => {
        if (get().currentUser?.role !== 'admin') {
          get().syncServerSession();
          return false;
        }
        try {
          const res = await fetch('/api/admin/chapters', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({
              action: 'SAVE_CHAPTER',
              classNum,
              day,
              title,
              content,
            }),
          });
          const data = await res.json();
          if (res.ok && data.ok) {
            const key = `${classNum}-${day}`;
            set((state) => ({
              savedChapters: {
                ...state.savedChapters,
                [key]: {
                  classNum,
                  day,
                  title,
                  content,
                  updatedAt: new Date().toISOString(),
                },
              },
            }));
            return true;
          }
          return false;
        } catch {
          return false;
        }
      },

      bulkSaveChapters: async (classNum, days, overwrite) => {
        if (get().currentUser?.role !== 'admin') {
          get().syncServerSession();
          return 0;
        }
        try {
          const res = await fetch('/api/admin/chapters', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({
              action: 'BULK_SAVE_CHAPTERS',
              classNum,
              items: days,
              overwrite,
            }),
          });
          const data = await res.json();
          if (res.ok && data.ok) {
            const updated = { ...get().savedChapters };
            for (const item of days) {
              const key = `${classNum}-${item.day}`;
              if (overwrite || !updated[key]) {
                updated[key] = {
                  classNum,
                  day: item.day,
                  title: item.title,
                  content: item.content,
                  updatedAt: new Date().toISOString(),
                };
              }
            }
            set({ savedChapters: updated });
            return (data.inserted || 0) + (data.updated || 0);
          }
          return 0;
        } catch {
          return 0;
        }
      },

      deleteClassChapters: async (classNum) => {
        if (get().currentUser?.role !== 'admin') {
          get().syncServerSession();
          return false;
        }
        try {
          const res = await fetch('/api/admin/chapters', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({
              action: 'DELETE_CLASS_CHAPTERS',
              classNum,
            }),
          });
          const data = await res.json();
          if (res.ok && data.ok) {
            set((state) => {
              const next = { ...state.savedChapters };
              Object.keys(next).forEach((k) => {
                if (k.startsWith(`${classNum}-`)) {
                  delete next[k];
                }
              });
              return { savedChapters: next };
            });
            return true;
          }
          return false;
        } catch {
          return false;
        }
      },

      resetAllChapters: async () => {
        if (get().currentUser?.role !== 'admin') {
          get().syncServerSession();
          return false;
        }
        try {
          const res = await fetch('/api/admin/chapters', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ action: 'RESET_ALL_CHAPTERS' }),
          });
          const data = await res.json();
          if (res.ok && data.ok) {
            set({ savedChapters: {} });
            return true;
          }
          return false;
        } catch {
          return false;
        }
      },

      updateTeacherStatus: async (teacherId, status) => {
        if (get().currentUser?.role !== 'admin') {
          get().syncServerSession();
          return false;
        }
        try {
          const res = await fetch('/api/admin/action', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({
              action: 'UPDATE_TEACHER_STATUS',
              target: teacherId,
              teacherId,
              status,
            }),
          });
          const data = await res.json();
          if (res.ok && (data.ok || data.authorized)) {
            set((state) => ({
              teachers: state.teachers.map((t) => (t.id === teacherId ? { ...t, status } : t)),
            }));
            return true;
          }
          return false;
        } catch {
          return false;
        }
      },

      syncTeacherData: async () => {
        try {
          const res = await fetch('/api/teacher/action', {
            method: 'GET',
            credentials: 'include',
          });
          if (res.ok) {
            const data = await res.json();
            if (data.ok && data.teacher) {
              const t = data.teacher;
              set((state) => {
                const prev = state.teachers[0];
                const updatedTeacher: TeacherRecord = {
                  id: t.id,
                  name: t.name || state.currentUser?.name || 'Teacher',
                  email: t.email || state.currentUser?.email || '',
                  code: t.code || 'DOLLOXW0',
                  tier: t.tier || 'Beginner Teacher',
                  status: t.status || 'approved',
                  balance: typeof t.balance === 'number' ? t.balance : 0,
                  totalEarned: typeof t.totalEarned === 'number' ? t.totalEarned : 0,
                  thisMonthEarned: prev?.thisMonthEarned || 0,
                  referredCount: prev?.referredCount || 0,
                  pendingReferrals: prev?.pendingReferrals || 0,
                  paidActiveCount: prev?.paidActiveCount || 0,
                  riskScore: prev?.riskScore || 0,
                  kycVerified: Boolean(t.kycVerified),
                  kycPan: t.kycPan || '',
                  upiId: t.upiId || '',
                  dailySignups: prev?.dailySignups || [],
                };
                return {
                  teachers: [updatedTeacher],
                  withdrawals: Array.isArray(data.withdrawals) && data.withdrawals.length > 0
                    ? data.withdrawals.map((w: Record<string, unknown>) => ({
                        id: String(w.id),
                        teacherId: String(w.teacherId || t.id),
                        teacherName: updatedTeacher.name,
                        date: String(w.date || new Date().toISOString().slice(0, 10)),
                        method: (w.method === 'Bank' ? 'Bank' : 'UPI') as 'UPI' | 'Bank',
                        destination: String(w.destination || ''),
                        amount: Number(w.amount || 0),
                        status: (w.status === 'paid' ? 'paid' : w.status === 'rejected' ? 'rejected' : 'pending') as 'pending' | 'paid' | 'rejected',
                        invoiceId: String(w.invoiceId || `INV_${String(w.id).slice(0, 8)}`),
                      }))
                    : state.withdrawals,
                };
              });
            }
          }
        } catch {
          // ignore network sync errors
        }
      },

      requestWithdrawal: async (method, destination, amount) => {
        const state = get();
        const role = state.currentUser?.role;
        if (role !== 'teacher' && role !== 'admin') {
          await state.syncServerSession();
          return false;
        }
        if (amount < 500) return false;

        try {
          const idempotencyKey = `idemp_wd_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
          const res = await fetch('/api/teacher/action', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'x-idempotency-key': idempotencyKey,
            },
            credentials: 'include',
            body: JSON.stringify({
              action: 'REQUEST_WITHDRAWAL',
              method,
              destination,
              amount,
              idempotencyKey,
            }),
          });
          const data = await res.json();
          if (res.ok && data.ok) {
            const w = data.withdrawal;
            const newWithdrawal: WithdrawalRequest = {
              id: w?.id || generateCryptographicOpaqueRecordId('WD'),
              teacherId: w?.teacherId || (state.teachers[0]?.id ?? 't1'),
              teacherName: state.teachers[0]?.name || state.currentUser?.name || 'Teacher',
              date: w?.createdAt ? String(w.createdAt).slice(0, 10) : new Date().toISOString().slice(0, 10),
              method,
              destination,
              amount,
              status: 'pending',
              invoiceId: `INV_${String(w?.id || 'WD').replace(/[^a-zA-Z0-9]/g, '').slice(0, 8).toUpperCase()}`,
            };

            set((s) => ({
              teachers: s.teachers.map((t) =>
                t.id === (w?.teacherId || s.teachers[0]?.id)
                  ? { ...t, balance: typeof data.newBalance === 'number' ? data.newBalance : t.balance - amount }
                  : t
              ),
              withdrawals: [newWithdrawal, ...s.withdrawals],
            }));
            return true;
          }
          return false;
        } catch {
          return false;
        }
      },

      processWithdrawal: async (withdrawalId, status) => {
        if (get().currentUser?.role !== 'admin') {
          get().syncServerSession();
          return false;
        }
        try {
          const action = status === 'paid' ? 'PROCESS_WITHDRAWAL' : 'REJECT_WITHDRAWAL';
          const idempotencyKey = `idemp_admin_wd_${withdrawalId}_${Date.now()}`;
          const res = await fetch('/api/admin/action', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'x-idempotency-key': idempotencyKey,
            },
            credentials: 'include',
            body: JSON.stringify({
              action,
              target: withdrawalId,
              withdrawalId,
              idempotencyKey,
            }),
          });
          const data = await res.json();
          if (res.ok && (data.ok || data.authorized)) {
            set((state) => {
              const target = state.withdrawals.find((w) => w.id === withdrawalId);
              return {
                withdrawals: state.withdrawals.map((w) =>
                  w.id === withdrawalId ? { ...w, status } : w
                ),
                teachers:
                  status === 'rejected' && target
                    ? state.teachers.map((t) =>
                        t.id === target.teacherId ? { ...t, balance: t.balance + target.amount } : t
                      )
                    : state.teachers,
              };
            });
            return true;
          }
          return false;
        } catch {
          return false;
        }
      },

      submitTeacherKyc: (pan, upiId) => {
        const state = get();
        const role = state.currentUser?.role;
        if (role !== 'teacher' && role !== 'admin') {
          state.syncServerSession();
          return;
        }
        const isAdminActor = role === 'admin';
        set((s) => ({
          teachers: s.teachers.map((t, idx) =>
            idx === 0
              ? {
                  ...t,
                  kycPan: pan.toUpperCase(),
                  upiId,
                  kycVerified: isAdminActor ? true : t.kycVerified,
                  status: isAdminActor ? 'approved' : 'pending',
                }
              : t
          ),
        }));
        verifyServerTeacherAction(
          'SUBMIT_KYC',
          { pan: pan.toUpperCase(), upiId },
          () => get().syncServerSession()
        );
      },

      simulateTeacherReferral: () => {
        const state = get();
        const role = state.currentUser?.role;
        if (role !== 'teacher' && role !== 'admin') {
          state.syncServerSession();
          return;
        }
        // Client-side referral & balance simulation is disabled in production;
        // referrals and commissions are derived solely from authoritative server events.
        verifyServerTeacherAction(
          'SIMULATE_REFERRAL',
          {},
          () => get().syncServerSession()
        );
      },

      syncAdminVerifications: async () => {
        if (get().currentUser?.role !== 'admin') return;
        try {
          const res = await fetch('/api/admin/action', {
            method: 'GET',
            credentials: 'include',
          });
          if (res.ok) {
            const data = await res.json();
            if (data.authorized && Array.isArray(data.verifications)) {
              set({
                verifications: data.verifications.map((v: Record<string, unknown>) => ({
                  id: String(v.id),
                  studentName: String(v.studentName || 'Student'),
                  classNum: Number(v.classNum || 10),
                  school: String(v.school || 'School'),
                  documentName: String(v.documentName || 'Student ID'),
                  submittedAt: String(v.submittedAt || 'Recent'),
                  status: (v.status === 'approved' ? 'approved' : v.status === 'rejected' ? 'rejected' : 'pending') as 'pending' | 'approved' | 'rejected',
                })),
              });
            }
          }
        } catch {
          // ignore network errors
        }
      },

      submitStudentIdVerification: (docName) =>
        set((state) => {
          const user = state.currentUser;
          const item: StudentVerificationItem = {
            id: `ver-${Date.now()}`,
            studentName: user?.name || 'New Student',
            classNum: user?.classNum || 10,
            school: user?.school || 'DPS School',
            documentName: docName,
            submittedAt: 'Just now',
            status: 'pending',
          };
          return {
            currentUser: user ? { ...user, idCardName: docName } : null,
            verifications: [item, ...state.verifications],
          };
        }),

      handleVerification: async (id, status) => {
        if (get().currentUser?.role !== 'admin') {
          get().syncServerSession();
          return false;
        }
        try {
          const res = await fetch('/api/admin/action', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({
              action: 'HANDLE_VERIFICATION',
              target: id,
              verificationId: id,
              targetStatus: status,
              reason: status === 'rejected' ? 'Document rejected by reviewer' : undefined,
            }),
          });
          const data = await res.json();
          if (res.ok && (data.ok || data.authorized)) {
            set((state) => ({
              verifications: state.verifications.map((v) => (v.id === id ? { ...v, status } : v)),
            }));
            return true;
          }
          return false;
        } catch {
          return false;
        }
      },

      payForExam: (type, razorpayId) =>
        set((state) => ({
          examPaid: { ...state.examPaid, [type]: true },
          payments: [
            {
              id: `pay-${Date.now()}`,
              userId: state.currentUser?.id || 'guest',
              userName: state.currentUser?.name || 'Student',
              amount: 199,
              type: type === 'mid' ? 'mid_exam' : 'final_exam',
              razorpayId,
              status: 'captured',
              createdAt: new Date().toISOString().slice(0, 16).replace('T', ' '),
            },
            ...state.payments,
          ],
        })),

      submitExamAttempt: (type, score, total, answers) => {
        const attempt: ExamAttempt = {
          id: `attempt-${Date.now()}`,
          type,
          score,
          total,
          answers,
          completedAt: new Date().toLocaleString(),
          rank: score >= total * 0.9 ? 1 : score >= total * 0.75 ? 4 : 7,
        };
        set((state) => ({
          examAttempts: [attempt, ...state.examAttempts],
        }));
        return attempt;
      },

      refundPayment: async (paymentId) => {
        if (get().currentUser?.role !== 'admin') {
          get().syncServerSession();
          return false;
        }
        try {
          const idempotencyKey = `idemp_admin_rfnd_${paymentId}_${Date.now()}`;
          const res = await fetch('/api/admin/action', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'x-idempotency-key': idempotencyKey,
            },
            credentials: 'include',
            body: JSON.stringify({
              action: 'REFUND_PAYMENT',
              target: paymentId,
              paymentId,
              idempotencyKey,
            }),
          });
          const data = await res.json();
          if (res.ok && (data.ok || data.authorized)) {
            set((state) => ({
              payments: state.payments.map((p) =>
                p.id === paymentId ? { ...p, status: 'refunded' } : p
              ),
            }));
            return true;
          }
          return false;
        } catch {
          return false;
        }
      },

      addCustomExamQuestion: async (q) => {
        if (get().currentUser?.role !== 'admin') {
          get().syncServerSession();
          return false;
        }
        try {
          const res = await fetch('/api/admin/action', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({
              action: 'ADD_EXAM_QUESTION',
              target: q.id,
              question: q,
            }),
          });
          const data = await res.json();
          if (res.ok && (data.ok || data.authorized)) {
            set((state) => ({
              customExamQuestions: [q, ...state.customExamQuestions],
            }));
            return true;
          }
          return false;
        } catch {
          return false;
        }
      },

      bulkImportExamQuestions: async (questions) => {
        const role = get().currentUser?.role;
        if (role !== 'admin' && role !== 'teacher') {
          get().syncServerSession();
          return 0;
        }
        if (!questions.length) return 0;
        try {
          if (role === 'admin') {
            const res = await fetch('/api/admin/action', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              credentials: 'include',
              body: JSON.stringify({
                action: 'BULK_IMPORT_EXAM_QUESTIONS',
                target: `${questions.length} Exam Questions`,
                questions,
              }),
            });
            const data = await res.json();
            if (!res.ok || (!data.ok && !data.authorized)) {
              return 0;
            }
          }
          set((state) => ({
            customExamQuestions: [...questions, ...state.customExamQuestions],
            auditLogs: [
              {
                id: `aud-${Date.now()}`,
                actor: state.currentUser?.email || 'admin',
                action: 'GOOGLE_SHEETS_IMPORT_MCQS',
                target: `${questions.length} Exam Questions`,
                timestamp: new Date().toISOString().slice(0, 16).replace('T', ' '),
              },
              ...state.auditLogs,
            ],
          }));
          return questions.length;
        } catch {
          return 0;
        }
      },

      deleteCustomExamQuestion: async (id) => {
        if (get().currentUser?.role !== 'admin') {
          get().syncServerSession();
          return false;
        }
        try {
          const res = await fetch('/api/admin/action', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({
              action: 'DELETE_EXAM_QUESTION',
              target: id,
              questionId: id,
            }),
          });
          const data = await res.json();
          if (res.ok && (data.ok || data.authorized)) {
            set((state) => ({
              customExamQuestions: state.customExamQuestions.filter((q) => q.id !== id),
            }));
            return true;
          }
          return false;
        } catch {
          return false;
        }
      },

      importLeaderboardFromSheet: (students) => {
        const role = get().currentUser?.role;
        if (role !== 'admin' && role !== 'teacher') {
          get().syncServerSession();
          return;
        }
        set((state) => ({
          leaderboard: students.map((s, idx) => ({
            ...s,
            rank: s.rank || idx + 1,
          })),
          auditLogs: [
            {
              id: `aud-${Date.now()}`,
              actor: state.currentUser?.email || 'admin',
              action: 'GOOGLE_SHEETS_SYNC_LEADERBOARD',
              target: `${students.length} Leaderboard Records`,
              timestamp: new Date().toISOString().slice(0, 16).replace('T', ' '),
            },
            ...state.auditLogs,
          ],
        }));
        if (role === 'admin') {
          verifyServerAdminAction(
            'IMPORT_LEADERBOARD',
            { target: `${students.length} Leaderboard Records` },
            () => get().syncServerSession()
          );
        }
      },

      markAllNotificationsRead: () =>
        set((state) => ({
          notifications: state.notifications.map((n) => ({ ...n, read: true })),
        })),

      broadcastNotification: async (title, body) => {
        if (get().currentUser?.role !== 'admin') {
          get().syncServerSession();
          return { ok: false };
        }
        try {
          const res = await fetch('/api/admin/action', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({
              action: 'BROADCAST_NOTIFICATION',
              title,
              body,
            }),
          });
          const data = await res.json();
          if (res.ok && (data.ok || data.authorized)) {
            set((state) => ({
              notifications: [
                {
                  id: data.notificationId || `notif-${Date.now()}`,
                  title,
                  body,
                  read: false,
                  createdAt: 'Broadcast • Just now',
                },
                ...state.notifications,
              ],
            }));
            return { ok: true, recipientCount: data.recipientCount || 1 };
          }
          return { ok: false };
        } catch {
          return { ok: false };
        }
      },
    }),
    {
      name: 'uyanix-30days-storage-v1',
      skipHydration: true,
      partialize: (state) => ({
        darkMode: state.darkMode,
        brandLogo: state.brandLogo,
        completedDays: state.completedDays,
        dailyScores: state.dailyScores,
        leaderboard: state.leaderboard,
        teachers: state.teachers,
        referrals: state.referrals,
        withdrawals: state.withdrawals,
        fraudLogs: state.fraudLogs,
        verifications: state.verifications,
        savedChapters: state.savedChapters,
        examAttempts: state.examAttempts,
        notifications: state.notifications,
      }),
      merge: (persistedState, currentState) => {
        const safePersisted = { ...(persistedState as Partial<UyanixState>) };
        // Never trust authentication, role, identity, payment entitlement, audit logs, or answer keys from browser storage
        delete safePersisted.currentUser;
        delete safePersisted.isAuthenticated;
        delete safePersisted.authChecked;
        delete safePersisted.customExamQuestions;
        delete safePersisted.examPaid;
        delete safePersisted.payments;
        delete safePersisted.auditLogs;
        return {
          ...currentState,
          ...safePersisted,
          currentUser: currentState.currentUser,
          isAuthenticated: currentState.isAuthenticated,
          authChecked: currentState.authChecked,
          customExamQuestions: currentState.customExamQuestions,
          examPaid: currentState.examPaid,
          payments: currentState.payments,
          auditLogs: currentState.auditLogs,
        };
      },
    }
  )
);
