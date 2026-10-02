'use client';

import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { EXAM_QUESTIONS_POOL, MCQQuestion } from './curriculum';
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
  idVerified: boolean;
  idCardName?: string;
  streakReminders: boolean;
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
  setBrandLogo: (url: string) => void;
  resetBrandLogo: () => void;
  completeDay: (day: number, score: number) => void;
  refreshLeaderboard: () => void;
  markPrizePaid: (studentId: string) => void;
  toggleBanStudent: (studentId: string) => void;

  // Chapters Admin
  saveChapter: (classNum: number, day: number, title: string, content: string) => void;
  bulkSaveChapters: (classNum: number, days: { day: number; title: string; content: string }[], overwrite: boolean) => number;
  deleteClassChapters: (classNum: number) => void;
  resetAllChapters: () => void;

  // Teacher & Admin Actions
  updateTeacherStatus: (teacherId: string, status: 'approved' | 'rejected' | 'pending') => void;
  requestWithdrawal: (method: 'UPI' | 'Bank', destination: string, amount: number) => boolean;
  processWithdrawal: (withdrawalId: string, status: 'paid' | 'rejected') => void;
  submitTeacherKyc: (pan: string, upiId: string) => void;
  simulateTeacherReferral: () => void;

  // Verifications
  submitStudentIdVerification: (docName: string) => void;
  handleVerification: (id: string, status: 'approved' | 'rejected') => void;

  // Exams & Payments
  payForExam: (type: 'mid' | 'final', razorpayId: string) => void;
  submitExamAttempt: (type: 'mid' | 'final', score: number, total: number, answers: Record<string, number>) => ExamAttempt;
  refundPayment: (paymentId: string) => void;
  addCustomExamQuestion: (q: MCQQuestion) => void;
  bulkImportExamQuestions: (questions: MCQQuestion[]) => number;
  deleteCustomExamQuestion: (id: string) => void;
  importLeaderboardFromSheet: (students: StudentLeader[]) => void;

  // Notifications
  markAllNotificationsRead: () => void;
  broadcastNotification: (title: string, body: string) => void;
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
      completedDays: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
      dailyScores: {
        1: 5, 2: 5, 3: 4, 4: 5, 5: 5, 6: 4, 7: 5, 8: 5, 9: 4, 10: 5, 11: 5, 12: 5, 13: 4, 14: 5, 15: 5,
      },
      leaderboard: INITIAL_LEADERBOARD,
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
      customExamQuestions: EXAM_QUESTIONS_POOL,
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
              examPaid: isUserSwitch
                ? { mid: false, final: false }
                : state.examPaid,
            }));
            return incomingUser;
          }
          set({
            currentUser: null,
            isAuthenticated: false,
            authChecked: true,
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

      setBrandLogo: (url) => {
        if (get().currentUser?.role !== 'admin') {
          get().syncServerSession();
          return;
        }
        set({ brandLogo: url });
        verifyServerAdminAction(
          'SET_BRAND_LOGO',
          { target: 'brandLogo' },
          () => get().syncServerSession()
        );
      },

      resetBrandLogo: () => {
        if (get().currentUser?.role !== 'admin') {
          get().syncServerSession();
          return;
        }
        set({ brandLogo: DEFAULT_LOGO });
        verifyServerAdminAction(
          'RESET_BRAND_LOGO',
          { target: 'brandLogo' },
          () => get().syncServerSession()
        );
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
                body: `Shandar! Aapने Day ${day} quiz mein ${score}/5 score kiya. Streak: ${nextDays.length} days!`,
                read: false,
                createdAt: 'Just now',
              },
              ...state.notifications,
            ],
          };
        }),

      refreshLeaderboard: () =>
        set((state) => ({
          leaderboard: [...state.leaderboard].sort((a, b) => b.score - a.score || a.rank - b.rank),
        })),

      markPrizePaid: (studentId) => {
        if (get().currentUser?.role !== 'admin') {
          get().syncServerSession();
          return;
        }
        set((state) => ({
          leaderboard: state.leaderboard.map((s) =>
            s.id === studentId ? { ...s, prizePaid: !s.prizePaid } : s
          ),
          auditLogs: [
            {
              id: `aud-${Date.now()}`,
              actor: state.currentUser?.email || 'admin',
              action: 'PRIZE_MARK_PAID',
              target: studentId,
              timestamp: new Date().toISOString().slice(0, 16).replace('T', ' '),
            },
            ...state.auditLogs,
          ],
        }));
        verifyServerAdminAction(
          'MARK_PRIZE_PAID',
          { target: studentId },
          () => get().syncServerSession()
        );
      },

      toggleBanStudent: (studentId) => {
        if (get().currentUser?.role !== 'admin') {
          get().syncServerSession();
          return;
        }
        const targetStudent = get().leaderboard.find((s) => s.id === studentId);
        const nextBanned = targetStudent?.status !== 'banned';
        set((state) => ({
          leaderboard: state.leaderboard.map((s) =>
            s.id === studentId ? { ...s, status: s.status === 'banned' ? 'active' : 'banned' } : s
          ),
        }));
        verifyServerAdminAction(
          'TOGGLE_BAN_STUDENT',
          { target: studentId, targetUserId: studentId, banned: nextBanned },
          () => get().syncServerSession()
        );
      },

      saveChapter: (classNum, day, title, content) => {
        if (get().currentUser?.role !== 'admin') {
          get().syncServerSession();
          return;
        }
        set((state) => {
          const key = `${classNum}-${day}`;
          return {
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
            auditLogs: [
              {
                id: `aud-${Date.now()}`,
                actor: state.currentUser?.email || 'admin',
                action: 'SAVE_CHAPTER',
                target: `Class ${classNum} Day ${day}: ${title}`,
                timestamp: new Date().toISOString().slice(0, 16).replace('T', ' '),
              },
              ...state.auditLogs,
            ],
          };
        });
        verifyServerAdminAction(
          'SAVE_CHAPTER',
          { target: `Class ${classNum} Day ${day}: ${title}` },
          () => get().syncServerSession()
        );
      },

      bulkSaveChapters: (classNum, days, overwrite) => {
        if (get().currentUser?.role !== 'admin') {
          get().syncServerSession();
          return 0;
        }
        let count = 0;
        set((state) => {
          const updated = { ...state.savedChapters };
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
              count++;
            }
          }
          return { savedChapters: updated };
        });
        verifyServerAdminAction(
          'BULK_SAVE_CHAPTERS',
          { target: `Class ${classNum} (${count} chapters)` },
          () => get().syncServerSession()
        );
        return count;
      },

      deleteClassChapters: (classNum) => {
        if (get().currentUser?.role !== 'admin') {
          get().syncServerSession();
          return;
        }
        set((state) => {
          const next = { ...state.savedChapters };
          Object.keys(next).forEach((k) => {
            if (k.startsWith(`${classNum}-`)) {
              delete next[k];
            }
          });
          return { savedChapters: next };
        });
        verifyServerAdminAction(
          'DELETE_CLASS_CHAPTERS',
          { target: `Class ${classNum}` },
          () => get().syncServerSession()
        );
      },

      resetAllChapters: () => {
        if (get().currentUser?.role !== 'admin') {
          get().syncServerSession();
          return;
        }
        set({ savedChapters: {} });
        verifyServerAdminAction(
          'RESET_ALL_CHAPTERS',
          { target: 'all_classes' },
          () => get().syncServerSession()
        );
      },

      updateTeacherStatus: (teacherId, status) => {
        if (get().currentUser?.role !== 'admin') {
          get().syncServerSession();
          return;
        }
        set((state) => ({
          teachers: state.teachers.map((t) => (t.id === teacherId ? { ...t, status } : t)),
          auditLogs: [
            {
              id: `aud-${Date.now()}`,
              actor: state.currentUser?.email || 'admin',
              action: `TEACHER_${status.toUpperCase()}`,
              target: teacherId,
              timestamp: new Date().toISOString().slice(0, 16).replace('T', ' '),
            },
            ...state.auditLogs,
          ],
        }));
        verifyServerAdminAction(
          'UPDATE_TEACHER_STATUS',
          { target: `${teacherId}:${status}` },
          () => get().syncServerSession()
        );
      },

      requestWithdrawal: (method, destination, amount) => {
        const state = get();
        const role = state.currentUser?.role;
        if (role !== 'teacher' && role !== 'admin') {
          state.syncServerSession();
          return false;
        }
        const teacher = state.teachers[0];
        if (!teacher || teacher.balance < amount || amount < 500) return false;

        const newWithdrawal: WithdrawalRequest = {
          id: generateCryptographicOpaqueRecordId('WD'),
          teacherId: teacher.id,
          teacherName: teacher.name,
          date: new Date().toISOString().slice(0, 10),
          method,
          destination,
          amount,
          status: 'pending',
          invoiceId: generateCryptographicOpaqueRecordId('PAY'),
        };

        set({
          teachers: state.teachers.map((t, idx) =>
            idx === 0 ? { ...t, balance: t.balance - amount } : t
          ),
          withdrawals: [newWithdrawal, ...state.withdrawals],
        });

        verifyServerTeacherAction(
          'REQUEST_WITHDRAWAL',
          { method, destination, amount },
          () => get().syncServerSession()
        );
        return true;
      },

      processWithdrawal: (withdrawalId, status) => {
        if (get().currentUser?.role !== 'admin') {
          get().syncServerSession();
          return;
        }
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
        verifyServerAdminAction(
          'PROCESS_WITHDRAWAL',
          { target: `${withdrawalId}:${status}` },
          () => get().syncServerSession()
        );
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

      handleVerification: (id, status) => {
        if (get().currentUser?.role !== 'admin') {
          get().syncServerSession();
          return;
        }
        set((state) => ({
          verifications: state.verifications.map((v) => (v.id === id ? { ...v, status } : v)),
        }));
        verifyServerAdminAction(
          'HANDLE_VERIFICATION',
          { target: `${id}:${status}` },
          () => get().syncServerSession()
        );
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

      refundPayment: (paymentId) => {
        if (get().currentUser?.role !== 'admin') {
          get().syncServerSession();
          return;
        }
        set((state) => ({
          payments: state.payments.map((p) =>
            p.id === paymentId ? { ...p, status: 'refunded' } : p
          ),
        }));
        verifyServerAdminAction(
          'REFUND_PAYMENT',
          { target: paymentId },
          () => get().syncServerSession()
        );
      },

      addCustomExamQuestion: (q) => {
        if (get().currentUser?.role !== 'admin') {
          get().syncServerSession();
          return;
        }
        set((state) => ({
          customExamQuestions: [q, ...state.customExamQuestions],
        }));
        verifyServerAdminAction(
          'ADD_EXAM_QUESTION',
          { target: q.id },
          () => get().syncServerSession()
        );
      },

      bulkImportExamQuestions: (questions) => {
        const role = get().currentUser?.role;
        if (role !== 'admin' && role !== 'teacher') {
          get().syncServerSession();
          return 0;
        }
        if (!questions.length) return 0;
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
        if (role === 'admin') {
          verifyServerAdminAction(
            'BULK_IMPORT_EXAM_QUESTIONS',
            { target: `${questions.length} Exam Questions` },
            () => get().syncServerSession()
          );
        }
        return questions.length;
      },

      deleteCustomExamQuestion: (id) => {
        if (get().currentUser?.role !== 'admin') {
          get().syncServerSession();
          return;
        }
        set((state) => ({
          customExamQuestions: state.customExamQuestions.filter((q) => q.id !== id),
        }));
        verifyServerAdminAction(
          'DELETE_EXAM_QUESTION',
          { target: id },
          () => get().syncServerSession()
        );
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

      broadcastNotification: (title, body) => {
        if (get().currentUser?.role !== 'admin') {
          get().syncServerSession();
          return;
        }
        set((state) => ({
          notifications: [
            {
              id: `notif-${Date.now()}`,
              title,
              body,
              read: false,
              createdAt: 'Broadcast • Just now',
            },
            ...state.notifications,
          ],
        }));
        verifyServerAdminAction(
          'BROADCAST_NOTIFICATION',
          { target: title },
          () => get().syncServerSession()
        );
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
