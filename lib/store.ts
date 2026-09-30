'use client';

import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { EXAM_QUESTIONS_POOL, MCQQuestion } from './curriculum';

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
  login: (user: Partial<UserProfile>) => void;
  logout: () => void;
  updateProfile: (updates: Partial<UserProfile>) => void;
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

export const useUyanixStore = create<UyanixState>()(
  persist(
    (set, get) => ({
      currentUser: {
        id: 'user-dolly-1',
        name: 'dollysingh',
        teacherShortName: 'dolly',
        email: 'dollysingh1268@gmail.com',
        phone: '9000012345',
        classNum: 12,
        school: 'Delhi Public School, Jaipur',
        city: 'Jaipur',
        role: 'admin',
        idVerified: true,
        streakReminders: true,
        createdAt: '2026-09-01T10:00:00Z',
      },
      isAuthenticated: true,
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
          body: 'Badhai ho dollysingh! Aapka 15-Day Mid Exam ab unlock ho chuka hai.',
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
          actor: 'dollysingh1268@gmail.com',
          action: 'SYSTEM_INIT',
          target: 'Uyanix 30 Days Batch #4',
          timestamp: '2026-09-27 08:00',
        },
      ],

      login: (userData) =>
        set((state) => {
          const updated: UserProfile = {
            ...(state.currentUser || {
              id: `user-${Date.now()}`,
              name: 'dollysingh',
              teacherShortName: 'dolly',
              email: 'dollysingh1268@gmail.com',
              phone: '9000012345',
              classNum: 12,
              school: 'Delhi Public School',
              city: 'Jaipur',
              role: 'student',
              idVerified: true,
              streakReminders: true,
              createdAt: new Date().toISOString(),
            }),
            ...userData,
          };
          return {
            currentUser: updated,
            isAuthenticated: true,
            auditLogs: [
              {
                id: `aud-${Date.now()}`,
                actor: updated.email || updated.phone,
                action: 'USER_LOGIN',
                target: updated.name,
                timestamp: new Date().toISOString().slice(0, 16).replace('T', ' '),
              },
              ...state.auditLogs,
            ],
          };
        }),

      logout: () =>
        set((state) => ({
          isAuthenticated: false,
          auditLogs: [
            {
              id: `aud-${Date.now()}`,
              actor: state.currentUser?.email || 'user',
              action: 'USER_LOGOUT',
              target: state.currentUser?.name || 'session',
              timestamp: new Date().toISOString().slice(0, 16).replace('T', ' '),
            },
            ...state.auditLogs,
          ],
        })),

      updateProfile: (updates) =>
        set((state) => ({
          currentUser: state.currentUser ? { ...state.currentUser, ...updates } : null,
        })),

      toggleDarkMode: () =>
        set((state) => {
          const next = !state.darkMode;
          if (typeof document !== 'undefined') {
            document.documentElement.classList.toggle('dark', next);
          }
          return { darkMode: next };
        }),

      setBrandLogo: (url) => set({ brandLogo: url }),
      resetBrandLogo: () => set({ brandLogo: DEFAULT_LOGO }),

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

      markPrizePaid: (studentId) =>
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
        })),

      toggleBanStudent: (studentId) =>
        set((state) => ({
          leaderboard: state.leaderboard.map((s) =>
            s.id === studentId ? { ...s, status: s.status === 'banned' ? 'active' : 'banned' } : s
          ),
        })),

      saveChapter: (classNum, day, title, content) =>
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
        }),

      bulkSaveChapters: (classNum, days, overwrite) => {
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
        return count;
      },

      deleteClassChapters: (classNum) =>
        set((state) => {
          const next = { ...state.savedChapters };
          Object.keys(next).forEach((k) => {
            if (k.startsWith(`${classNum}-`)) {
              delete next[k];
            }
          });
          return { savedChapters: next };
        }),

      resetAllChapters: () => set({ savedChapters: {} }),

      updateTeacherStatus: (teacherId, status) =>
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
        })),

      requestWithdrawal: (method, destination, amount) => {
        const state = get();
        const teacher = state.teachers[0];
        if (!teacher || teacher.balance < amount || amount < 500) return false;

        const newWithdrawal: WithdrawalRequest = {
          id: `wd-${Date.now()}`,
          teacherId: teacher.id,
          teacherName: teacher.name,
          date: new Date().toISOString().slice(0, 10),
          method,
          destination,
          amount,
          status: 'pending',
          invoiceId: `INV-UYX-${Math.floor(100000 + Math.random() * 900000)}`,
        };

        set({
          teachers: state.teachers.map((t, idx) =>
            idx === 0 ? { ...t, balance: t.balance - amount } : t
          ),
          withdrawals: [newWithdrawal, ...state.withdrawals],
        });
        return true;
      },

      processWithdrawal: (withdrawalId, status) =>
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
        }),

      submitTeacherKyc: (pan, upiId) =>
        set((state) => ({
          teachers: state.teachers.map((t, idx) =>
            idx === 0 ? { ...t, kycPan: pan.toUpperCase(), upiId, kycVerified: true, status: 'approved' } : t
          ),
        })),

      simulateTeacherReferral: () =>
        set((state) => {
          const names = ['Rohan Gupta', 'Priya Nair', 'Aditya Chauhan', 'Neha Kumari', 'Yashvardhan'];
          const pick = names[Math.floor(Math.random() * names.length)];
          const cls = Math.floor(Math.random() * 12) + 1;

          const newRef: ReferralItem = {
            id: `ref-${Date.now()}`,
            teacherCode: 'DOLLOXW0',
            studentName: pick,
            studentClass: cls,
            status: 'verified',
            commission: 15,
            date: 'Today',
          };

          return {
            referrals: [newRef, ...state.referrals],
            teachers: state.teachers.map((t, idx) => {
              if (idx !== 0) return t;
              const nextPaid = t.paidActiveCount + 1;
              const commission = nextPaid > 200 ? 20 : nextPaid > 50 ? 15 : 10;
              const addAmount = Math.max(commission, 250); // Add ₹250 in demo so teacher can test ₹500 withdrawal quickly
              const nextTier =
                nextPaid > 200
                  ? 'Super Educator'
                  : nextPaid >= 5
                  ? 'Active Mentor'
                  : 'Beginner Teacher';

              const updatedSignups = t.dailySignups.map((d, i) =>
                i === t.dailySignups.length - 1 ? { ...d, count: d.count + 1 } : d
              );

              return {
                ...t,
                status: 'approved',
                referredCount: t.referredCount + 1,
                paidActiveCount: nextPaid,
                balance: t.balance + addAmount,
                totalEarned: t.totalEarned + addAmount,
                thisMonthEarned: t.thisMonthEarned + addAmount,
                tier: nextTier,
                dailySignups: updatedSignups,
              };
            }),
          };
        }),

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
            currentUser: user ? { ...user, idVerified: true, idCardName: docName } : null,
            verifications: [item, ...state.verifications],
          };
        }),

      handleVerification: (id, status) =>
        set((state) => ({
          verifications: state.verifications.map((v) => (v.id === id ? { ...v, status } : v)),
        })),

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

      refundPayment: (paymentId) =>
        set((state) => ({
          payments: state.payments.map((p) =>
            p.id === paymentId ? { ...p, status: 'refunded' } : p
          ),
        })),

      addCustomExamQuestion: (q) =>
        set((state) => ({
          customExamQuestions: [q, ...state.customExamQuestions],
        })),

      bulkImportExamQuestions: (questions) => {
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
        return questions.length;
      },

      deleteCustomExamQuestion: (id) =>
        set((state) => ({
          customExamQuestions: state.customExamQuestions.filter((q) => q.id !== id),
        })),

      importLeaderboardFromSheet: (students) =>
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
        })),

      markAllNotificationsRead: () =>
        set((state) => ({
          notifications: state.notifications.map((n) => ({ ...n, read: true })),
        })),

      broadcastNotification: (title, body) =>
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
        })),
    }),
    {
      name: 'uyanix-30days-storage-v1',
      skipHydration: true,
    }
  )
);
