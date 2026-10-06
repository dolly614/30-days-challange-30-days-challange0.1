import 'server-only';

import { MCQQuestion, TOPIC_MCQS_BANK } from '@/lib/curriculum';

export interface ServerAuthoritativeQuestion {
  id: string;
  examType: 'mid' | 'final';
  questionText: string;
  options: [string, string, string, string];
  correctOption: number;
  explanation: string;
  topic: string;
  classNum: number;
  questionVersion: number;
}

export interface SanitizedStudentQuestion {
  id: string;
  questionNumber: number;
  questionText: string;
  options: [string, string, string, string];
  topic: string;
  questionVersion: number;
}

// Master question bank stored exclusively on the server
export const SERVER_AUTHORITATIVE_QUESTIONS_VAULT: ServerAuthoritativeQuestion[] = [
  ...((TOPIC_MCQS_BANK['Quadratic Equations'] || []).map((q, idx) => ({
    id: q.id || `quad-${idx}`,
    examType: 'mid' as const,
    questionText: q.question,
    options: q.options,
    correctOption: q.correctIndex,
    explanation: q.explanation,
    topic: 'Quadratic Equations',
    classNum: 12,
    questionVersion: 1,
  }))),
  ...((TOPIC_MCQS_BANK['Globalization'] || []).map((q, idx) => ({
    id: q.id || `glob-${idx}`,
    examType: 'mid' as const,
    questionText: q.question,
    options: q.options,
    correctOption: q.correctIndex,
    explanation: q.explanation,
    topic: 'Globalization',
    classNum: 12,
    questionVersion: 1,
  }))),
  ...((TOPIC_MCQS_BANK['Indian Constitution Basics'] || []).map((q, idx) => ({
    id: q.id || `const-${idx}`,
    examType: 'mid' as const,
    questionText: q.question,
    options: q.options,
    correctOption: q.correctIndex,
    explanation: q.explanation,
    topic: 'Indian Constitution Basics',
    classNum: 12,
    questionVersion: 1,
  }))),
  {
    id: 'ex-16',
    examType: 'mid',
    questionText: 'Newton ka First Law of Motion kis naam se bhi jaana jaata hai?',
    options: ['Law of Momentum', 'Law of Inertia', 'Law of Action-Reaction', 'Law of Gravitation'],
    correctOption: 1,
    explanation: 'Newton ke First Law ko Law of Inertia kehte hain: koi object tab tak apni state nahi badalta jab tak external force na lage.',
    topic: "Newton's Laws",
    classNum: 12,
    questionVersion: 1,
  },
  {
    id: 'ex-17',
    examType: 'mid',
    questionText: 'Cell ka "Powerhouse" kise kaha jaata hai?',
    options: ['Nucleus', 'Ribosome', 'Mitochondria', 'Golgi Body'],
    correctOption: 2,
    explanation: 'Mitochondria ATP (energy currency) banata hai, isliye isse Powerhouse of the Cell kehte hain.',
    topic: 'Cell Biology',
    classNum: 12,
    questionVersion: 1,
  },
  {
    id: 'ex-18',
    examType: 'mid',
    questionText: 'Electric current ka SI unit kya hai?',
    options: ['Volt', 'Ohm', 'Ampere', 'Watt'],
    correctOption: 2,
    explanation: 'Electric current (I) ko Ampere (A) mein maapa jaata hai.',
    topic: 'Electricity Basics',
    classNum: 12,
    questionVersion: 1,
  },
  {
    id: 'ex-19',
    examType: 'mid',
    questionText: 'Arithmetic Progression (AP): 2, 5, 8, 11... ka 10th term kya hoga?',
    options: ['27', '29', '32', '30'],
    correctOption: 1,
    explanation: 'a = 2, d = 3. a₁₀ = a + 9d = 2 + 9(3) = 29.',
    topic: 'Arithmetic Progression',
    classNum: 12,
    questionVersion: 1,
  },
  {
    id: 'ex-20',
    examType: 'mid',
    questionText: 'Ek fair coin ko uchhalne par Head aane ki probability kya hoti hai?',
    options: ['1', '1/2', '1/4', '0'],
    correctOption: 1,
    explanation: 'Total outcomes = 2 (Head, Tail), favourable = 1. Toh probability = 1/2 (0.5).',
    topic: 'Probability',
    classNum: 12,
    questionVersion: 1,
  },
  {
    id: 'ex-21',
    examType: 'final',
    questionText: 'Modern Periodic Table mein elements kis basis par arrange kiye gaye hain?',
    options: ['Atomic Mass', 'Atomic Number', 'Density', 'Alphabetical Order'],
    correctOption: 1,
    explanation: 'Henry Moseley ke according Modern Periodic Table increasing Atomic Number (Z) par based hai.',
    topic: 'Periodic Table',
    classNum: 12,
    questionVersion: 1,
  },
  {
    id: 'ex-22',
    examType: 'final',
    questionText: 'sin²θ + cos²θ ki value hamesha kitni hoti hai?',
    options: ['0', '1', '2', 'tan θ'],
    correctOption: 1,
    explanation: 'Fundamental trigonometric identity ke anusar sin²θ + cos²θ = 1 hota hai.',
    topic: 'Trigonometry',
    classNum: 12,
    questionVersion: 1,
  },
  {
    id: 'ex-23',
    examType: 'final',
    questionText: 'Point (3, 4) ki origin (0, 0) se distance kitni hogi?',
    options: ['7 units', '5 units', '12 units', '1 unit'],
    correctOption: 1,
    explanation: 'Distance = √(3² + 4²) = √(9 + 16) = √25 = 5 units.',
    topic: 'Coordinate Geometry',
    classNum: 12,
    questionVersion: 1,
  },
  {
    id: 'ex-24',
    examType: 'final',
    questionText: 'Reserve Bank of India (RBI) ka main kaam kya hai?',
    options: [
      'Sirf schools chalana',
      'Currency issue karna aur monetary policy control karna',
      'Trains chalana',
      'Road tax collect karna',
    ],
    correctOption: 1,
    explanation: 'RBI India ka central bank hai jo currency notes issue karta hai aur banks/credit ko regulate karna hai.',
    topic: 'Indian Economy',
    classNum: 12,
    questionVersion: 1,
  },
  {
    id: 'ex-25',
    examType: 'final',
    questionText: 'Series 3, 6, 12, 24, ? mein agla number kya aayega?',
    options: ['36', '48', '30', '42'],
    correctOption: 1,
    explanation: 'Har number double (×2) ho raha hai: 3×2=6, 6×2=12, 12×2=24, 24×2=48.',
    topic: 'Logical Reasoning',
    classNum: 12,
    questionVersion: 1,
  },
];

/**
 * Creates an immutable snapshot of exam questions for a new attempt.
 * Retains answer keys only in server memory/database snapshot, NEVER returned to student.
 */
export function getAuthoritativeQuestionsForExamType(
  examType: 'mid' | 'final'
): ServerAuthoritativeQuestion[] {
  // Return all questions matching the exam type, or complete pool
  const matches = SERVER_AUTHORITATIVE_QUESTIONS_VAULT.filter(
    (q) => q.examType === examType || examType === 'final'
  );
  return matches.length > 0 ? matches : SERVER_AUTHORITATIVE_QUESTIONS_VAULT;
}

/**
 * Sanitizes questions for student-facing APIs.
 * STRICT: Absolutely no correctOption, explanation, or scoring metadata!
 */
export function sanitizeQuestionsForCandidate(
  questions: ServerAuthoritativeQuestion[]
): SanitizedStudentQuestion[] {
  return questions.map((q, idx) => ({
    id: q.id,
    questionNumber: idx + 1,
    questionText: q.questionText,
    options: [q.options[0], q.options[1], q.options[2], q.options[3]],
    topic: q.topic,
    questionVersion: q.questionVersion,
  }));
}
