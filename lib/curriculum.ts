export interface MCQQuestion {
  id: string;
  question: string;
  options: [string, string, string, string];
  correctIndex: number;
  explanation: string;
  topic?: string;
}

export interface ChapterData {
  id: string;
  classNum: number;
  day: number;
  title: string;
  summary: string;
  content: string;
  keyTakeaways: string[];
  pdfUrl?: string;
  mcqs: MCQQuestion[];
}

export const CLASS_1_TOPICS: string[] = [
  'Counting 1 to 100',
  'Hindi Varnamala',
  'Colours & Shapes',
  'My Family',
  'Days of the Week',
  'Fruits & Vegetables',
  'Animals & Birds',
  'Body Parts',
  'Good Habits',
  'Seasons of India',
  'Festivals of India',
  'National Symbols',
  'Simple Addition',
  'Simple Subtraction',
  'English Alphabet',
  'Rhyming Words',
  'Story: The Thirsty Crow',
  'Solar System Basics',
  'Plants Around Us',
  'Water Cycle',
  'Means of Transport',
  'Healthy Food',
  'Safety Rules',
  'My School',
  'Helpers in Society',
  'Indian States',
  'Famous Monuments',
  'Traffic Rules',
  'Revision Day',
  'Final Practice',
];

export const CLASS_12_TOPICS: string[] = [
  'Quadratic Equations',
  'Trigonometry',
  'Coordinate Geometry',
  'Statistics',
  'Probability',
  'Polynomials',
  'Surface Area & Volume',
  'Arithmetic Progression',
  "Newton's Laws",
  'Electricity Basics',
  'Chemical Reactions',
  'Periodic Table',
  'Cell Biology',
  'Genetics',
  'Indian Economy',
  'Globalization',
  'Reading Comprehension',
  'Essay Writing',
  'Indian Polity',
  'Fundamental Rights',
  'Modern Indian History',
  'World Wars',
  'Geography: Climate',
  'Natural Resources',
  'English Grammar Advanced',
  'Hindi Sahitya',
  'Logical Reasoning',
  'Current Affairs',
  'Full Revision',
  'Final Mock Test',
];

export const MIDDLE_CLASS_TOPICS: string[] = [
  'Number System & Fractions',
  'Basic Algebra & Expressions',
  'Geometry: Lines & Angles',
  'Data Handling & Graphs',
  'Ratio & Proportion',
  'Percentage & Profit-Loss',
  'Mensuration: Area & Perimeter',
  'Linear Equations',
  'Force, Work & Energy',
  'Light, Shadows & Reflections',
  'Acids, Bases & Salts',
  'Metals & Non-Metals',
  'Indian Constitution Basics',
  'Human Digestive & Respiratory System',
  'Our Environment & Ecosystem',
  'Globalization & Trade',
  'English Reading Comprehension',
  'Creative Paragraph Writing',
  'Panchayati Raj & Local Govt',
  'Fundamental Rights & Duties',
  'Indian Freedom Struggle',
  'Ancient Civilizations',
  'Indian Monsoon & Climate',
  'Soil, Water & Forest Resources',
  'Tenses & Active-Passive Voice',
  'Hindi Vyakaran & Muhavare',
  'Coding-Decoding & Logical Puzzles',
  'India & World Current Affairs',
  'Complete 30-Day Revision',
  'Grand Finale Mock Practice',
];

export function getTopicsForClass(classNum: number): string[] {
  if (classNum <= 3) return CLASS_1_TOPICS;
  if (classNum >= 9) return CLASS_12_TOPICS;
  return MIDDLE_CLASS_TOPICS;
}

export const TOPIC_MCQS_BANK: Record<string, MCQQuestion[]> = {
  'Quadratic Equations': [
    {
      id: 'qe-1',
      question: 'Standard form of a quadratic equation kya hota hai?',
      options: ['ax + b = 0', 'ax² + bx + c = 0 (a ≠ 0)', 'ax³ + bx² + c = 0', 'ax² + bx = c²'],
      correctIndex: 1,
      explanation: 'Quadratic equation ki degree 2 hoti hai, isliye standard form ax² + bx + c = 0 hota hai jahan a ≠ 0.',
    },
    {
      id: 'qe-2',
      question: 'Equation x² - 5x + 6 = 0 ke roots kya honge?',
      options: ['2 aur 3', '-2 aur -3', '1 aur 6', '-1 aur 6'],
      correctIndex: 0,
      explanation: 'x² - 5x + 6 = (x - 2)(x - 3) = 0, toh roots x = 2 aur x = 3 hain.',
    },
    {
      id: 'qe-3',
      question: 'Discriminant (D) ka sahi formula kaunsa hai?',
      options: ['b² + 4ac', 'b² - 4ac', '2b - 4ac', '4ac - b²'],
      correctIndex: 1,
      explanation: 'Discriminant D = b² - 4ac se pata chalta hai ki roots real hain ya imaginary.',
    },
    {
      id: 'qe-4',
      question: 'Agar D = 0 ho, toh quadratic equation ke roots kaise hote hain?',
      options: ['Real aur Distinct', 'Real aur Equal', 'Imaginary (No real roots)', 'Zero roots'],
      correctIndex: 1,
      explanation: 'Jab b² - 4ac = 0 hota hai, dono roots real aur barabar (-b / 2a) hote hain.',
    },
    {
      id: 'qe-5',
      question: '2x² - 4x + 3 = 0 ka discriminant (D) kitna hoga?',
      options: ['-8', '8', '40', '-4'],
      correctIndex: 0,
      explanation: 'Yahan a=2, b=-4, c=3. D = (-4)² - 4(2)(3) = 16 - 24 = -8.',
    },
  ],
  'Globalization': [
    {
      id: 'gl-1',
      question: 'Globalization ka main matlab kya hai?',
      options: [
        'Sirf ek desh ke andar trade karna',
        'Duniya bhar ki economies, markets aur cultures ka aapas mein judna',
        'Foreign imports par 100% ban lagana',
        'Local shops band karna',
      ],
      correctIndex: 1,
      explanation: 'Globalization ka arth hai different countries ke beech trade, investment, aur technology ka fast integration.',
    },
    {
      id: 'gl-2',
      question: 'India mein New Economic Policy (LPG Reforms) kis saal laagu hui thi?',
      options: ['1947', '1985', '1991', '2001'],
      correctIndex: 2,
      explanation: '1991 mein Liberalization, Privatization aur Globalization (LPG) reforms se Indian economy open hui.',
    },
    {
      id: 'gl-3',
      question: 'MNC ka full form kya hota hai?',
      options: [
        'Multi-National Corporation',
        'Modern National Company',
        'Macro Network Council',
        'Multi-Network Commerce',
      ],
      correctIndex: 0,
      explanation: 'MNC (Multi-National Corporation) woh company hai jo ek se zyada deshon mein production ya service control karti hai.',
    },
    {
      id: 'gl-4',
      question: 'WTO (World Trade Organization) ka main kaam kya hai?',
      options: [
        'Taxes badhana',
        'International trade ko free aur fair banana',
        'Sirf rich countries ko loan dena',
        'Passports issue karna',
      ],
      correctIndex: 1,
      explanation: 'WTO international trade rules banata hai taaki deshon ke beech bina rukawat vyapar ho sake.',
    },
    {
      id: 'gl-5',
      question: 'Foreign कंपनी jab India mein factory ya office lagati hai toh usse kya kehte hain?',
      options: ['Foreign Direct Investment (FDI)', 'Domestic Tax', 'Import Duty', 'Subsidy'],
      correctIndex: 0,
      explanation: 'MNCs dwara land, building aur machines mein kiye gaye investment ko Foreign Direct Investment (FDI) kehte hain.',
    },
  ],
  'Indian Constitution Basics': [
    {
      id: 'ic-1',
      question: 'Indian Constitution ke Drafting Committee ke Chairman kaun the?',
      options: ['Mahatma Gandhi', 'Pt. Jawaharlal Nehru', 'Dr. B.R. Ambedkar', 'Sardar Vallabhbhai Patel'],
      correctIndex: 2,
      explanation: 'Dr. Bhimrao Ambedkar Drafting Committee ke Chairman the aur unhe Father of Indian Constitution kaha jaata hai.',
    },
    {
      id: 'ic-2',
      question: 'Hamara Samvidhan (Constitution) poori tarah kab laagu hua?',
      options: ['15 August 1947', '26 November 1949', '26 January 1950', '2 October 1950'],
      correctIndex: 2,
      explanation: '26 January 1950 ko Indian Constitution poori tarah laagu hua, jise hum Republic Day ke roop mein manate hain.',
    },
    {
      id: 'ic-3',
      question: 'Indian Constitution mein citizens ko kitne Fundamental Rights diye gaye hain?',
      options: ['5', '6', '7', '10'],
      correctIndex: 1,
      explanation: 'Abhi Indian Constitution mein 6 Fundamental Rights hain (Right to Equality, Freedom, against Exploitation, Freedom of Religion, Cultural & Educational, Constitutional Remedies).',
    },
    {
      id: 'ic-4',
      question: 'Constitution ki Preamble (Prastavana) kis shabd se shuru hoti hai?',
      options: ['Bharat Mata Ki Jai', 'We, the People of India', 'Satyameva Jayate', 'In the Name of Parliament'],
      correctIndex: 1,
      explanation: 'Preamble "We, the People of India" (Hum, Bharat ke Log) se shuru hoti hai jo dikhata hai ki asli taqat janta ke paas hai.',
    },
    {
      id: 'ic-5',
      question: 'Fundamental Duties Constitution ke kis Part mein hain?',
      options: ['Part III', 'Part IV', 'Part IV-A (Article 51A)', 'Part V'],
      correctIndex: 2,
      explanation: '42nd Amendment (1976) ke zariye Part IV-A (Article 51A) mein Fundamental Duties jodi gayi.',
    },
  ],
};

export function generateChapterForClassAndDay(classNum: number, day: number): ChapterData {
  const topics = getTopicsForClass(classNum);
  const title = topics[(day - 1) % topics.length] || `Day ${day} Topic`;

  const customMcqs = TOPIC_MCQS_BANK[title];
  const mcqs: MCQQuestion[] = customMcqs || [
    {
      id: `c${classNum}-d${day}-q1`,
      question: `"${title}" chapter ka sabse important foundational concept kaunsa hai?`,
      options: [
        `${title} ke core rules aur real-life applications samajhna`,
        'Bina samjhe ratta lagana',
        'Examples skip karna',
        'Formula ko ulta likhna',
      ],
      correctIndex: 0,
      explanation: `Concept clarity sabse zaroori hai! ${title} ke core rules aur real-world examples samajhne se exam mein 100% accuracy aati hai.`,
    },
    {
      id: `c${classNum}-d${day}-q2`,
      question: `Day ${day} (${title}) ke questions solve karte waqt pehla step kya hona chahiye?`,
      options: [
        'Sidha option guess karna',
        'Given data aur question ki requirement dhyan se padhna',
        'Question chhod dena',
        'Timer band karna',
      ],
      correctIndex: 1,
      explanation: 'Hamesha pehle question mein diye gaye values/keywords identify karein, phir sahi rule lagayein.',
    },
    {
      id: `c${classNum}-d${day}-q3`,
      question: `Class ${classNum} curriculum mein "${title}" kyun padhaya jaata hai?`,
      options: [
        'Analytical thinking aur problem-solving strong karne ke liye',
        'Sirf homework badhane ke liye',
        'Iska koi use nahi hai',
        'Sirf drawing ke liye',
      ],
      correctIndex: 0,
      explanation: `${title} aapki logical reasoning aur board/competitive foundation ko strong banata hai.`,
    },
    {
      id: `c${classNum}-d${day}-q4`,
      question: `Agar "${title}" ke kisi question mein 2 options close lagein, toh kya karna chahiye?`,
      options: [
        'Elimination method use karke core definition check karni chahiye',
        'Dono mark kar dene chahiye',
        'Exam band kar dena chahiye',
        'Random click karna chahiye',
      ],
      correctIndex: 0,
      explanation: 'Elimination method se galat options hatao aur exact NCERT/standard definition se match karo.',
    },
    {
      id: `c${classNum}-d${day}-q5`,
      question: `Uyanix 30 Days Challenge mein Day ${day} complete karne se aapke streak aur rank par kya asar padta hai?`,
      options: [
        'Daily streak +1 badhti hai aur Leaderboard score improve hota hai',
        'Rank kam ho jaata hai',
        'Koi farak nahi padta',
        'Account lock ho jaata hai',
      ],
      correctIndex: 0,
      explanation: 'Roz chapter padhne aur 5 MCQs solve karne se aapka daily streak badhta hai aur Top 3 prizes jeetne ka chance strong hota hai!',
    },
  ];

  const defaultContent = `# Day ${day}: ${title} (Class ${classNum})

Namaste Champion! 🌟 **Uyanix 30 Days Challenge** ke **Day ${day}** mein aapka swagat hai. Aaj hum **${title}** ko bilkul aasaan aur practical Hinglish bhasha mein samjhenge taaki aap daily quiz aur final exam dono mein full marks laa sakein.

---

### 🎯 1. Core Concept (Asli Matlab Kya Hai?)
**${title}** Class ${classNum} ke syllabus ka ek bahut hi scoring aur foundational topic hai. Jab hum iske basic principles ko daily life ke examples se jodte hain, toh bade se bada sawal bhi 30 seconds ke andar solve ho jaata hai.

* **Definition & Foundation:** Har concept ke peeche ek cause-and-effect rule hota hai. ${title} mein sabse pehle key terms aur unke beech ka relation yaad rakhein.
* **Smart Shortcut:** Ratta maarne ke bajaye keyword पहचानो — exam mein 80% questions direct core property par aate hain.

---

### 💡 2. Step-by-Step Breakdown & Examples
1. **Step 1 — Identify the Pattern:** Question mein kya diya gaya hai (Given) aur kya poocha gaya hai (To Find), usse underline karein.
2. **Step 2 — Apply the Golden Rule:** ${title} ka standard rule ya formula apply karein.
3. **Step 3 — Verify Units & Logic:** Answer tick karne se pehle check karein ki kya result practical aur logical hai.

> **Pro Tip for Uyanix Toppers 🏆:** Final Exam mein 150 questions 45 minutes mein karne hote hain (yaani ~18 seconds per question). Isliye aaj ke 5 MCQs ko poore focus ke saath attempt karein!

---

### 📝 3. Quick Revision Summary
* **Topic:** ${title}
* **Target Class:** Class ${classNum}
* **Daily Weightage:** 5 MCQs (100% Concept Based)
* **Final Exam Impact:** Is chapter se कम से कम 4–5 direct questions Mid/Final Exam mein aayenge.`;

  return {
    id: `class-${classNum}-day-${day}`,
    classNum,
    day,
    title,
    summary: `Class ${classNum} • Day ${day}: Master ${title} in 10 minutes with Hinglish notes & 5 high-yield MCQs.`,
    content: defaultContent,
    keyTakeaways: [
      `${title} ke fundamental definitions aur core rules`,
      'Exam-oriented 15-second elimination trick',
      'Common silly mistakes jinse exam mein bachna hai',
      '5 high-probability MCQs for Mid & Final Exam',
    ],
    mcqs,
  };
}

export const EXAM_QUESTIONS_POOL: MCQQuestion[] = [
  ...TOPIC_MCQS_BANK['Quadratic Equations'],
  ...TOPIC_MCQS_BANK['Globalization'],
  ...TOPIC_MCQS_BANK['Indian Constitution Basics'],
  {
    id: 'ex-16',
    question: 'Newton ka First Law of Motion kis naam se bhi jaana jaata hai?',
    options: ['Law of Momentum', 'Law of Inertia', 'Law of Action-Reaction', 'Law of Gravitation'],
    correctIndex: 1,
    explanation: 'Newton ke First Law ko Law of Inertia kehte hain: koi object tab tak apni state nahi badalta jab tak external force na lage.',
    topic: "Newton's Laws",
  },
  {
    id: 'ex-17',
    question: 'Cell ka "Powerhouse" kise kaha jaata hai?',
    options: ['Nucleus', 'Ribosome', 'Mitochondria', 'Golgi Body'],
    correctIndex: 2,
    explanation: 'Mitochondria ATP (energy currency) banata hai, isliye isse Powerhouse of the Cell kehte hain.',
    topic: 'Cell Biology',
  },
  {
    id: 'ex-18',
    question: 'Electric current ka SI unit kya hai?',
    options: ['Volt', 'Ohm', 'Ampere', 'Watt'],
    correctIndex: 2,
    explanation: 'Electric current (I) ko Ampere (A) mein maapa jaata hai.',
    topic: 'Electricity Basics',
  },
  {
    id: 'ex-19',
    question: 'Arithmetic Progression (AP): 2, 5, 8, 11... ka 10th term kya hoga?',
    options: ['27', '29', '32', '30'],
    correctIndex: 1,
    explanation: 'a = 2, d = 3. a₁₀ = a + 9d = 2 + 9(3) = 29.',
    topic: 'Arithmetic Progression',
  },
  {
    id: 'ex-20',
    question: 'Ek fair coin ko uchhalne par Head aane ki probability kya hoti hai?',
    options: ['1', '1/2', '1/4', '0'],
    correctIndex: 1,
    explanation: 'Total outcomes = 2 (Head, Tail), favourable = 1. Toh probability = 1/2 (0.5).',
    topic: 'Probability',
  },
  {
    id: 'ex-21',
    question: 'Modern Periodic Table mein elements kis basis par arrange kiye gaye hain?',
    options: ['Atomic Mass', 'Atomic Number', 'Density', 'Alphabetical Order'],
    correctIndex: 1,
    explanation: 'Henry Moseley ke according Modern Periodic Table increasing Atomic Number (Z) par based hai.',
    topic: 'Periodic Table',
  },
  {
    id: 'ex-22',
    question: 'sin²θ + cos²θ ki value hamesha kitni hoti hai?',
    options: ['0', '1', '2', 'tan θ'],
    correctIndex: 1,
    explanation: 'Fundamental trigonometric identity ke anusar sin²θ + cos²θ = 1 hota hai.',
    topic: 'Trigonometry',
  },
  {
    id: 'ex-23',
    question: 'Point (3, 4) ki origin (0, 0) se distance kitni hogi?',
    options: ['7 units', '5 units', '12 units', '1 unit'],
    correctIndex: 1,
    explanation: 'Distance = √(3² + 4²) = √(9 + 16) = √25 = 5 units.',
    topic: 'Coordinate Geometry',
  },
  {
    id: 'ex-24',
    question: 'Reserve Bank of India (RBI) ka main kaam kya hai?',
    options: [
      'Sirf schools chalana',
      'Currency issue karna aur monetary policy control karna',
      'Trains chalana',
      'Road tax collect karna',
    ],
    correctIndex: 1,
    explanation: 'RBI India ka central bank hai jo currency notes issue karta hai aur banks/credit ko regulate karta hai.',
    topic: 'Indian Economy',
  },
  {
    id: 'ex-25',
    question: 'Series 3, 6, 12, 24, ? mein agla number kya aayega?',
    options: ['36', '48', '30', '42'],
    correctIndex: 1,
    explanation: 'Har number double (×2) ho raha hai: 3×2=6, 6×2=12, 12×2=24, 24×2=48.',
    topic: 'Logical Reasoning',
  },
];
