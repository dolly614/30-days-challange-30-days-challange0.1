// scripts/audit-authorization.mjs
// Automated positive & negative API authorization audit test runner

const BASE_URL = 'http://localhost:3000';

async function postJson(endpoint, body, headers = {}) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), 10000);
  try {
    const res = await fetch(`${BASE_URL}${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...headers },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch {}
    return { status: res.status, json, text };
  } finally {
    clearTimeout(id);
  }
}

async function get(endpoint, headers = {}) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), 10000);
  try {
    const res = await fetch(`${BASE_URL}${endpoint}`, {
      method: 'GET',
      headers,
      signal: controller.signal,
    });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch {}
    return { status: res.status, json, text };
  } finally {
    clearTimeout(id);
  }
}

async function patchJson(endpoint, body, headers = {}) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), 10000);
  try {
    const res = await fetch(`${BASE_URL}${endpoint}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', ...headers },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch {}
    return { status: res.status, json, text };
  } finally {
    clearTimeout(id);
  }
}

async function main() {
  console.log('================================================================');
  console.log('   UYANIX 30 DAYS — COMPREHENSIVE API AUTHORIZATION AUDIT TEST   ');
  console.log('================================================================\n');

  // 1. Obtain test tokens for isolated roles
  const adminRes = await postJson('/api/auth/demo', { role: 'admin' });
  const teacherRes = await postJson('/api/auth/demo', { role: 'teacher' });
  const studentRes = await postJson('/api/auth/demo', { role: 'student' });

  const adminToken = adminRes.json?.token;
  const teacherToken = teacherRes.json?.token;
  const studentToken = studentRes.json?.token;

  if (!adminToken || !teacherToken || !studentToken) {
    console.error('FAILED to obtain demo test credentials');
    process.exit(1);
  }

  const hAdmin = { 'x-uyanix-session': adminToken };
  const hTeacher = { 'x-uyanix-session': teacherToken };
  const hStudent = { 'x-uyanix-session': studentToken };
  const hAnon = {};

  const testResults = [];

  function record(category, testName, passed, details) {
    testResults.push({ category, testName, passed, details });
    const mark = passed ? '✅ PASS' : '❌ FAIL';
    console.log(`${mark} | [${category}] ${testName} -> ${details}`);
  }

  // -------------------------------------------------------------
  // Test Suite 1: Admin-Only Endpoints
  // -------------------------------------------------------------
  console.log('\n--- 1. ADMIN-ONLY ENDPOINTS RBAC ---');
  {
    // GET /api/admin/metrics
    const r1 = await get('/api/admin/metrics', hAnon);
    record('ADMIN_METRICS', 'Unauthenticated rejected (401)', r1.status === 401, `Status: ${r1.status}`);

    const r2 = await get('/api/admin/metrics', hStudent);
    record('ADMIN_METRICS', 'Student rejected (403)', r2.status === 403, `Status: ${r2.status}`);

    const r3 = await get('/api/admin/metrics', hTeacher);
    record('ADMIN_METRICS', 'Teacher rejected (403)', r3.status === 403, `Status: ${r3.status}`);

    const r4 = await get('/api/admin/metrics', hAdmin);
    record('ADMIN_METRICS', 'Admin authorized (200)', r4.status === 200, `Status: ${r4.status}`);
  }

  {
    // POST /api/admin/action
    const r1 = await postJson('/api/admin/action', { action: 'EXPORT_ADMIN_DATA' }, hAnon);
    record('ADMIN_ACTION', 'Unauthenticated rejected (401)', r1.status === 401, `Status: ${r1.status}`);

    const r2 = await postJson('/api/admin/action', { action: 'EXPORT_ADMIN_DATA' }, hStudent);
    record('ADMIN_ACTION', 'Student rejected (403)', r2.status === 403, `Status: ${r2.status}`);

    const r3 = await postJson('/api/admin/action', { action: 'EXPORT_ADMIN_DATA' }, hTeacher);
    record('ADMIN_ACTION', 'Teacher rejected (403)', r3.status === 403, `Status: ${r3.status}`);

    const r4 = await postJson('/api/admin/action', { action: 'EXPORT_ADMIN_DATA', exportType: 'LEADERBOARD' }, hAdmin);
    record('ADMIN_ACTION', 'Admin authorized (200)', r4.status === 200, `Status: ${r4.status}`);
  }

  {
    // GET /api/admin/incidents
    const r1 = await get('/api/admin/incidents?phaseReport=true', hStudent);
    record('ADMIN_INCIDENTS', 'Student rejected (403)', r1.status === 403, `Status: ${r1.status}`);

    const r2 = await get('/api/admin/incidents?phaseReport=true', hAdmin);
    record('ADMIN_INCIDENTS', 'Admin authorized (200)', r2.status === 200, `Status: ${r2.status}`);
  }

  {
    // POST /api/admin/chapters (SAVE_CHAPTER)
    const r1 = await postJson('/api/admin/chapters', { action: 'SAVE_CHAPTER', classNum: 10, day: 1, title: 'Test', content: 'Test' }, hStudent);
    record('ADMIN_CHAPTERS', 'Student chapter modification rejected (403)', r1.status === 403, `Status: ${r1.status}`);

    const r2 = await postJson('/api/admin/chapters', { action: 'SAVE_CHAPTER', classNum: 10, day: 1, title: 'Security Test Chapter', content: 'Content' }, hAdmin);
    record('ADMIN_CHAPTERS', 'Admin chapter modification authorized (200)', r2.status === 200, `Status: ${r2.status}`);
  }

  // -------------------------------------------------------------
  // Test Suite 2: Teacher Portal RBAC & IDOR Prevention
  // -------------------------------------------------------------
  console.log('\n--- 2. TEACHER PORTAL RBAC & IDOR PREVENTION ---');
  {
    const r1 = await get('/api/teacher/action', hAnon);
    record('TEACHER_GET', 'Unauthenticated rejected (401)', r1.status === 401, `Status: ${r1.status}`);

    const r2 = await get('/api/teacher/action', hStudent);
    record('TEACHER_GET', 'Student rejected (403)', r2.status === 403, `Status: ${r2.status}`);

    const r3 = await get('/api/teacher/action', hTeacher);
    record('TEACHER_GET', 'Teacher authorized (200)', r3.status === 200, `Status: ${r3.status}`);

    // IDOR check: Teacher attempting action on another teacher's user ID
    const r4 = await postJson('/api/teacher/action', {
      action: 'SUBMIT_KYC',
      teacherUserId: 'usr_teacher_victim_999',
      pan: 'ABCDE1234F',
      upiId: 'test@upi',
    }, hTeacher);
    record('TEACHER_IDOR', 'Cross-teacher account action rejected (403)', r4.status === 403, `Status: ${r4.status}`);

    // Positive check: Teacher acting on self
    const r5 = await postJson('/api/teacher/action', {
      action: 'SUBMIT_KYC',
      teacherUserId: 'usr_teacher_dolly',
      pan: 'ABCDE1234F',
      upiId: 'test@upi',
    }, hTeacher);
    record('TEACHER_OWN_ACTION', 'Teacher acting on own account authorized (200)', r5.status === 200, `Status: ${r5.status}`);
  }

  // -------------------------------------------------------------
  // Test Suite 3: User Profile & Privilege Escalation Guards
  // -------------------------------------------------------------
  console.log('\n--- 3. USER PROFILE & PRIVILEGE ESCALATION ---');
  {
    const r1 = await get('/api/user/profile', hAnon);
    record('PROFILE_GET', 'Unauthenticated rejected (401)', r1.status === 401, `Status: ${r1.status}`);

    // IDOR check: Student attempting to query another student's profile via ?userId=
    const r2 = await get('/api/user/profile?userId=usr_other_student_123', hStudent);
    record('PROFILE_IDOR_READ', 'Student cross-user profile access rejected (403)', r2.status === 403, `Status: ${r2.status}`);

    // Positive check: Student querying own profile
    const r3 = await get('/api/user/profile', hStudent);
    record('PROFILE_OWN_READ', 'Student accessing own profile authorized (200)', r3.status === 200, `Status: ${r3.status}`);

    // Privilege escalation check: Student attempting to inject role=admin or isAdmin=true
    const r4 = await patchJson('/api/user/profile', { role: 'admin' }, hStudent);
    record('PRIVILEGE_ESCALATION', 'Role injection in PATCH rejected (403)', r4.status === 403, `Status: ${r4.status}`);

    const r5 = await patchJson('/api/user/profile', { isAdmin: true }, hStudent);
    record('PRIVILEGE_ESCALATION', 'isAdmin injection in PATCH rejected (403)', r5.status === 403, `Status: ${r5.status}`);

    // IDOR check: Student attempting to modify another student's profile
    const r6 = await patchJson('/api/user/profile', { userId: 'usr_other_victim_456', name: 'Hacked Name' }, hStudent);
    record('PROFILE_IDOR_WRITE', 'Student modifying other student profile rejected (403)', r6.status === 403, `Status: ${r6.status}`);

    // Positive check: Student modifying own allowed field (name)
    const r7 = await patchJson('/api/user/profile', { name: 'Dolly Singh Updated' }, hStudent);
    record('PROFILE_OWN_WRITE', 'Student updating own name authorized (200)', r7.status === 200, `Status: ${r7.status}`);
  }

  // -------------------------------------------------------------
  // Test Suite 4: Student Progress & Daily Quiz Authorization
  // -------------------------------------------------------------
  console.log('\n--- 4. STUDENT PROGRESS & DAILY CHALLENGE ---');
  {
    const r1 = await get('/api/student/progress', hAnon);
    record('PROGRESS_GET', 'Unauthenticated rejected (401)', r1.status === 401, `Status: ${r1.status}`);

    const r2 = await get('/api/student/progress', hStudent);
    record('PROGRESS_GET', 'Student authorized for own progress (200)', r2.status === 200, `Status: ${r2.status}`);

    const r3 = await get('/api/daily/1', hAnon);
    record('DAILY_READ', 'Unauthenticated daily chapter rejected (401)', r3.status === 401, `Status: ${r3.status}`);

    const r4 = await get('/api/daily/1', hStudent);
    record('DAILY_READ', 'Student reading daily chapter authorized (200)', r4.status === 200, `Status: ${r4.status}`);

    // Daily submit invalid input validation
    const r5 = await postJson('/api/daily/1/submit', { answers: [0, 1] }, hStudent);
    record('DAILY_VALIDATION', 'Incomplete answers rejected (422)', r5.status === 422, `Status: ${r5.status}`);

    // Daily submit valid
    const r6 = await postJson('/api/daily/1/submit', { answers: [0, 1, 2, 3, 0] }, hStudent);
    record('DAILY_SUBMIT', 'Valid 5-answer daily quiz authorized (200)', r6.status === 200, `Status: ${r6.status}`);
  }

  // -------------------------------------------------------------
  // Test Suite 5: Exam Engine & Administrative Corrections
  // -------------------------------------------------------------
  console.log('\n--- 5. EXAM ENGINE & RESULT CORRECTIONS ---');
  {
    const r1 = await get('/api/exam?type=mid', hAnon);
    record('EXAM_GET', 'Unauthenticated exam access rejected (401)', r1.status === 401, `Status: ${r1.status}`);

    const r2 = await get('/api/exam?type=mid', hStudent);
    record('EXAM_GET', 'Student exam metadata access authorized (200)', r2.status === 200, `Status: ${r2.status}`);

    // Student attempting admin result correction
    const r3 = await postJson('/api/exam', {
      action: 'ADMIN_CORRECT_RESULT',
      attemptId: 'ATT-123',
      correctedScore: 100,
      reason: 'Bypassing exam',
    }, hStudent);
    record('EXAM_ADMIN_CORRECT', 'Student attempting ADMIN_CORRECT_RESULT rejected (403)', r3.status === 403, `Status: ${r3.status}`);
  }

  // -------------------------------------------------------------
  // Test Suite 6: Financial & Payment Operations
  // -------------------------------------------------------------
  console.log('\n--- 6. FINANCIAL & PAYMENT OPERATIONS ---');
  {
    // Payment create order
    const r1 = await postJson('/api/payment', { action: 'CREATE_ORDER', examType: 'mid' }, hAnon);
    record('PAYMENT_ORDER', 'Unauthenticated order creation rejected (401)', r1.status === 401, `Status: ${r1.status}`);

    const r2 = await postJson('/api/payment', { action: 'CREATE_ORDER', examType: 'mid' }, hStudent);
    record('PAYMENT_ORDER', 'Student order creation authorized (200)', r2.status === 200, `Status: ${r2.status}`);

    // Student attempting financial refund
    const r3 = await postJson('/api/payment', { action: 'REFUND', paymentId: 'pay_test_123' }, hStudent);
    record('PAYMENT_REFUND', 'Student attempting refund rejected (403)', r3.status === 403, `Status: ${r3.status}`);

    // Student attempting financial reconciliation
    const r4 = await postJson('/api/payment', { action: 'RECONCILE', orderId: 'ord_test_123' }, hStudent);
    record('PAYMENT_RECONCILE', 'Student attempting reconciliation rejected (403)', r4.status === 403, `Status: ${r4.status}`);

    // Student attempting client-side status tampering claims
    const r5 = await postJson('/api/payment', { paymentSuccessful: true, examUnlocked: true }, hStudent);
    record('PAYMENT_TAMPER', 'Client-side paymentSuccessful claim rejected (403/400)', r5.status === 403 || r5.status === 400, `Status: ${r5.status}`);
  }

  // -------------------------------------------------------------
  // Test Suite 7: Certificate Governance
  // -------------------------------------------------------------
  console.log('\n--- 7. CERTIFICATE GOVERNANCE ---');
  {
    const r1 = await get('/api/certificate', hAnon);
    record('CERTIFICATE_GET', 'Unauthenticated private certificate access rejected (401)', r1.status === 401, `Status: ${r1.status}`);

    const r2 = await get('/api/certificate', hStudent);
    record('CERTIFICATE_GET', 'Student access to own certificate authorized (200)', r2.status === 200, `Status: ${r2.status}`);

    // Student attempting certificate revocation
    const r3 = await postJson('/api/certificate', { action: 'REVOKE', publicCertificateId: 'CERT-123' }, hStudent);
    record('CERTIFICATE_REVOKE', 'Student certificate revocation rejected (403)', r3.status === 403, `Status: ${r3.status}`);
  }

  // -------------------------------------------------------------
  // Test Suite 8: Google Workspace & Sheets API
  // -------------------------------------------------------------
  console.log('\n--- 8. GOOGLE WORKSPACE & SHEETS API ---');
  {
    const r1 = await get('/api/sheets', hAnon);
    record('SHEETS_GET', 'Unauthenticated rejected (401)', r1.status === 401, `Status: ${r1.status}`);

    const r2 = await get('/api/sheets', hStudent);
    record('SHEETS_GET', 'Student rejected (403)', r2.status === 403, `Status: ${r2.status}`);
  }

  console.log('\n================================================================');
  const passedCount = testResults.filter(t => t.passed).length;
  const totalCount = testResults.length;
  console.log(`TOTAL TESTS: ${totalCount} | PASSED: ${passedCount} | FAILED: ${totalCount - passedCount}`);
  console.log('================================================================\n');

  if (passedCount !== totalCount) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('Test runner encountered error:', err);
  process.exit(1);
});
