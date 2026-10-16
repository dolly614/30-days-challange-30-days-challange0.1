import { NextRequest, NextResponse } from 'next/server';

const SESSION_COOKIE_NAME = 'uyanix_session';

const EDGE_CSP_HEADER = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' https://apis.google.com https://accounts.google.com https://checkout.razorpay.com",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "img-src 'self' data: blob: https://picsum.photos https://lh3.googleusercontent.com",
  "font-src 'self' data: https://fonts.gstatic.com",
  "connect-src 'self' https://*.googleapis.com https://*.firebaseio.com https://identitytoolkit.googleapis.com https://securetoken.googleapis.com https://*.supabase.co https://api.razorpay.com",
  "media-src 'self'",
  "object-src 'none'",
  "frame-src 'self' https://accounts.google.com https://api.razorpay.com",
  "frame-ancestors 'self' https://*.google.com https://*.run.app",
  "base-uri 'self'",
  "form-action 'self'",
  "worker-src 'self' blob:",
  "manifest-src 'self'",
  "report-uri /api/health?cspReport=true",
].join('; ');

function validateSafeInternalRedirect(
  rawRedirect: string | null | undefined,
  fallbackPath = '/dashboard'
): { safeRedirectPath: string } {
  if (!rawRedirect || typeof rawRedirect !== 'string') {
    return { safeRedirectPath: fallbackPath };
  }
  const trimmed = rawRedirect.trim();
  if (
    !trimmed.startsWith('/') ||
    trimmed.startsWith('//') ||
    trimmed.startsWith('/\\') ||
    /[\x00-\x1f\x7f]/.test(trimmed) ||
    /^[a-zA-Z][a-zA-Z0-9+.-]*:/i.test(trimmed) ||
    trimmed.includes('://')
  ) {
    return { safeRedirectPath: fallbackPath };
  }
  return { safeRedirectPath: trimmed };
}

function buildAuthoritativeSecurityHeaders(params: {
  environment: 'PRODUCTION' | 'DEVELOPMENT';
  isHttps: boolean;
  isSensitiveApiOrAuthPage: boolean;
}): Record<string, string> {
  const headers: Record<string, string> = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy':
      'camera=(), microphone=(), geolocation=(), payment=(self), usb=(), magnetometer=(), gyroscope=(), accelerometer=()',
    'X-DNS-Prefetch-Control': 'off',
    'X-Download-Options': 'noopen',
    'X-Permitted-Cross-Domain-Policies': 'none',
    'Content-Security-Policy': EDGE_CSP_HEADER,
  };
  if (params.environment === 'PRODUCTION' && params.isHttps) {
    headers['Strict-Transport-Security'] = 'max-age=31536000';
  }
  if (params.isSensitiveApiOrAuthPage) {
    headers['Cache-Control'] =
      'private, no-store, no-cache, must-revalidate, max-age=0';
    headers['Pragma'] = 'no-cache';
    headers['X-Robots-Tag'] = 'noindex, nofollow, noarchive';
  }
  return headers;
}

interface EdgeSessionPayload {
  jti: string;
  sub: string;
  role: 'student' | 'teacher' | 'admin';
  registrationId?: string;
  email: string;
  exp: number;
}

const TRUSTED_ADMIN_EMAILS = new Set([
  'dollysingh1268@gmail.com',
  'admin@uyanix.in',
  ...(process.env.ADMIN_BOOTSTRAP_EMAIL
    ? [process.env.ADMIN_BOOTSTRAP_EMAIL.trim().toLowerCase()]
    : []),
]);

function isTrustedAdminEmail(email?: string | null): boolean {
  if (!email) return false;
  return TRUSTED_ADMIN_EMAILS.has(email.trim().toLowerCase());
}

function getSigningSecret(): string {
  const secret = process.env.AUTH_SESSION_SECRET;
  if (!secret || secret.length < 32) {
    return 'uyanix-authoritative-session-secret-key-must-be-min-32bytes-for-safety';
  }
  return secret;
}

function arrayBufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function base64UrlToUtf8(input: string): string {
  const normalized = input.replace(/-/g, '+').replace(/_/g, '/');
  const pad = normalized.length % 4;
  const padded = pad ? normalized + '='.repeat(4 - pad) : normalized;
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new TextDecoder().decode(bytes);
}

function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

async function verifyEdgeSessionToken(
  token: string | undefined
): Promise<EdgeSessionPayload | null> {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payloadB64, signatureB64] = parts;
  if (!payloadB64 || !signatureB64) return null;

  try {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(getSigningSecret()),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const sigBuffer = await crypto.subtle.sign(
      'HMAC',
      key,
      encoder.encode(payloadB64)
    );
    const expectedSigB64 = arrayBufferToBase64Url(sigBuffer);

    if (!constantTimeEqual(signatureB64, expectedSigB64)) {
      return null;
    }

    const decoded = JSON.parse(base64UrlToUtf8(payloadB64)) as EdgeSessionPayload;
    if (
      !decoded ||
      typeof decoded.sub !== 'string' ||
      typeof decoded.exp !== 'number' ||
      Date.now() >= decoded.exp
    ) {
      return null;
    }

    return decoded;
  } catch {
    return null;
  }
}

const PROTECTED_PREFIXES = [
  '/dashboard',
  '/profile',
  '/exam',
  '/daily',
  '/certificate',
  '/teacher',
  '/admin',
  '/sheets',
];

function attachSecurityHeaders(
  res: NextResponse,
  req: NextRequest,
  isProtected: boolean
): NextResponse {
  const isHttps =
    req.nextUrl.protocol === 'https:' ||
    req.headers.get('x-forwarded-proto') === 'https';
  const secHeaders = buildAuthoritativeSecurityHeaders({
    environment:
      process.env.NODE_ENV === 'production' ? 'PRODUCTION' : 'DEVELOPMENT',
    isHttps,
    isSensitiveApiOrAuthPage: isProtected,
  });

  for (const [key, value] of Object.entries(secHeaders)) {
    res.headers.set(key, value);
  }
  return res;
}

export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;

  const isProtected = PROTECTED_PREFIXES.some(
    (prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`)
  );

  if (!isProtected) {
    return attachSecurityHeaders(NextResponse.next(), req, false);
  }

  const token =
    req.cookies.get(SESSION_COOKIE_NAME)?.value ||
    req.headers.get('x-uyanix-session') ||
    (req.headers.get('authorization')?.startsWith('Bearer ')
      ? req.headers.get('authorization')?.slice(7).trim()
      : undefined);
  const session = await verifyEdgeSessionToken(token);

  if (!session) {
    const loginUrl = new URL('/login', req.url);
    const { safeRedirectPath } = validateSafeInternalRedirect(
      pathname,
      '/dashboard'
    );
    loginUrl.searchParams.set('redirect', safeRedirectPath);
    return attachSecurityHeaders(NextResponse.redirect(loginUrl), req, true);
  }

  // Student progression to dashboard requires mandatory Registration ID
  if (
    (pathname === '/dashboard' || pathname.startsWith('/dashboard/')) &&
    session.role === 'student' &&
    !session.registrationId
  ) {
    const regRedirectUrl = new URL('/register', req.url);
    regRedirectUrl.searchParams.set('step', '1');
    regRedirectUrl.searchParams.set('error', 'registration_id_required');
    return attachSecurityHeaders(NextResponse.redirect(regRedirectUrl), req, true);
  }

  // Admin-only routes
  if (
    (pathname === '/admin' || pathname.startsWith('/admin/')) &&
    (session.role !== 'admin' || !isTrustedAdminEmail(session.email))
  ) {
    const forbiddenUrl = new URL('/dashboard', req.url);
    forbiddenUrl.searchParams.set('error', 'admin_only');
    return attachSecurityHeaders(NextResponse.redirect(forbiddenUrl), req, true);
  }

  // Teacher / Admin routes
  if (
    (pathname === '/teacher' || pathname.startsWith('/teacher/')) &&
    session.role !== 'teacher' &&
    session.role !== 'admin'
  ) {
    const forbiddenUrl = new URL('/dashboard', req.url);
    forbiddenUrl.searchParams.set('error', 'teacher_only');
    return attachSecurityHeaders(NextResponse.redirect(forbiddenUrl), req, true);
  }

  // Google Sheets hub requires Admin or Teacher role
  if (
    (pathname === '/sheets' || pathname.startsWith('/sheets/')) &&
    session.role !== 'admin' &&
    session.role !== 'teacher'
  ) {
    const forbiddenUrl = new URL('/dashboard', req.url);
    forbiddenUrl.searchParams.set('error', 'forbidden');
    return attachSecurityHeaders(NextResponse.redirect(forbiddenUrl), req, true);
  }

  return attachSecurityHeaders(NextResponse.next(), req, true);
}

export const config = {
  matcher: [
    '/dashboard/:path*',
    '/profile/:path*',
    '/exam/:path*',
    '/daily/:path*',
    '/certificate/:path*',
    '/teacher/:path*',
    '/admin/:path*',
    '/sheets/:path*',
  ],
};
