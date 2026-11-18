import { createHash } from 'node:crypto';

/** Private server configuration, never a client-supplied registration field. */
export const GOOGLE_EMAIL_EXCEPTION_ENV = 'VENDOS_GOOGLE_EMAIL_SHA256_ALLOWLIST';

interface GoogleIdentity {
  provider?: unknown;
  email?: unknown;
  emailVerified?: unknown;
  googleId?: unknown;
}

function normalizeEmail(email: unknown): string | null {
  if (typeof email !== 'string') {
    return null;
  }
  const normalized = email.trim().toLowerCase();
  if (
    normalized.length > 254 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/u.test(normalized) ||
    /[\u0000-\u001f\u007f]/u.test(email)
  ) {
    return null;
  }
  return normalized;
}

function validGoogleId(id: unknown): id is string {
  return (
    typeof id === 'string' &&
    id.length > 0 &&
    id.length <= 255 &&
    !/\s|[\u0000-\u001f\u007f]/u.test(id)
  );
}

/**
 * Adds one identity exception to the caller's existing domain policy. It does
 * not replace that policy, grant a role, enable registration, or link accounts.
 * The boolean verification claim must come from the Google OAuth profile, or
 * from the corresponding persisted Google user at the OAuth callback boundary.
 */
export function isVerifiedGoogleEmailException(
  identity: GoogleIdentity,
  configuredHashes: string | undefined = process.env[GOOGLE_EMAIL_EXCEPTION_ENV],
): boolean {
  if (
    identity.provider !== 'google' ||
    identity.emailVerified !== true ||
    !validGoogleId(identity.googleId) ||
    typeof configuredHashes !== 'string' ||
    !configuredHashes.trim() ||
    configuredHashes.length > 10000
  ) {
    return false;
  }
  const hashes = configuredHashes.split(',').map((value) => value.trim().toLowerCase());
  if (hashes.some((value) => !/^[a-f0-9]{64}$/.test(value))) {
    return false;
  }
  const email = normalizeEmail(identity.email);
  if (email === null) {
    return false;
  }
  const hash = createHash('sha256').update(email, 'utf8').digest('hex');
  return hashes.includes(hash);
}

/** Exact binding prevents the existing email fallback from linking an exception to another subject. */
export function isSameGoogleExceptionIdentity(
  stored: GoogleIdentity,
  verified: GoogleIdentity,
): boolean {
  const email = normalizeEmail(verified.email);
  return (
    stored.provider === 'google' &&
    verified.provider === 'google' &&
    stored.emailVerified === true &&
    verified.emailVerified === true &&
    validGoogleId(stored.googleId) &&
    stored.googleId === verified.googleId &&
    email !== null &&
    normalizeEmail(stored.email) === email
  );
}
