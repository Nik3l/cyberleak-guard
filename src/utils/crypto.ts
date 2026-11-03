// Local in-memory prefix cache to optimize repeated k-anonymity client queries
const localPrefixCache = new Map<string, string>();

// SHA-1 hashing in browser or Node via subtle crypto
export async function sha1(str: string): Promise<string> {
  const buffer = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest('SHA-1', buffer);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

export interface PasswordCheckResult {
  pwned: boolean;
  count: number;
  hashPrefix: string;
  hashSuffix: string;
  source: 'hibp-api' | 'local-heuristic' | 'error';
  strengthScore: number; // 0 to 4
  entropy: number;
  feedback: string[];
}

export async function checkPasswordPwned(password: string): Promise<PasswordCheckResult> {
  if (!password) {
    return {
      pwned: false,
      count: 0,
      hashPrefix: '',
      hashSuffix: '',
      source: 'local-heuristic',
      strengthScore: 0,
      entropy: 0,
      feedback: ['Veuillez saisir un mot de passe à analyser.']
    };
  }

  const hash = await sha1(password);
  const prefix = hash.substring(0, 5);
  const suffix = hash.substring(5);

  let pwnedCount = 0;
  let source: 'hibp-api' | 'local-heuristic' | 'error' = 'hibp-api';

  try {
    let textResponse = localPrefixCache.get(prefix) || '';

    if (!textResponse) {
      // 1. Try local server proxy first
      try {
        const proxyRes = await fetch(`/api/check/pwned-range/${prefix}`);
        if (proxyRes.ok) {
          const json = await proxyRes.json();
          textResponse = json.data || '';
        }
      } catch (proxyErr) {
        console.warn('Proxy fetch error, attempting direct HIBP query:', proxyErr);
      }

      // 2. Direct fallback to HIBP API if proxy did not return valid text
      if (!textResponse) {
        try {
          const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
            headers: { 'Add-Padding': 'true' }
          });
          if (res.ok) {
            textResponse = await res.text();
          }
        } catch (directErr) {
          console.warn('Direct HIBP fetch failed or offline:', directErr);
        }
      }

      if (textResponse) {
        localPrefixCache.set(prefix, textResponse);
      }
    }

    if (textResponse) {
      // Fast parsing
      const lines = textResponse.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const colonIdx = line.indexOf(':');
        if (colonIdx !== -1) {
          const hashPart = line.substring(0, colonIdx).trim();
          if (hashPart === suffix) {
            pwnedCount = parseInt(line.substring(colonIdx + 1).trim(), 10) || 0;
            break;
          }
        }
      }
    } else {
      // Offline / API down heuristic
      source = 'local-heuristic';
      const commonPatterns: Record<string, number> = {
        '123456': 210461208,
        'password': 52372427,
        '123456789': 75214532,
        'azerty': 3355889,
        'qwerty': 15892110,
        'admin': 12389045,
        '12345678': 35890124,
        'welcome': 8452109,
        'password123': 2266543,
        'azerty123': 954120,
        'motdepasse': 1450230,
        'soleil': 854012,
        'marseille': 621450,
        'chouchou': 489201,
        'iloveyou': 6891230,
        '000000': 4512980,
        '111111': 6789012,
        'secret': 3452100,
        'master': 2189040,
        'superman': 1560230
      };

      const normalized = password.toLowerCase().trim();
      if (commonPatterns[normalized]) {
        pwnedCount = commonPatterns[normalized];
      }
    }
  } catch (err) {
    console.warn('Failed to query k-anonymity API, falling back to heuristic:', err);
    source = 'local-heuristic';
    const commonPatterns: Record<string, number> = {
      '123456': 210461208,
      'password': 52372427,
      '123456789': 75214532,
      'azerty': 3355889,
      'qwerty': 15892110,
      'admin': 12389045,
      '12345678': 35890124,
      'welcome': 8452109,
      'password123': 2266543,
      'azerty123': 954120,
      'motdepasse': 1450230,
      'soleil': 854012,
      'marseille': 621450,
      'chouchou': 489201,
      'iloveyou': 6891230,
      '000000': 4512980,
      '111111': 6789012
    };
    const normalized = password.toLowerCase().trim();
    if (commonPatterns[normalized]) {
      pwnedCount = commonPatterns[normalized];
    }
  }

  // Calculate password strength and entropy
  const { score, entropy, feedback } = evaluatePasswordStrength(password, pwnedCount);

  return {
    pwned: pwnedCount > 0,
    count: pwnedCount,
    hashPrefix: prefix,
    hashSuffix: suffix,
    source,
    strengthScore: score,
    entropy,
    feedback
  };
}

export function evaluatePasswordStrength(password: string, pwnedCount: number) {
  let poolSize = 0;
  if (/[a-z]/.test(password)) poolSize += 26;
  if (/[A-Z]/.test(password)) poolSize += 26;
  if (/[0-9]/.test(password)) poolSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) poolSize += 33;

  const entropy = poolSize > 0 ? Math.round(password.length * Math.log2(poolSize)) : 0;
  const feedback: string[] = [];

  let score = 0;
  if (password.length >= 8) score++;
  if (password.length >= 14) score++;
  if (/[A-Z]/.test(password) && /[a-z]/.test(password)) score++;
  if (/[0-9]/.test(password) && /[^a-zA-Z0-9]/.test(password)) score++;

  if (pwnedCount > 0) {
    score = Math.min(score, 1);
    feedback.push(`Ce mot de passe apparaît déjà ${pwnedCount.toLocaleString()} fois dans des fuites de données publiques.`);
  }

  if (password.length < 8) {
    feedback.push('Longueur trop courte : visez au moins 14 à 16 caractères.');
  } else if (password.length >= 14) {
    feedback.push('Excellente longueur (>14 caractères).');
  }

  if (!/[^a-zA-Z0-9]/.test(password)) {
    feedback.push('Ajoutez des caractères spéciaux (!, @, #, $, etc.) pour maximiser la résistance aux attaques brute-force.');
  }

  if (/^[a-zA-Z]+$/.test(password)) {
    feedback.push('Ce mot de passe ne contient que des lettres.');
  }

  return { score: Math.min(4, Math.max(0, score)), entropy, feedback };
}

export function generateSecurePassword(length = 18, useSpecial = true, useNumbers = true, useUpper = true): string {
  let charset = 'abcdefghijklmnopqrstuvwxyz';
  if (useUpper) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (useNumbers) charset += '0123456789';
  if (useSpecial) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';

  const array = new Uint32Array(length);
  crypto.getRandomValues(array);

  let result = '';
  for (let i = 0; i < length; i++) {
    result += charset[array[i] % charset.length];
  }
  return result;
}
