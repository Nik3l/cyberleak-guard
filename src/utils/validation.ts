/**
 * Security and validation utilities for CyberLeak Guard
 */

const EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

export function sanitizeAndValidateEmail(email: unknown): { valid: boolean; email?: string; error?: string } {
  if (!email || typeof email !== 'string') {
    return { valid: false, error: 'Une adresse e-mail est requise.' };
  }

  const trimmed = email.trim().toLowerCase();

  if (trimmed.length === 0) {
    return { valid: false, error: 'L\'adresse e-mail ne peut pas être vide.' };
  }

  if (trimmed.length > 254) {
    return { valid: false, error: 'L\'adresse e-mail dépasse la longueur maximale autorisée (254 caractères).' };
  }

  if (!EMAIL_REGEX.test(trimmed)) {
    return { valid: false, error: 'Format d\'adresse e-mail invalide (ex: nom@domaine.fr).' };
  }

  return { valid: true, email: trimmed };
}

export function validateHashPrefix(prefix: unknown): { valid: boolean; prefix?: string; error?: string } {
  if (!prefix || typeof prefix !== 'string') {
    return { valid: false, error: 'Le préfixe est requis.' };
  }

  const cleanPrefix = prefix.trim().toUpperCase();

  if (!/^[0-9A-F]{5}$/.test(cleanPrefix)) {
    return { valid: false, error: 'Le préfixe k-anonymat doit comporter exactement 5 caractères hexadécimaux.' };
  }

  return { valid: true, prefix: cleanPrefix };
}

export function sanitizePasswordInput(password: unknown): { valid: boolean; password?: string; error?: string } {
  if (password === undefined || password === null || typeof password !== 'string') {
    return { valid: false, error: 'Un mot de passe est requis.' };
  }

  if (password.length > 512) {
    return { valid: false, error: 'La longueur du mot de passe dépasse la limite autorisée (512 caractères).' };
  }

  return { valid: true, password };
}
