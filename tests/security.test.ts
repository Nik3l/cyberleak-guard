import test from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeAndValidateEmail, validateHashPrefix, sanitizePasswordInput } from '../src/utils/validation.ts';
import { evaluatePasswordStrength, sha1 } from '../src/utils/crypto.ts';
import { SimpleTTLCache, SimpleRateLimiter } from '../src/server/rateLimiter.ts';

test('Email validation - valid emails', () => {
  const cases = [
    'test@example.com',
    'b.chazal@sudouest.fr',
    'user+tag@domain.co.uk',
    'first.last123@sub.domain.org'
  ];

  for (const email of cases) {
    const res = sanitizeAndValidateEmail(email);
    assert.equal(res.valid, true, `Expected ${email} to be valid`);
    assert.equal(res.email, email.toLowerCase());
  }
});

test('Email validation - invalid & malicious inputs', () => {
  const invalidCases = [
    '',
    '   ',
    'notanemail',
    '@domain.com',
    'user@',
    'user@domain..com',
    null,
    undefined,
    12345,
    'a'.repeat(250) + '@example.com' // Exceeds 254 chars
  ];

  for (const input of invalidCases) {
    const res = sanitizeAndValidateEmail(input);
    assert.equal(res.valid, false, `Expected ${input} to be invalid`);
    assert.ok(res.error);
  }
});

test('Hash prefix validation - k-anonymity format', () => {
  assert.equal(validateHashPrefix('5BAA6').valid, true);
  assert.equal(validateHashPrefix('5baa6').prefix, '5BAA6');
  assert.equal(validateHashPrefix('00000').valid, true);
  assert.equal(validateHashPrefix('FFFFF').valid, true);

  // Invalid formats
  assert.equal(validateHashPrefix('5BAA').valid, false); // 4 chars
  assert.equal(validateHashPrefix('5BAA61').valid, false); // 6 chars
  assert.equal(validateHashPrefix('5BAAZ').valid, false); // non-hex 'Z'
  assert.equal(validateHashPrefix('').valid, false);
});

test('Password input bounds sanitization', () => {
  assert.equal(sanitizePasswordInput('mypassword123').valid, true);
  assert.equal(sanitizePasswordInput('a'.repeat(513)).valid, false); // >512
});

test('SHA-1 hashing & k-anonymity prefix computation', async () => {
  // 'password' SHA-1 is known to be 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
  const hash = await sha1('password');
  assert.equal(hash, '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8');
  assert.equal(hash.substring(0, 5), '5BAA6');
});

test('Password strength scoring & entropy', () => {
  const weak = evaluatePasswordStrength('123456', 5000000);
  assert.equal(weak.score <= 1, true);

  const strong = evaluatePasswordStrength('K9#zL2$vP8!mQ4@xR7', 0);
  assert.equal(strong.score >= 3, true);
  assert.equal(strong.entropy > 70, true);
});

test('SimpleTTLCache operations and expiration', async () => {
  const cache = new SimpleTTLCache<string>(10);
  cache.set('key1', 'value1', 50); // 50ms TTL

  assert.equal(cache.get('key1'), 'value1');

  // Wait 60ms for expiration
  await new Promise(r => setTimeout(r, 60));
  assert.equal(cache.get('key1'), null);
});

test('SimpleRateLimiter blocking after threshold', () => {
  const limiter = new SimpleRateLimiter(1000, 3);
  const ip = '192.168.1.1';

  assert.equal(limiter.check(ip).allowed, true);
  assert.equal(limiter.check(ip).allowed, true);
  assert.equal(limiter.check(ip).allowed, true);

  // 4th request must be blocked
  const fourth = limiter.check(ip);
  assert.equal(fourth.allowed, false);
  assert.ok(fourth.retryAfterSec && fourth.retryAfterSec > 0);
});

test('Target email validation - b_chazal@hotmail.com is valid and sanitized', () => {
  const res = sanitizeAndValidateEmail('  b_chazal@hotmail.com  ');
  assert.equal(res.valid, true);
  assert.equal(res.email, 'b_chazal@hotmail.com');
});

test('Breach site parsing handles semicolon delimited lists without loss', () => {
  const siteStr = 'Collection-1;Adobe;ExploitIN;Free;1.4BillionRecords';
  const sites = siteStr.split(';').map(s => s.trim()).filter(Boolean);
  assert.equal(sites.length, 5);
  assert.ok(sites.includes('Collection-1'));
  assert.ok(sites.includes('Adobe'));
  assert.ok(sites.includes('Free'));
});

