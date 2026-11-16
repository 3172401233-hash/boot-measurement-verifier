import { generateKeyPairSync, randomBytes, sign as cryptoSign, constants } from 'node:crypto';
import {
  buildQuotePayload,
  computePcrDigest,
  hashEventData,
  replayEvents,
} from '../src/index.js';

export const HASH_ALG = 'sha256';

export function makeBootEvents(hashAlg = HASH_ALG) {
  const records = [
    { pcrIndex: 0, data: 'bios-firmware-1.2.3' },
    { pcrIndex: 0, data: 'grub-config-sha:9f2c' },
    { pcrIndex: 0, data: 'kernel-image-6.8.1-amd64' },
    { pcrIndex: 1, data: 'initrd-6.8.1-amd64' },
    { pcrIndex: 1, data: 'cmdline:root=/dev/sda1 ro quiet' },
  ];
  return records.map((record, seq) => ({
    seq,
    pcrIndex: record.pcrIndex,
    hashAlg,
    digest: hashEventData(record.data, hashAlg).toString('hex'),
    data: record.data,
  }));
}

export function makeAkKeyPair(signatureAlg = 'ed25519') {
  if (signatureAlg === 'ed25519') {
    return generateKeyPairSync('ed25519');
  }
  if (signatureAlg === 'ecdsa-p256-sha256') {
    return generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  }
  if (signatureAlg === 'rsa-pss-sha256') {
    return generateKeyPairSync('rsa', { modulusLength: 2048 });
  }
  throw new Error(`测试未覆盖的签名算法: ${signatureAlg}`);
}

export function signQuote(quote, signatureAlg, privateKey) {
  const payload = Buffer.from(buildQuotePayload(quote), 'utf8');
  if (signatureAlg === 'ed25519') {
    return cryptoSign(null, payload, privateKey);
  }
  if (signatureAlg === 'rsa-pss-sha256') {
    return cryptoSign('sha256', payload, {
      key: privateKey,
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
    });
  }
  return cryptoSign('sha256', payload, privateKey);
}

export function makeFixture(options = {}) {
  const { signatureAlg = 'ed25519', hashAlg = HASH_ALG } = options;
  const { publicKey, privateKey } = makeAkKeyPair(signatureAlg);
  const events = makeBootEvents(hashAlg);
  const { pcrs, errors } = replayEvents(events);
  if (errors.length > 0) throw new Error('夹具事件日志本身无效');

  const nonce = randomBytes(32);
  const quotedPcrs = Object.fromEntries(
    [...pcrs.entries()].map(([key, value]) => [key, value.toString('hex')]),
  );
  const quote = {
    hashAlg,
    nonce: nonce.toString('hex'),
    pcrDigest: computePcrDigest(pcrs, hashAlg).toString('hex'),
    timestamp: 1_800_000_000_000,
    signatureAlg,
  };
  quote.signature = signQuote(quote, signatureAlg, privateKey).toString('hex');

  return {
    events,
    pcrs: quotedPcrs,
    quote,
    nonce,
    akPublicKey: publicKey,
    privateKey,
    nonceExpiresAt: quote.timestamp + 60_000,
    now: quote.timestamp + 1_000,
  };
}

export function verifyFixture(fixture, overrides = {}) {
  return {
    nonce: fixture.nonce,
    nonceExpiresAt: fixture.nonceExpiresAt,
    events: fixture.events,
    pcrs: fixture.pcrs,
    quote: fixture.quote,
    akPublicKey: fixture.akPublicKey,
    now: fixture.now,
    ...overrides,
  };
}
