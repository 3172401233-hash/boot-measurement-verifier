import {
  createHash,
  createPublicKey,
  timingSafeEqual,
  verify as cryptoVerify,
  constants as cryptoConstants,
} from 'node:crypto';

export const ErrorCode = Object.freeze({
  DIGEST_MISMATCH: 'DIGEST_MISMATCH',
  EVENT_GAP: 'EVENT_GAP',
  POLICY_MISMATCH: 'POLICY_MISMATCH',
  SIGNATURE_INVALID: 'SIGNATURE_INVALID',
  NONCE_MISMATCH: 'NONCE_MISMATCH',
  NONCE_EXPIRED: 'NONCE_EXPIRED',
  UNSUPPORTED_ALGORITHM: 'UNSUPPORTED_ALGORITHM',
  MALFORMED_EVENT: 'MALFORMED_EVENT',
});

export const SUPPORTED_HASH_ALGORITHMS = Object.freeze(['sha1', 'sha256', 'sha384', 'sha512']);

export const SUPPORTED_SIGNATURE_ALGORITHMS = Object.freeze([
  'ed25519',
  'ecdsa-p256-sha256',
  'ecdsa-p384-sha384',
  'rsa-pss-sha256',
  'rsa-pkcs1-sha256',
]);

const SIGNATURE_ALGORITHM_SPECS = Object.freeze({
  ed25519: { keyTypes: ['ed25519'], hash: null },
  'ecdsa-p256-sha256': { keyTypes: ['ec'], namedCurve: 'prime256v1', hash: 'sha256' },
  'ecdsa-p384-sha384': { keyTypes: ['ec'], namedCurve: 'secp384r1', hash: 'sha384' },
  'rsa-pss-sha256': {
    keyTypes: ['rsa', 'rsa-pss'],
    hash: 'sha256',
    padding: cryptoConstants.RSA_PKCS1_PSS_PADDING,
    saltLength: cryptoConstants.RSA_PSS_SALTLEN_DIGEST,
  },
  'rsa-pkcs1-sha256': {
    keyTypes: ['rsa'],
    hash: 'sha256',
    padding: cryptoConstants.RSA_PKCS1_PADDING,
  },
});

function makeError(code, message, details = {}) {
  return { code, message, ...details };
}

function hashLength(hashAlg) {
  return createHash(hashAlg).digest().length;
}

function toBuffer(value, encoding = 'hex') {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (typeof value === 'string') return Buffer.from(value, encoding);
  throw new TypeError(`无法转换为 Buffer: ${typeof value}`);
}

function buffersEqual(a, b) {
  return a.length === b.length && timingSafeEqual(a, b);
}

export function hashEventData(data, hashAlg) {
  return createHash(hashAlg).update(toBuffer(data, 'utf8')).digest();
}

export function extendPcr(pcrValue, digest, hashAlg) {
  return createHash(hashAlg).update(Buffer.concat([pcrValue, digest])).digest();
}

export function pcrKey(pcrIndex, hashAlg) {
  return `${pcrIndex}:${hashAlg}`;
}

export function normalizePcrs(pcrs, defaultHashAlg = 'sha256') {
  const normalized = new Map();
  if (!pcrs) return normalized;
  const entries = pcrs instanceof Map ? pcrs.entries() : Object.entries(pcrs);
  for (const [key, value] of entries) {
    const isNested = value != null
      && typeof value === 'object'
      && !Buffer.isBuffer(value)
      && !(value instanceof Uint8Array);
    if (isNested) {
      for (const [alg, digest] of Object.entries(value)) {
        normalized.set(pcrKey(Number(key), alg), toBuffer(digest));
      }
    } else if (String(key).includes(':')) {
      const [index, alg] = String(key).split(':');
      normalized.set(pcrKey(Number(index), alg), toBuffer(value));
    } else {
      normalized.set(pcrKey(Number(key), defaultHashAlg), toBuffer(value));
    }
  }
  return normalized;
}

export function replayEvents(events, options = {}) {
  const { expectedFirstSeq = 0 } = options;
  const errors = [];
  const pcrs = new Map();
  const sorted = [...events].sort((a, b) => a.seq - b.seq);

  let previousSeq = null;
  sorted.forEach((event, position) => {
    if (!Number.isInteger(event.seq) || !Number.isInteger(event.pcrIndex)) {
      errors.push(
        makeError(ErrorCode.MALFORMED_EVENT, '事件缺少整数 seq 或 pcrIndex', { position }),
      );
      return;
    }

    if (previousSeq === null) {
      if (event.seq > expectedFirstSeq) {
        const missingSeqs = [];
        for (let seq = expectedFirstSeq; seq < event.seq; seq += 1) missingSeqs.push(seq);
        errors.push(
          makeError(ErrorCode.EVENT_GAP, `日志起始处缺失 ${missingSeqs.length} 个事件`, {
            kind: 'missing',
            position,
            afterSeq: expectedFirstSeq - 1,
            missingSeqs,
          }),
        );
      }
    } else if (event.seq === previousSeq) {
      errors.push(
        makeError(ErrorCode.EVENT_GAP, `序列号 ${event.seq} 重复，疑似插入伪造事件`, {
          kind: 'duplicate',
          position,
          afterSeq: previousSeq,
          missingSeqs: [],
        }),
      );
    } else if (event.seq > previousSeq + 1) {
      const missingSeqs = [];
      for (let seq = previousSeq + 1; seq < event.seq; seq += 1) missingSeqs.push(seq);
      errors.push(
        makeError(ErrorCode.EVENT_GAP, `序列号 ${previousSeq} 之后缺失 ${missingSeqs.length} 个事件`, {
          kind: 'missing',
          position,
          afterSeq: previousSeq,
          missingSeqs,
        }),
      );
    }
    previousSeq = event.seq;

    const hashAlg = event.hashAlg ?? 'sha256';
    if (!SUPPORTED_HASH_ALGORITHMS.includes(hashAlg)) {
      errors.push(
        makeError(ErrorCode.UNSUPPORTED_ALGORITHM, `不支持的摘要算法: ${hashAlg}`, {
          position,
          seq: event.seq,
          hashAlg,
        }),
      );
      return;
    }

    let digest;
    try {
      digest = toBuffer(event.digest);
    } catch {
      errors.push(
        makeError(ErrorCode.MALFORMED_EVENT, '事件 digest 不是有效的 hex/Buffer', {
          position,
          seq: event.seq,
        }),
      );
      return;
    }
    if (digest.length !== hashLength(hashAlg)) {
      errors.push(
        makeError(
          ErrorCode.MALFORMED_EVENT,
          `digest 长度 ${digest.length} 与 ${hashAlg} 输出长度不符`,
          { position, seq: event.seq, hashAlg },
        ),
      );
      return;
    }

    if (event.data !== undefined && event.data !== null) {
      const recomputed = hashEventData(event.data, hashAlg);
      if (!buffersEqual(recomputed, digest)) {
        errors.push(
          makeError(ErrorCode.DIGEST_MISMATCH, `事件 seq=${event.seq} 的摘要与事件数据不匹配`, {
            position,
            seq: event.seq,
            pcrIndex: event.pcrIndex,
            hashAlg,
            expected: recomputed.toString('hex'),
            actual: digest.toString('hex'),
          }),
        );
      }
    }

    const key = pcrKey(event.pcrIndex, hashAlg);
    const current = pcrs.get(key) ?? Buffer.alloc(hashLength(hashAlg), 0);
    pcrs.set(key, extendPcr(current, digest, hashAlg));
  });

  return { pcrs, errors };
}

export function computePcrDigest(pcrs, hashAlg) {
  const normalized = pcrs instanceof Map ? pcrs : normalizePcrs(pcrs, hashAlg);
  const hash = createHash(hashAlg);
  const sortedEntries = [...normalized.entries()].sort(([a], [b]) => (a < b ? -1 : 1));
  for (const [key, value] of sortedEntries) {
    hash.update(key, 'utf8');
    hash.update(value);
  }
  return hash.digest();
}

export function buildQuotePayload(quote) {
  const nonceHex = toBuffer(quote.nonce).toString('hex');
  const pcrDigestHex = toBuffer(quote.pcrDigest).toString('hex');
  return `BMV1|${quote.hashAlg}|${nonceHex}|${pcrDigestHex}|${quote.timestamp}`;
}

function comparePcrs(computed, quoted, policy, errors) {
  for (const [key, quotedValue] of quoted.entries()) {
    const replayed = computed.get(key);
    if (!replayed) {
      errors.push(
        makeError(ErrorCode.POLICY_MISMATCH, `PCR ${key} 在事件日志中没有任何 extend 记录`, {
          reason: 'replay_mismatch',
          pcr: key,
          expected: quotedValue.toString('hex'),
          actual: null,
        }),
      );
    } else if (!buffersEqual(replayed, quotedValue)) {
      errors.push(
        makeError(ErrorCode.POLICY_MISMATCH, `PCR ${key} 重放结果与引用值不一致`, {
          reason: 'replay_mismatch',
          pcr: key,
          expected: quotedValue.toString('hex'),
          actual: replayed.toString('hex'),
        }),
      );
    }
  }

  const expectedPcrs = normalizePcrs(policy.expectedPcrs);
  for (const [key, expectedValue] of expectedPcrs.entries()) {
    const replayed = computed.get(key);
    if (!replayed || !buffersEqual(replayed, expectedValue)) {
      errors.push(
        makeError(ErrorCode.POLICY_MISMATCH, `PCR ${key} 不满足策略基准值`, {
          reason: 'policy_violation',
          pcr: key,
          expected: expectedValue.toString('hex'),
          actual: replayed ? replayed.toString('hex') : null,
        }),
      );
    }
  }
}

function checkAlgorithmPolicy(events, quote, policy, errors) {
  if (Array.isArray(policy.allowedHashAlgs)) {
    for (const event of events) {
      const hashAlg = event.hashAlg ?? 'sha256';
      if (!policy.allowedHashAlgs.includes(hashAlg)) {
        errors.push(
          makeError(ErrorCode.POLICY_MISMATCH, `摘要算法 ${hashAlg} 不在策略允许列表中`, {
            reason: 'hash_alg_not_allowed',
            seq: event.seq,
            hashAlg,
          }),
        );
      }
    }
    if (quote.hashAlg && !policy.allowedHashAlgs.includes(quote.hashAlg)) {
      errors.push(
        makeError(ErrorCode.POLICY_MISMATCH, `引用对象摘要算法 ${quote.hashAlg} 不被策略允许`, {
          reason: 'hash_alg_not_allowed',
          hashAlg: quote.hashAlg,
        }),
      );
    }
  }
  if (
    Array.isArray(policy.allowedSignatureAlgs)
    && !policy.allowedSignatureAlgs.includes(quote.signatureAlg)
  ) {
    errors.push(
      makeError(ErrorCode.POLICY_MISMATCH, `签名算法 ${quote.signatureAlg} 不在策略允许列表中`, {
        reason: 'signature_alg_not_allowed',
        signatureAlg: quote.signatureAlg,
      }),
    );
  }
}

function checkNonceBinding(quote, challengeNonce, nonceExpiresAt, now, errors) {
  const quoteNonce = toBuffer(quote.nonce);
  const expectedNonce = toBuffer(challengeNonce);
  if (!buffersEqual(quoteNonce, expectedNonce)) {
    errors.push(
      makeError(ErrorCode.NONCE_MISMATCH, '引用对象中的 nonce 与本次 challenge 不一致', {
        expected: expectedNonce.toString('hex'),
        actual: quoteNonce.toString('hex'),
      }),
    );
  }
  if (nonceExpiresAt !== undefined && now > nonceExpiresAt) {
    errors.push(
      makeError(ErrorCode.NONCE_EXPIRED, 'challenge nonce 已过期，证据可能为重放', {
        nonceExpiresAt,
        now,
      }),
    );
  }
}

function verifyQuoteSignature(quote, quotedPcrs, akPublicKey, errors) {
  const spec = SIGNATURE_ALGORITHM_SPECS[quote.signatureAlg];
  if (!spec) {
    errors.push(
      makeError(ErrorCode.UNSUPPORTED_ALGORITHM, `不支持的签名算法: ${quote.signatureAlg}`, {
        signatureAlg: quote.signatureAlg,
      }),
    );
    return;
  }

  const recomputedPcrDigest = computePcrDigest(quotedPcrs, quote.hashAlg);
  if (!buffersEqual(recomputedPcrDigest, toBuffer(quote.pcrDigest))) {
    errors.push(
      makeError(ErrorCode.SIGNATURE_INVALID, '引用对象中的 PCR 摘要与 PCR 集合不一致', {
        reason: 'quote_pcr_digest_mismatch',
        expected: recomputedPcrDigest.toString('hex'),
        actual: toBuffer(quote.pcrDigest).toString('hex'),
      }),
    );
    return;
  }

  let key;
  try {
    key = typeof akPublicKey === 'string' || Buffer.isBuffer(akPublicKey)
      ? createPublicKey(akPublicKey)
      : akPublicKey;
  } catch {
    errors.push(
      makeError(ErrorCode.SIGNATURE_INVALID, 'AK 公钥无法解析', { reason: 'bad_key' }),
    );
    return;
  }

  if (!spec.keyTypes.includes(key.asymmetricKeyType)) {
    errors.push(
      makeError(
        ErrorCode.SIGNATURE_INVALID,
        `AK 密钥类型 ${key.asymmetricKeyType} 与签名算法 ${quote.signatureAlg} 不匹配`,
        { reason: 'key_algorithm_mismatch' },
      ),
    );
    return;
  }
  if (spec.namedCurve && key.asymmetricKeyDetails?.namedCurve !== spec.namedCurve) {
    errors.push(
      makeError(
        ErrorCode.SIGNATURE_INVALID,
        `EC 曲线与 ${quote.signatureAlg} 要求的 ${spec.namedCurve} 不符`,
        { reason: 'key_algorithm_mismatch' },
      ),
    );
    return;
  }

  const payload = Buffer.from(buildQuotePayload(quote), 'utf8');
  const keyObject = spec.padding
    ? { key, padding: spec.padding, saltLength: spec.saltLength }
    : key;
  let valid = false;
  try {
    valid = cryptoVerify(spec.hash ?? null, payload, keyObject, toBuffer(quote.signature));
  } catch {
    valid = false;
  }
  if (!valid) {
    errors.push(
      makeError(ErrorCode.SIGNATURE_INVALID, 'AK 签名校验失败', {
        reason: 'verification_failed',
        signatureAlg: quote.signatureAlg,
      }),
    );
  }
}

export function verifyAttestation(input) {
  const {
    nonce,
    nonceExpiresAt,
    events,
    pcrs,
    quote,
    akPublicKey,
    policy = {},
    now = Date.now(),
  } = input;

  const errors = [];

  const { pcrs: computedPcrs, errors: replayErrors } = replayEvents(events, policy);
  errors.push(...replayErrors);

  const quotedPcrs = normalizePcrs(pcrs, quote.hashAlg ?? 'sha256');
  comparePcrs(computedPcrs, quotedPcrs, policy, errors);
  checkAlgorithmPolicy(events, quote, policy, errors);
  checkNonceBinding(quote, nonce, nonceExpiresAt, now, errors);
  verifyQuoteSignature(quote, quotedPcrs, akPublicKey, errors);

  return {
    ok: errors.length === 0,
    errors,
    computedPcrs: Object.fromEntries(
      [...computedPcrs.entries()].map(([key, value]) => [key, value.toString('hex')]),
    ),
  };
}
