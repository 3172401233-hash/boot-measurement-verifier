import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import {
  ErrorCode,
  computePcrDigest,
  hashEventData,
  verifyAttestation,
} from '../src/index.js';
import { HASH_ALG, makeFixture, signQuote, verifyFixture } from './helpers.js';

function codes(result) {
  return result.errors.map((error) => error.code);
}

describe('合法启动', () => {
  it('完整证据链通过校验', () => {
    const fixture = makeFixture();
    const result = verifyAttestation(verifyFixture(fixture));
    assert.equal(result.ok, true, JSON.stringify(result.errors, null, 2));
    assert.deepEqual(result.errors, []);
    assert.ok(result.computedPcrs['0:sha256']);
    assert.ok(result.computedPcrs['1:sha256']);
  });

  it('支持 RSA-PSS 与 ECDSA P-256 签名', () => {
    for (const signatureAlg of ['rsa-pss-sha256', 'ecdsa-p256-sha256']) {
      const fixture = makeFixture({ signatureAlg });
      const result = verifyAttestation(verifyFixture(fixture));
      assert.equal(result.ok, true, `${signatureAlg}: ${JSON.stringify(result.errors)}`);
    }
  });

  it('支持 sha1/sha384/sha512 摘要', () => {
    for (const hashAlg of ['sha1', 'sha384', 'sha512']) {
      const fixture = makeFixture({ hashAlg });
      const result = verifyAttestation(verifyFixture(fixture));
      assert.equal(result.ok, true, `${hashAlg}: ${JSON.stringify(result.errors)}`);
    }
  });
});

describe('事件篡改与缺失', () => {
  it('事件数据被篡改时报 DIGEST_MISMATCH 并定位 seq', () => {
    const fixture = makeFixture();
    const events = fixture.events.map((event) =>
      event.seq === 2 ? { ...event, data: 'kernel-image-6.8.1-backdoored' } : event);
    const result = verifyAttestation(verifyFixture(fixture, { events }));
    assert.equal(result.ok, false);
    const digestErrors = result.errors.filter((e) => e.code === ErrorCode.DIGEST_MISMATCH);
    assert.equal(digestErrors.length, 1);
    assert.equal(digestErrors[0].seq, 2);
    assert.ok(!codes(result).includes(ErrorCode.POLICY_MISMATCH));
  });

  it('事件摘要被替换时报 DIGEST_MISMATCH 且 PCR 重放不一致', () => {
    const fixture = makeFixture();
    const events = fixture.events.map((event) =>
      event.seq === 2
        ? { ...event, digest: hashEventData('kernel-image-evil', HASH_ALG).toString('hex') }
        : event);
    const result = verifyAttestation(verifyFixture(fixture, { events }));
    assert.equal(result.ok, false);
    assert.ok(codes(result).includes(ErrorCode.DIGEST_MISMATCH));
    assert.ok(codes(result).includes(ErrorCode.POLICY_MISMATCH));
  });

  it('中间事件被删除时报 EVENT_GAP 并指出缺失位置', () => {
    const fixture = makeFixture();
    const events = fixture.events.filter((event) => event.seq !== 2);
    const result = verifyAttestation(verifyFixture(fixture, { events }));
    assert.equal(result.ok, false);
    const gap = result.errors.find((e) => e.code === ErrorCode.EVENT_GAP);
    assert.ok(gap, '应报告事件缺口');
    assert.deepEqual(gap.missingSeqs, [2]);
    assert.equal(gap.afterSeq, 1);
    assert.equal(gap.position, 2);
    assert.ok(codes(result).includes(ErrorCode.POLICY_MISMATCH));
  });

  it('插入伪造事件导致 PCR 重放与引用值不一致', () => {
    const fixture = makeFixture();
    const forged = {
      seq: 5,
      pcrIndex: 0,
      hashAlg: HASH_ALG,
      data: 'malicious-module',
      digest: hashEventData('malicious-module', HASH_ALG).toString('hex'),
    };
    const events = [...fixture.events, forged];
    const result = verifyAttestation(verifyFixture(fixture, { events }));
    assert.equal(result.ok, false);
    assert.ok(codes(result).includes(ErrorCode.POLICY_MISMATCH));
    const mismatch = result.errors.find((e) => e.code === ErrorCode.POLICY_MISMATCH);
    assert.equal(mismatch.reason, 'replay_mismatch');
    assert.equal(mismatch.pcr, '0:sha256');
  });

  it('重复序列号的插入事件被标记为 EVENT_GAP duplicate', () => {
    const fixture = makeFixture();
    const forged = {
      ...fixture.events[2],
      data: 'evil',
      digest: hashEventData('evil', HASH_ALG).toString('hex'),
    };
    const events = [...fixture.events, forged];
    const result = verifyAttestation(verifyFixture(fixture, { events }));
    const gap = result.errors.find((e) => e.code === ErrorCode.EVENT_GAP);
    assert.ok(gap);
    assert.equal(gap.kind, 'duplicate');
  });
});

describe('PCR 替换', () => {
  it('引用 PCR 被替换（重新签名）时仅报 POLICY_MISMATCH', () => {
    const fixture = makeFixture();
    const pcrs = { ...fixture.pcrs, '0:sha256': randomBytes(32).toString('hex') };
    const quote = {
      ...fixture.quote,
      pcrDigest: computePcrDigest(pcrs, HASH_ALG).toString('hex'),
    };
    quote.signature = signQuote(quote, quote.signatureAlg, fixture.privateKey).toString('hex');
    const result = verifyAttestation(verifyFixture(fixture, { pcrs, quote }));
    assert.equal(result.ok, false);
    assert.ok(codes(result).includes(ErrorCode.POLICY_MISMATCH));
    assert.ok(!codes(result).includes(ErrorCode.SIGNATURE_INVALID));
  });

  it('PCR 不满足策略基准值时报 policy_violation', () => {
    const fixture = makeFixture();
    const policy = { expectedPcrs: { '0:sha256': randomBytes(32).toString('hex') } };
    const result = verifyAttestation(verifyFixture(fixture, { policy }));
    assert.equal(result.ok, false);
    const violation = result.errors.find((e) => e.code === ErrorCode.POLICY_MISMATCH);
    assert.equal(violation.reason, 'policy_violation');
  });
});

describe('nonce 绑定', () => {
  it('过期 nonce 报 NONCE_EXPIRED', () => {
    const fixture = makeFixture();
    const result = verifyAttestation(
      verifyFixture(fixture, { now: fixture.nonceExpiresAt + 1 }),
    );
    assert.equal(result.ok, false);
    assert.ok(codes(result).includes(ErrorCode.NONCE_EXPIRED));
  });

  it('nonce 与 challenge 不一致报 NONCE_MISMATCH', () => {
    const fixture = makeFixture();
    const result = verifyAttestation(
      verifyFixture(fixture, { nonce: randomBytes(32) }),
    );
    assert.equal(result.ok, false);
    assert.ok(codes(result).includes(ErrorCode.NONCE_MISMATCH));
  });
});

describe('签名篡改', () => {
  it('签名字节被翻转时报 SIGNATURE_INVALID', () => {
    const fixture = makeFixture();
    const signature = Buffer.from(fixture.quote.signature, 'hex');
    signature[0] ^= 0xff;
    const quote = { ...fixture.quote, signature: signature.toString('hex') };
    const result = verifyAttestation(verifyFixture(fixture, { quote }));
    assert.equal(result.ok, false);
    const sigErrors = result.errors.filter((e) => e.code === ErrorCode.SIGNATURE_INVALID);
    assert.equal(sigErrors.length, 1);
    assert.equal(sigErrors[0].reason, 'verification_failed');
  });

  it('引用对象 nonce 被改动后签名失效', () => {
    const fixture = makeFixture();
    const quote = { ...fixture.quote, nonce: randomBytes(32).toString('hex') };
    const result = verifyAttestation(
      verifyFixture(fixture, { quote, nonce: Buffer.from(quote.nonce, 'hex') }),
    );
    assert.equal(result.ok, false);
    assert.ok(codes(result).includes(ErrorCode.SIGNATURE_INVALID));
  });

  it('密钥类型与签名算法不匹配报 SIGNATURE_INVALID', () => {
    const fixture = makeFixture();
    const quote = { ...fixture.quote, signatureAlg: 'rsa-pss-sha256' };
    const result = verifyAttestation(verifyFixture(fixture, { quote }));
    const sigError = result.errors.find((e) => e.code === ErrorCode.SIGNATURE_INVALID);
    assert.ok(sigError);
    assert.equal(sigError.reason, 'key_algorithm_mismatch');
  });
});
