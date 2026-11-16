# boot-measurement-verifier

JavaScript 可信启动度量校验库：按事件顺序重放 PCR extend，校验引用 PCR、摘要算法、
AK 签名对象与 challenge nonce 绑定。任何中间事件被删除或篡改都会报出缺失位置。

## 快速开始

```js
import { verifyAttestation } from 'boot-measurement-verifier';

const result = verifyAttestation({
  nonce,            // 本次 challenge 下发的 nonce（hex 或 Buffer）
  nonceExpiresAt,   // nonce 过期时间（ms 时间戳，可选）
  events,           // 启动事件日志：[{ seq, pcrIndex, hashAlg, digest, data? }]
  pcrs,             // 引用对象中的 PCR 当前值：{ "0:sha256": "hex", ... }
  quote,            // 签名对象：{ hashAlg, nonce, pcrDigest, timestamp, signatureAlg, signature }
  akPublicKey,      // AK 公钥（PEM 或 KeyObject）
  policy: {         // 可选策略
    expectedPcrs,          // PCR 基准值
    allowedHashAlgs,       // 允许的摘要算法
    allowedSignatureAlgs,  // 允许的签名算法
  },
});

if (!result.ok) {
  for (const error of result.errors) console.error(error.code, error.message);
}
```

## 校验流程

1. **事件重放**：按 `seq` 排序后执行 `PCR = Hash(PCR || digest)`，从零值 PCR 开始。
2. **摘要校验**：事件携带 `data` 时重新计算 `Hash(data)` 并与 `digest` 比对。
3. **缺口检测**：`seq` 不连续或重复时报告 `EVENT_GAP`，`missingSeqs` / `position`
   指出缺失或插入位置。
4. **PCR 比对**：重放结果与引用 PCR 当前值、策略基准值逐一比对。
5. **nonce 绑定**：引用对象中的 nonce 必须等于 challenge nonce 且未过期。
6. **签名校验**：重建签名载荷 `BMV1|hashAlg|nonce|pcrDigest|timestamp`，
   用 AK 公钥验证签名，并检查密钥类型/曲线与签名算法匹配。

## 错误分类

| code | 含义 |
| --- | --- |
| `DIGEST_MISMATCH` | 事件摘要与事件数据不匹配（含 `seq`、`position`） |
| `EVENT_GAP` | 事件被删除/插入（含 `missingSeqs`、`afterSeq`、`position`） |
| `POLICY_MISMATCH` | PCR 重放与引用值不一致，或不满足策略（`reason`: `replay_mismatch` / `policy_violation` / `hash_alg_not_allowed` / `signature_alg_not_allowed`） |
| `SIGNATURE_INVALID` | AK 签名校验失败、密钥与算法不匹配、引用 PCR 摘要被改 |
| `NONCE_MISMATCH` | 引用对象 nonce 与 challenge 不一致 |
| `NONCE_EXPIRED` | challenge nonce 已过期，疑似重放 |
| `UNSUPPORTED_ALGORITHM` | 摘要或签名算法不受支持 |
| `MALFORMED_EVENT` | 事件字段缺失或 digest 长度不符 |

## 支持的算法

- **哈希**：`sha1`、`sha256`、`sha384`、`sha512`
- **签名**：
  - `ed25519`（Ed25519）
  - `ecdsa-p256-sha256`（ECDSA P-256 + SHA-256）
  - `ecdsa-p384-sha384`（ECDSA P-384 + SHA-384）
  - `rsa-pss-sha256`（RSA-PSS + SHA-256，salt 长度等于摘要长度）
  - `rsa-pkcs1-sha256`（RSA PKCS#1 v1.5 + SHA-256）

## 测试

```sh
node --test
```

覆盖：合法启动、事件插入/删除/篡改、PCR 替换、过期与不匹配 nonce、签名篡改，
以及 RSA-PSS / ECDSA / Ed25519 与多种哈希组合。
