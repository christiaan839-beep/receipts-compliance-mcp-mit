import { createHash, createPublicKey, verify as nodeVerify } from "node:crypto";

/** Signed receipt bundle manifest (`MANIFEST.signed.json`). */
export interface BundleManifest {
  v: number;
  type: string;
  generatedAt: string;
  receiptCount: number;
  bundleDigest: string;
  manifestHash: string;
  signature: string;
  receipts: unknown[];
}

export type VerifyResult =
  | { ok: true; receiptCount: number; manifestHash: string; generatedAt: string }
  | {
      ok: false;
      reason:
        | "wrong-type"
        | "wrong-version"
        | "hash-mismatch"
        | "signature-mismatch"
        | "bad-public-key";
    };

function sortKeysDeep(v: unknown): unknown {
  if (v === null || typeof v !== "object") return v;
  if (Array.isArray(v)) return v.map(sortKeysDeep);
  const src = v as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(src).sort()) out[k] = sortKeysDeep(src[k]);
  return out;
}

function stableHash(v: unknown): string {
  return createHash("sha256")
    .update(JSON.stringify(sortKeysDeep(v)), "utf8")
    .digest("hex");
}

/**
 * Decode a manifest signature to raw Ed25519 bytes. Accepts plain base64,
 * `v2=<base64>`, and `v3=<ed25519>.<mldsa65>` (only the Ed25519 half is checked).
 */
function ed25519Bytes(signature: string): Buffer {
  let s = signature;
  if (s.startsWith("v2=")) s = s.slice(3);
  else if (s.startsWith("v3=")) s = s.slice(3).split(".")[0] ?? "";
  return Buffer.from(s, "base64");
}

/**
 * Check a signed bundle manifest against an Ed25519 public key (PEM).
 * Recomputes the manifest hash, then verifies the signature over it.
 * The ML-DSA-65 half of a v3 signature is not checked.
 */
export function verifyManifest(
  manifest: BundleManifest,
  publicKeyPem: string,
): VerifyResult {
  let key;
  try {
    key = createPublicKey({ key: publicKeyPem, format: "pem" });
  } catch {
    return { ok: false, reason: "bad-public-key" };
  }
  if (manifest.type !== "verifiable-receipt-bundle") {
    return { ok: false, reason: "wrong-type" };
  }
  if (manifest.v !== 1) return { ok: false, reason: "wrong-version" };
  const body = {
    v: manifest.v,
    type: manifest.type,
    generatedAt: manifest.generatedAt,
    receiptCount: manifest.receiptCount,
    bundleDigest: manifest.bundleDigest,
    receipts: manifest.receipts,
  };
  if (stableHash(body) !== manifest.manifestHash) {
    return { ok: false, reason: "hash-mismatch" };
  }
  let valid = false;
  try {
    valid = nodeVerify(
      null,
      Buffer.from(manifest.manifestHash, "utf8"),
      key,
      ed25519Bytes(String(manifest.signature ?? "")),
    );
  } catch {
    valid = false;
  }
  if (!valid) return { ok: false, reason: "signature-mismatch" };
  return {
    ok: true,
    receiptCount: manifest.receiptCount,
    manifestHash: manifest.manifestHash,
    generatedAt: manifest.generatedAt,
  };
}
