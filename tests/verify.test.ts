import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import { verifyManifest, type BundleManifest } from "../src/verify.js";

const sortKeys = (v: unknown): unknown =>
  v === null || typeof v !== "object"
    ? v
    : Array.isArray(v)
      ? v.map(sortKeys)
      : Object.fromEntries(
          Object.keys(v as object)
            .sort()
            .map((k) => [k, sortKeys((v as Record<string, unknown>)[k])]),
        );

function makeSigned(prefix = "") {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const body = {
    v: 1,
    type: "verifiable-receipt-bundle",
    generatedAt: "2026-01-01T00:00:00.000Z",
    receiptCount: 1,
    bundleDigest: "abc",
    receipts: [{ id: "r1" }],
  };
  const manifestHash = createHash("sha256")
    .update(JSON.stringify(sortKeys(body)), "utf8")
    .digest("hex");
  const signature =
    prefix + sign(null, Buffer.from(manifestHash, "utf8"), privateKey).toString("base64");
  const manifest: BundleManifest = { ...body, manifestHash, signature };
  return { manifest, pem: publicKey.export({ type: "spki", format: "pem" }).toString() };
}

describe("verifyManifest", () => {
  it("accepts a valid manifest, with and without a v2= prefix", () => {
    for (const prefix of ["", "v2="]) {
      const { manifest, pem } = makeSigned(prefix);
      expect(verifyManifest(manifest, pem)).toMatchObject({ ok: true, receiptCount: 1 });
    }
  });

  it("rejects a tampered body as hash-mismatch", () => {
    const { manifest, pem } = makeSigned();
    expect(verifyManifest({ ...manifest, receiptCount: 2 }, pem)).toEqual({
      ok: false,
      reason: "hash-mismatch",
    });
  });

  it("rejects a signature from another key", () => {
    const { manifest } = makeSigned();
    const other = makeSigned().pem;
    expect(verifyManifest(manifest, other)).toEqual({ ok: false, reason: "signature-mismatch" });
  });

  it("rejects a malformed key, wrong type and wrong version", () => {
    const { manifest, pem } = makeSigned();
    expect(verifyManifest(manifest, "not a key")).toEqual({ ok: false, reason: "bad-public-key" });
    expect(verifyManifest({ ...manifest, type: "x" }, pem)).toEqual({ ok: false, reason: "wrong-type" });
    expect(verifyManifest({ ...manifest, v: 2 }, pem)).toEqual({ ok: false, reason: "wrong-version" });
  });

  it("does not throw on a garbage signature", () => {
    const { manifest, pem } = makeSigned();
    expect(verifyManifest({ ...manifest, signature: "!!" }, pem)).toEqual({
      ok: false,
      reason: "signature-mismatch",
    });
  });
});
