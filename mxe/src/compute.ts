/*
 * ARCIUM SDK INTEGRATION POINT
 *
 * What to replace when the real Arcium SDK is available:
 *
 * 1. Function signature
 *    Current:  runMxeCompute(input: MxeComputeInput): Promise<MxeComputeOutput>
 *    Replace with the SDK's job submission call, e.g.:
 *      arcium.submitJob({ circuit: "selective_disclosure", inputs: input.encryptedData, args: input.policy })
 *    The SDK handles routing to the MXE cluster and returns a job ID or a resolved output.
 *
 * 2. encryptedData shape
 *    Each value is an AES-GCM-256 ciphertext (base64) produced in the browser.
 *    In production the ephemeral AES key (currently sent as `key`) must instead be
 *    wrapped with the MXE node's X25519 public key (key encapsulation / ECIES) so
 *    the raw key never leaves the client. The MXE node unwraps it inside the enclave.
 *
 * 3. What the MXE node returns
 *    The real SDK returns a signed output attestation, e.g.:
 *      { result: boolean, outputCommitment: string, signature: string }
 *    `outputCommitment` is a hash of (result, policy, timestamp) that can be
 *    verified on-chain or against the Arcium verifier endpoint.
 *    This mock returns { result, computedAt, mxeSimulated: true } in its place.
 *
 * 4. Key management note
 *    The `key` field in MxeComputeInput is present only for this simulation.
 *    Remove it entirely once the SDK handles key encapsulation internally.
 */

import { webcrypto } from "node:crypto";

export interface MxeComputeInput {
  encryptedData: Record<string, string>; // AES-GCM-256 ciphertext per field, base64-encoded
  iv: string;                            // 12-byte GCM nonce, base64-encoded
  key: string;                           // raw AES key, base64-encoded (simulation only — see note 4)
  policy: {
    field: string;
    operator: string;
    value: number;
  };
}

export interface MxeComputeOutput {
  result: boolean;
  computedAt: string;
  mxeSimulated: true;
}

const OPERATORS: Record<string, (a: number, b: number) => boolean> = {
  ">=": (a, b) => a >= b,
  "<=": (a, b) => a <= b,
  ">":  (a, b) => a > b,
  "<":  (a, b) => a < b,
  "==": (a, b) => a === b,
};

export async function runMxeCompute(
  input: MxeComputeInput
): Promise<MxeComputeOutput> {
  const { encryptedData, iv: ivB64, key: keyB64, policy } = input;

  const rawKey  = Uint8Array.from(Buffer.from(keyB64, "base64"));
  const ivBytes = Uint8Array.from(Buffer.from(ivB64,  "base64"));

  const cryptoKey = await webcrypto.subtle.importKey(
    "raw",
    rawKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );

  // Decrypt inside MXE: each ciphertext is AES-GCM decrypted, then parsed as a number.
  const decrypted: Record<string, number> = {};
  for (const [field, ciphertextB64] of Object.entries(encryptedData)) {
    const ciphertext = Uint8Array.from(Buffer.from(ciphertextB64, "base64"));
    const plaintext  = await webcrypto.subtle.decrypt(
      { name: "AES-GCM", iv: ivBytes },
      cryptoKey,
      ciphertext
    );
    const value = Number(new TextDecoder().decode(plaintext));
    if (isNaN(value)) throw new Error(`Field "${field}" did not decrypt to a number`);
    decrypted[field] = value;
  }

  const evaluate = OPERATORS[policy.operator];
  if (!evaluate) throw new Error(`Unknown operator: ${policy.operator}`);

  const fieldValue = decrypted[policy.field];
  const result = fieldValue !== undefined && evaluate(fieldValue, policy.value);

  return {
    result,
    computedAt: new Date().toISOString(),
    mxeSimulated: true,
  };
}
