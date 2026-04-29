/*
 * ARCIUM SDK INTEGRATION POINT
 *
 * What to replace when the real Arcium SDK is available:
 *
 * 1. Function signature
 *    Current:  runMxeCompute(input: MxeComputeInput): Promise<MxeComputeOutput>
 *    Replace with the SDK's confidential job submission:
 *      arcium.submitJob({ circuit: "selective_disclosure", inputs: input.encryptedData, args: input.policy })
 *    The SDK routes to the MXE cluster and returns a job handle or resolved output.
 *
 * 2. Key encapsulation
 *    Current: The browser sends its ephemeral X25519 public key (`clientPublicKey`).
 *    The MXE node performs ECDH with its own private key to derive the shared secret,
 *    then uses HKDF-SHA-256 to derive the AES-GCM-256 decryption key. No raw AES
 *    key ever crosses the wire.
 *    In production: the MXE node's long-term X25519 public key is published in
 *    Arcium's on-chain key registry. The client fetches it from there (not from this
 *    mock GET endpoint) and performs the same ECDH+HKDF derivation.
 *
 * 3. encryptedData shape
 *    Each value is an AES-GCM-256 ciphertext (base64), produced in the browser after
 *    deriving the AES key via ECDH+HKDF. The IV is a 12-byte random nonce (base64).
 *    Inside the real MXE enclave, the Arcium SDK handles decryption transparently —
 *    remove the manual ECDH/HKDF/AES logic in this file once the SDK is wired up.
 *
 * 4. What the MXE node returns
 *    The real SDK returns a signed output attestation:
 *      { result: boolean, outputCommitment: string, signature: string }
 *    `outputCommitment` is a hash of (result, policy, timestamp) verifiable on-chain
 *    against the Arcium verifier. Replace MxeComputeOutput with this shape and update
 *    the frontend to optionally display or forward the commitment for verification.
 */

import { webcrypto } from "node:crypto";
import { evaluatePolicy, Policy } from "../../backend/src/engine/policyEvaluator";

export interface MxeComputeInput {
  encryptedData: Record<string, string>; // AES-GCM-256 ciphertext per field, base64
  iv: string;                            // 12-byte GCM nonce, base64
  clientPublicKey: string;               // browser's ephemeral X25519 public key, base64 (raw 32 bytes)
  policy: Policy;
}

export interface MxeComputeOutput {
  result: boolean | string;
  outputType: "boolean" | "range" | "masked";
  // SHA-256 of the canonical policy JSON (sorted keys, no whitespace), hex-encoded.
  // In production this hash would be signed by the MXE node's attestation key (Ed25519 or
  // ECDSA P-256), allowing any verifier to confirm that this exact result was produced from
  // this exact policy without learning anything about the private input values.
  policyHash: string;
  evaluated: number;
  computedAt: string;
  mxeSimulated: true;
}

const HKDF_INFO = new TextEncoder().encode("selective-disclosure-aes-key");
const HKDF_SALT = new Uint8Array(32); // zero salt; IV already carries per-session randomness

// MXE node's ephemeral X25519 key pair — generated once on module load.
// In production this would be the node's long-term keypair from the Arcium key registry.
const _mxeKeyPairPromise = (webcrypto.subtle.generateKey(
  { name: "X25519" } as any,
  true,
  ["deriveBits"]
) as Promise<{ privateKey: webcrypto.CryptoKey; publicKey: webcrypto.CryptoKey }>);

export async function getMxePublicKey(): Promise<string> {
  const { publicKey } = await _mxeKeyPairPromise;
  const raw = await webcrypto.subtle.exportKey("raw", publicKey);
  return Buffer.from(raw).toString("base64");
}

async function deriveAesKey(
  mxePrivateKey: webcrypto.CryptoKey,
  clientPublicKeyB64: string,
  usage: "decrypt"
): Promise<webcrypto.CryptoKey> {
  const clientPubBytes = Uint8Array.from(Buffer.from(clientPublicKeyB64, "base64"));

  const clientPublicKey = await webcrypto.subtle.importKey(
    "raw",
    clientPubBytes,
    { name: "X25519" } as any,
    false,
    []
  );

  const sharedBits = await webcrypto.subtle.deriveBits(
    { name: "X25519", public: clientPublicKey } as any,
    mxePrivateKey,
    256
  );

  const hkdfKey = await webcrypto.subtle.importKey(
    "raw",
    sharedBits,
    { name: "HKDF" },
    false,
    ["deriveKey"]
  );

  return webcrypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: HKDF_SALT, info: HKDF_INFO },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    [usage]
  );
}

export async function runMxeCompute(
  input: MxeComputeInput
): Promise<MxeComputeOutput> {
  const { encryptedData, iv: ivB64, clientPublicKey, policy } = input;
  const { privateKey } = await _mxeKeyPairPromise;

  // Derive the same AES key the browser used, without the raw key ever leaving the client.
  const aesKey = await deriveAesKey(privateKey, clientPublicKey, "decrypt");
  const ivBytes = Uint8Array.from(Buffer.from(ivB64, "base64"));

  const decrypted: Record<string, number> = {};
  for (const [field, ciphertextB64] of Object.entries(encryptedData)) {
    const ciphertext = Uint8Array.from(Buffer.from(ciphertextB64, "base64"));
    const plaintext = await webcrypto.subtle.decrypt(
      { name: "AES-GCM", iv: ivBytes },
      aesKey,
      ciphertext
    );
    const value = Number(new TextDecoder().decode(plaintext));
    if (isNaN(value)) throw new Error(`Field "${field}" did not decrypt to a number`);
    decrypted[field] = value;
  }

  const { result, outputType, policyHash, evaluated } = evaluatePolicy(policy, decrypted);

  return { result, outputType, policyHash, evaluated, computedAt: new Date().toISOString(), mxeSimulated: true };
}
