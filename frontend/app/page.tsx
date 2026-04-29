"use client";

import { useState } from "react";

// ── Types ────────────────────────────────────────────────────────────────────

type LeafOperator = ">=" | "<=" | ">" | "<" | "==";
type LogicOp = "AND" | "OR";
type Mode = "single" | "multi";

interface PolicyOption {
  label: string;
  field: string;
  operator: LeafOperator;
  value: number;
}

type LeafPolicy = { field: string; operator: LeafOperator; value: number };
type CompositePolicy = { operator: LogicOp; policies: [LeafPolicy, LeafPolicy] };
type Policy = LeafPolicy | CompositePolicy;

// ── Policy catalogue ─────────────────────────────────────────────────────────

const POLICIES: PolicyOption[] = [
  { label: "Age ≥ 18",         field: "age",    operator: ">=", value: 18 },
  { label: "Age ≥ 21",         field: "age",    operator: ">=", value: 21 },
  { label: "Salary > 50,000",  field: "salary", operator: ">",  value: 50000 },
  { label: "Salary > 100,000", field: "salary", operator: ">",  value: 100000 },
];

// ── Crypto helpers ───────────────────────────────────────────────────────────

function bufToB64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function b64ToUint8Array(b64: string): Uint8Array {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

const HKDF_INFO = new TextEncoder().encode("selective-disclosure-aes-key");
const HKDF_SALT = new Uint8Array(32);

async function encryptFields(
  fields: Record<string, number>,
  mxePubKeyB64: string
): Promise<{ encryptedData: Record<string, string>; iv: string; clientPublicKey: string }> {
  // Generate browser's ephemeral X25519 key pair.
  const browserKP = (await crypto.subtle.generateKey(
    { name: "X25519" } as any,
    true,
    ["deriveBits"]
  )) as CryptoKeyPair;

  // Import the MXE node's X25519 public key (raw 32-byte format).
  const mxePublicKey = await crypto.subtle.importKey(
    "raw",
    b64ToUint8Array(mxePubKeyB64),
    { name: "X25519" } as any,
    false,
    []
  );

  // ECDH: derive 256-bit shared secret.
  const sharedBits = await crypto.subtle.deriveBits(
    { name: "X25519", public: mxePublicKey } as any,
    browserKP.privateKey,
    256
  );

  // HKDF-SHA-256: derive AES-GCM-256 key from the shared secret.
  const hkdfKey = await crypto.subtle.importKey(
    "raw",
    sharedBits,
    { name: "HKDF" },
    false,
    ["deriveKey"]
  );
  const aesKey = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: HKDF_SALT, info: HKDF_INFO },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );

  // Encrypt each field with a fresh IV.
  const ivBytes = crypto.getRandomValues(new Uint8Array(12));
  const encryptedData: Record<string, string> = {};
  for (const [field, value] of Object.entries(fields)) {
    const ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: ivBytes },
      aesKey,
      new TextEncoder().encode(String(value))
    );
    encryptedData[field] = bufToB64(ct);
  }

  // Export the browser's ephemeral public key to send with the request.
  const clientPublicKey = bufToB64(
    await crypto.subtle.exportKey("raw", browserKP.publicKey)
  );

  return { encryptedData, iv: bufToB64(ivBytes), clientPublicKey };
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function Home() {
  const [age, setAge]             = useState("");
  const [salary, setSalary]       = useState("");
  const [mode, setMode]           = useState<Mode>("single");
  const [policyIdx, setPolicyIdx] = useState(0);
  const [policyIdx2, setPolicyIdx2] = useState(2);
  const [logicOp, setLogicOp]     = useState<LogicOp>("AND");
  const [result, setResult]       = useState<boolean | null>(null);
  const [evaluated, setEvaluated] = useState<number | null>(null);
  const [loading, setLoading]     = useState(false);
  const [error, setError]         = useState<string | null>(null);

  function clearResult() {
    setResult(null);
    setEvaluated(null);
    setError(null);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    clearResult();

    try {
      // Fetch the MXE node's X25519 public key.
      const pkRes = await fetch("http://localhost:4000/policy/mxe-pubkey");
      if (!pkRes.ok) throw new Error("Failed to fetch MXE public key");
      const { publicKey: mxePubKeyB64 } = await pkRes.json();

      // Encrypt both fields via ECDH + HKDF — no raw AES key is sent.
      const { encryptedData, iv, clientPublicKey } = await encryptFields(
        { age: Number(age), salary: Number(salary) },
        mxePubKeyB64
      );

      // Build the policy shape based on the current mode.
      const leaf1: LeafPolicy = {
        field: POLICIES[policyIdx].field,
        operator: POLICIES[policyIdx].operator,
        value: POLICIES[policyIdx].value,
      };
      const policy: Policy =
        mode === "single"
          ? leaf1
          : {
              operator: logicOp,
              policies: [
                leaf1,
                {
                  field: POLICIES[policyIdx2].field,
                  operator: POLICIES[policyIdx2].operator,
                  value: POLICIES[policyIdx2].value,
                },
              ],
            };

      const res = await fetch("http://localhost:4000/policy/evaluate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ policy, encryptedData, iv, clientPublicKey }),
      });

      if (!res.ok) throw new Error(`Server responded with ${res.status}`);

      const data = await res.json();
      setResult(data.result);
      setEvaluated(data.evaluated ?? null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Request failed");
    } finally {
      setLoading(false);
    }
  }

  // ── Shared select/button class helpers ────────────────────────────────────

  const pillActive   = "bg-zinc-900 text-white";
  const pillInactive = "bg-zinc-100 text-zinc-600 hover:bg-zinc-200";
  const selectCls    =
    "w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 text-sm text-zinc-900 focus:outline-none focus:ring-2 focus:ring-zinc-900";

  return (
    <main className="min-h-screen bg-zinc-50 flex items-center justify-center p-6">
      <div className="w-full max-w-sm bg-white rounded-2xl border border-zinc-200 shadow-sm p-8">
        <h1 className="text-lg font-semibold text-zinc-900 mb-6">Policy Evaluator</h1>

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Inputs */}
          <div className="space-y-1">
            <label className="block text-sm font-medium text-zinc-700">Age</label>
            <input
              type="number" required min={0}
              value={age} onChange={(e) => { setAge(e.target.value); clearResult(); }}
              placeholder="e.g. 25"
              className="w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm text-zinc-900 placeholder:text-zinc-400 focus:outline-none focus:ring-2 focus:ring-zinc-900"
            />
          </div>

          <div className="space-y-1">
            <label className="block text-sm font-medium text-zinc-700">Salary</label>
            <input
              type="number" required min={0}
              value={salary} onChange={(e) => { setSalary(e.target.value); clearResult(); }}
              placeholder="e.g. 60000"
              className="w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm text-zinc-900 placeholder:text-zinc-400 focus:outline-none focus:ring-2 focus:ring-zinc-900"
            />
          </div>

          {/* Mode toggle */}
          <div className="flex rounded-lg overflow-hidden border border-zinc-200 text-sm font-medium">
            {(["single", "multi"] as Mode[]).map((m) => (
              <button
                key={m} type="button"
                onClick={() => { setMode(m); clearResult(); }}
                className={`flex-1 py-1.5 transition-colors capitalize ${mode === m ? pillActive : pillInactive}`}
              >
                {m === "single" ? "Single Policy" : "Multi Policy"}
              </button>
            ))}
          </div>

          {/* Policy selector(s) */}
          {mode === "single" ? (
            <div className="space-y-1">
              <label className="block text-sm font-medium text-zinc-700">Policy</label>
              <select value={policyIdx} onChange={(e) => { setPolicyIdx(Number(e.target.value)); clearResult(); }} className={selectCls}>
                {POLICIES.map((p, i) => <option key={i} value={i}>{p.label}</option>)}
              </select>
            </div>
          ) : (
            <div className="space-y-2">
              <div className="space-y-1">
                <label className="block text-sm font-medium text-zinc-700">Policy 1</label>
                <select value={policyIdx} onChange={(e) => { setPolicyIdx(Number(e.target.value)); clearResult(); }} className={selectCls}>
                  {POLICIES.map((p, i) => <option key={i} value={i}>{p.label}</option>)}
                </select>
              </div>

              {/* AND / OR toggle */}
              <div className="flex items-center justify-center gap-2">
                <div className="h-px flex-1 bg-zinc-200" />
                <div className="flex rounded-md overflow-hidden border border-zinc-200 text-xs font-semibold">
                  {(["AND", "OR"] as LogicOp[]).map((op) => (
                    <button
                      key={op} type="button"
                      onClick={() => { setLogicOp(op); clearResult(); }}
                      className={`px-3 py-1 transition-colors ${logicOp === op ? pillActive : pillInactive}`}
                    >
                      {op}
                    </button>
                  ))}
                </div>
                <div className="h-px flex-1 bg-zinc-200" />
              </div>

              <div className="space-y-1">
                <label className="block text-sm font-medium text-zinc-700">Policy 2</label>
                <select value={policyIdx2} onChange={(e) => { setPolicyIdx2(Number(e.target.value)); clearResult(); }} className={selectCls}>
                  {POLICIES.map((p, i) => <option key={i} value={i}>{p.label}</option>)}
                </select>
              </div>
            </div>
          )}

          <button
            type="submit" disabled={loading}
            className="w-full rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-zinc-700 disabled:opacity-50"
          >
            {loading ? "Evaluating…" : "Evaluate"}
          </button>

          <p className="text-center text-xs text-zinc-400">🔒 Encrypted before sending</p>
        </form>

        {error && <p className="mt-6 text-sm text-red-500">{error}</p>}

        {result !== null && error === null && (
          <div className="mt-8 flex flex-col items-center gap-1">
            <span className="text-5xl">{result ? "✅" : "❌"}</span>
            <span className={`text-2xl font-semibold ${result ? "text-green-600" : "text-red-600"}`}>
              {result ? "true" : "false"}
            </span>
            {evaluated !== null && (
              <span className="text-xs text-zinc-400">{evaluated} {evaluated === 1 ? "policy" : "policies"} evaluated</span>
            )}
          </div>
        )}
      </div>
    </main>
  );
}
