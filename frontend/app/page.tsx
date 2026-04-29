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

interface MxeResult {
  result: boolean;
  evaluated: number;
  mxeSimulated: true;
  computedAt: string;
}

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

function b64ToUint8Array(b64: string) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

const HKDF_INFO = new TextEncoder().encode("selective-disclosure-aes-key");
const HKDF_SALT = new Uint8Array(32);

async function encryptFields(
  fields: Record<string, number>,
  mxePubKeyB64: string
): Promise<{ encryptedData: Record<string, string>; iv: string; clientPublicKey: string }> {
  const browserKP = (await crypto.subtle.generateKey(
    { name: "X25519" } as any,
    true,
    ["deriveBits"]
  )) as CryptoKeyPair;

  const mxePublicKey = await crypto.subtle.importKey(
    "raw",
    b64ToUint8Array(mxePubKeyB64),
    { name: "X25519" } as any,
    false,
    []
  );

  const sharedBits = await crypto.subtle.deriveBits(
    { name: "X25519", public: mxePublicKey } as any,
    browserKP.privateKey,
    256
  );

  const hkdfKey = await crypto.subtle.importKey(
    "raw", sharedBits, { name: "HKDF" }, false, ["deriveKey"]
  );
  const aesKey = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: HKDF_SALT, info: HKDF_INFO },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );

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

  const clientPublicKey = bufToB64(
    await crypto.subtle.exportKey("raw", browserKP.publicKey)
  );

  return { encryptedData, iv: bufToB64(ivBytes.buffer), clientPublicKey };
}

// ── Policy evaluator (mirrors backend/src/engine/policyEvaluator.ts) ─────────

const COMPARATORS: Record<LeafOperator, (a: number, b: number) => boolean> = {
  ">=": (a, b) => a >= b,
  "<=": (a, b) => a <= b,
  ">":  (a, b) => a > b,
  "<":  (a, b) => a < b,
  "==": (a, b) => a === b,
};

function evaluatePolicyLocal(
  policy: Policy,
  input: Record<string, number>
): { result: boolean; evaluated: number } {
  if ("policies" in policy) {
    let result = policy.operator === "AND";
    let evaluated = 0;
    for (const child of policy.policies) {
      const r = evaluatePolicyLocal(child, input);
      evaluated += r.evaluated;
      result = policy.operator === "AND" ? result && r.result : result || r.result;
    }
    return { result, evaluated };
  }
  const raw = input[policy.field];
  if (raw === undefined) return { result: false, evaluated: 1 };
  return { result: COMPARATORS[policy.operator](raw, policy.value), evaluated: 1 };
}

// ── Mock MXE compute (replaces fetch to backend in demo mode) ─────────────────

async function mockMxeEvaluate(
  encryptedData: Record<string, string>,
  iv: string,
  clientPublicKey: string,
  mxePrivateKey: CryptoKey,
  policy: Policy
): Promise<MxeResult> {
  await new Promise<void>((resolve) => setTimeout(resolve, 600));

  const clientPubKey = await crypto.subtle.importKey(
    "raw",
    b64ToUint8Array(clientPublicKey),
    { name: "X25519" } as any,
    false,
    []
  );
  const sharedBits = await crypto.subtle.deriveBits(
    { name: "X25519", public: clientPubKey } as any,
    mxePrivateKey,
    256
  );
  const hkdfKey = await crypto.subtle.importKey(
    "raw", sharedBits, { name: "HKDF" }, false, ["deriveKey"]
  );
  const aesKey = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: HKDF_SALT, info: HKDF_INFO },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );

  const ivBytes = b64ToUint8Array(iv);
  const decrypted: Record<string, number> = {};
  for (const [field, ctB64] of Object.entries(encryptedData)) {
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: ivBytes },
      aesKey,
      b64ToUint8Array(ctB64)
    );
    decrypted[field] = Number(new TextDecoder().decode(plaintext));
  }

  const { result, evaluated } = evaluatePolicyLocal(policy, decrypted);
  return { result, evaluated, mxeSimulated: true, computedAt: new Date().toISOString() };
}

// ── Sub-components ────────────────────────────────────────────────────────────

function PolicySelect({
  value,
  onChange,
}: {
  value: number;
  onChange: (i: number) => void;
}) {
  return (
    <div className="relative">
      <select
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        className="w-full cursor-pointer appearance-none rounded-xl border border-white/[0.08] bg-white/[0.04] px-4 py-3 pr-10 text-sm text-white transition-all duration-200 focus:border-cyan-500/50 focus:bg-white/[0.06] focus:outline-none focus:shadow-[0_0_20px_rgba(6,182,212,0.12)] [&>option]:bg-[#0d1525] [&>option]:text-white"
      >
        {POLICIES.map((p, i) => (
          <option key={i} value={i}>{p.label}</option>
        ))}
      </select>
      <div className="pointer-events-none absolute inset-y-0 right-3 flex items-center">
        <svg className="h-4 w-4 text-zinc-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19 9l-7 7-7-7" />
        </svg>
      </div>
    </div>
  );
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function Home() {
  const [age, setAge]               = useState("");
  const [salary, setSalary]         = useState("");
  const [mode, setMode]             = useState<Mode>("single");
  const [policyIdx, setPolicyIdx]   = useState(0);
  const [policyIdx2, setPolicyIdx2] = useState(2);
  const [logicOp, setLogicOp]       = useState<LogicOp>("AND");
  const [result, setResult]         = useState<boolean | null>(null);
  const [evaluated, setEvaluated]   = useState<number | null>(null);
  const [loading, setLoading]       = useState(false);
  const [error, setError]           = useState<string | null>(null);

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
      const mockMxeKP = (await crypto.subtle.generateKey(
        { name: "X25519" } as any,
        true,
        ["deriveBits"]
      )) as CryptoKeyPair;

      const mockMxePubKeyB64 = bufToB64(
        await crypto.subtle.exportKey("raw", mockMxeKP.publicKey)
      );

      const { encryptedData, iv, clientPublicKey } = await encryptFields(
        { age: Number(age), salary: Number(salary) },
        mockMxePubKeyB64
      );

      const leaf1: LeafPolicy = {
        field:    POLICIES[policyIdx].field,
        operator: POLICIES[policyIdx].operator,
        value:    POLICIES[policyIdx].value,
      };
      const policy: Policy =
        mode === "single"
          ? leaf1
          : {
              operator: logicOp,
              policies: [
                leaf1,
                {
                  field:    POLICIES[policyIdx2].field,
                  operator: POLICIES[policyIdx2].operator,
                  value:    POLICIES[policyIdx2].value,
                },
              ],
            };

      const data = await mockMxeEvaluate(
        encryptedData, iv, clientPublicKey,
        mockMxeKP.privateKey,
        policy
      );

      setResult(data.result);
      setEvaluated(data.evaluated);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Evaluation failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="relative min-h-screen overflow-x-hidden bg-[#020817] text-white">

      {/* Ambient glow — top centre */}
      <div
        aria-hidden="true"
        className="pointer-events-none fixed left-1/2 top-0 -translate-x-1/2"
        style={{
          width: 900,
          height: 600,
          marginTop: -240,
          background: "radial-gradient(ellipse at center, rgba(6,182,212,0.13) 0%, rgba(168,85,247,0.06) 45%, transparent 70%)",
        }}
      />

      {/* Subtle dot grid */}
      <div
        aria-hidden="true"
        className="pointer-events-none fixed inset-0"
        style={{
          backgroundImage: "radial-gradient(circle, rgba(255,255,255,0.025) 1px, transparent 1px)",
          backgroundSize: "36px 36px",
        }}
      />

      {/* ── Demo bar ─────────────────────────────────────────────────────────── */}
      <header className="sticky top-0 z-50 border-b border-white/[0.05] bg-[#020817]/75 backdrop-blur-xl">
        <div className="mx-auto flex max-w-5xl items-center justify-center gap-3 px-4 py-2.5 sm:gap-5">
          <div className="flex items-center gap-2">
            <span className="relative flex h-1.5 w-1.5">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-cyan-400 opacity-60" />
              <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-cyan-500" />
            </span>
            <span className="text-[11px] font-semibold text-zinc-400">Demo mode</span>
          </div>
          <span className="text-white/[0.12]">·</span>
          <span className="text-[11px] text-zinc-600">MXE computation simulated in browser</span>
          <span className="hidden text-white/[0.12] sm:inline">·</span>
          <span className="hidden text-[11px] text-zinc-700 sm:inline">No backend required</span>
        </div>
      </header>

      {/* ── Main ─────────────────────────────────────────────────────────────── */}
      <main className="relative mx-auto flex max-w-5xl flex-col items-center px-4 pb-28 pt-16 sm:px-6 md:pt-24">

        {/* Hero */}
        <div className="mb-14 text-center md:mb-20">
          <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-cyan-500/20 bg-cyan-500/[0.07] px-4 py-1.5 text-[11px] font-medium text-cyan-400">
            <span>🔐</span>
            <span>Privacy-preserving policy evaluation</span>
          </div>
          <h1 className="text-[2.8rem] font-bold leading-[1.08] tracking-tight sm:text-5xl md:text-[3.75rem]">
            <span className="bg-gradient-to-r from-cyan-300 via-white to-purple-400 bg-clip-text text-transparent">
              Selective Disclosure
            </span>
            <br />
            <span className="text-white">Engine</span>
          </h1>
          <p className="mx-auto mt-4 max-w-sm text-sm leading-relaxed text-zinc-500 sm:text-[15px]">
            Prove data properties without revealing the underlying values.
          </p>
        </div>

        {/* ── Form ─────────────────────────────────────────────────────────── */}
        <form onSubmit={handleSubmit} className="w-full">

          {/* Two-column grid */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 lg:gap-5">

            {/* ── Left card — Input Data ── */}
            <div className="rounded-2xl border border-white/[0.07] bg-gradient-to-br from-white/[0.04] to-transparent p-6 backdrop-blur-sm">
              <div className="mb-5 flex items-center gap-3">
                <span className="text-[10px] font-bold uppercase tracking-[0.2em] text-zinc-600">
                  Input Data
                </span>
                <div className="h-px flex-1 bg-white/[0.05]" />
              </div>

              <div className="space-y-4">
                {/* Age */}
                <div>
                  <label className="mb-2 block text-[10px] font-bold uppercase tracking-[0.18em] text-zinc-600">
                    Age
                  </label>
                  <input
                    type="number" required min={0}
                    value={age}
                    onChange={(e) => { setAge(e.target.value); clearResult(); }}
                    placeholder="e.g. 25"
                    className="w-full rounded-xl border border-white/[0.08] bg-white/[0.04] px-4 py-3.5 text-sm text-white placeholder:text-zinc-700 transition-all duration-200 focus:border-cyan-500/50 focus:bg-white/[0.06] focus:outline-none focus:shadow-[0_0_22px_rgba(6,182,212,0.14)]"
                  />
                </div>

                {/* Salary */}
                <div>
                  <label className="mb-2 block text-[10px] font-bold uppercase tracking-[0.18em] text-zinc-600">
                    Salary
                  </label>
                  <input
                    type="number" required min={0}
                    value={salary}
                    onChange={(e) => { setSalary(e.target.value); clearResult(); }}
                    placeholder="e.g. 60000"
                    className="w-full rounded-xl border border-white/[0.08] bg-white/[0.04] px-4 py-3.5 text-sm text-white placeholder:text-zinc-700 transition-all duration-200 focus:border-cyan-500/50 focus:bg-white/[0.06] focus:outline-none focus:shadow-[0_0_22px_rgba(6,182,212,0.14)]"
                  />
                </div>
              </div>

              {/* Footer note */}
              <div className="mt-5 flex items-center gap-2 border-t border-white/[0.05] pt-5">
                <svg className="h-3.5 w-3.5 shrink-0 text-cyan-500/40" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
                <span className="text-[11px] text-zinc-700">
                  Values are encrypted before leaving your device
                </span>
              </div>
            </div>

            {/* ── Right card — Policy ── */}
            <div className="rounded-2xl border border-white/[0.07] bg-gradient-to-br from-white/[0.04] to-transparent p-6 backdrop-blur-sm">
              <div className="mb-5 flex items-center gap-3">
                <span className="text-[10px] font-bold uppercase tracking-[0.2em] text-zinc-600">
                  Policy
                </span>
                <div className="h-px flex-1 bg-white/[0.05]" />
              </div>

              {/* Mode toggle — sliding indicator */}
              <div className="relative mb-5 flex rounded-xl border border-white/[0.07] bg-black/20 p-1">
                <div
                  className="absolute top-1 h-[calc(100%-8px)] w-[calc(50%-4px)] rounded-lg border border-cyan-500/30 bg-cyan-500/[0.12] transition-all duration-300 ease-in-out"
                  style={{ left: mode === "multi" ? "50%" : "4px" }}
                />
                {(["single", "multi"] as Mode[]).map((m) => (
                  <button
                    key={m} type="button"
                    onClick={() => { setMode(m); clearResult(); }}
                    className={`relative z-10 flex-1 rounded-lg py-2.5 text-xs font-semibold tracking-wide transition-colors duration-300 ${
                      mode === m ? "text-cyan-400" : "text-zinc-600 hover:text-zinc-400"
                    }`}
                  >
                    {m === "single" ? "Single" : "Multi"}
                  </button>
                ))}
              </div>

              {mode === "single" ? (
                <div>
                  <label className="mb-2 block text-[10px] font-bold uppercase tracking-[0.18em] text-zinc-600">
                    Condition
                  </label>
                  <PolicySelect value={policyIdx} onChange={(i) => { setPolicyIdx(i); clearResult(); }} />
                </div>
              ) : (
                <div className="space-y-4">
                  <div>
                    <label className="mb-2 block text-[10px] font-bold uppercase tracking-[0.18em] text-zinc-600">
                      Condition 1
                    </label>
                    <PolicySelect value={policyIdx} onChange={(i) => { setPolicyIdx(i); clearResult(); }} />
                  </div>

                  {/* AND / OR — sliding pill */}
                  <div className="flex items-center gap-3">
                    <div className="h-px flex-1 bg-white/[0.05]" />
                    <div className="relative flex rounded-full border border-white/[0.08] bg-black/20 p-1">
                      <div
                        className="absolute top-1 h-[calc(100%-8px)] w-[calc(50%-4px)] rounded-full border border-purple-500/40 bg-purple-500/[0.18] transition-all duration-300 ease-in-out"
                        style={{ left: logicOp === "OR" ? "50%" : "4px" }}
                      />
                      {(["AND", "OR"] as LogicOp[]).map((op) => (
                        <button
                          key={op} type="button"
                          onClick={() => { setLogicOp(op); clearResult(); }}
                          className={`relative z-10 flex-1 px-5 py-1.5 text-[11px] font-bold tracking-widest transition-colors duration-300 ${
                            logicOp === op ? "text-purple-300" : "text-zinc-600 hover:text-zinc-400"
                          }`}
                        >
                          {op}
                        </button>
                      ))}
                    </div>
                    <div className="h-px flex-1 bg-white/[0.05]" />
                  </div>

                  <div>
                    <label className="mb-2 block text-[10px] font-bold uppercase tracking-[0.18em] text-zinc-600">
                      Condition 2
                    </label>
                    <PolicySelect value={policyIdx2} onChange={(i) => { setPolicyIdx2(i); clearResult(); }} />
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* ── Evaluate button ── */}
          <div className="mt-4 space-y-2.5">
            <button
              type="submit"
              disabled={loading}
              className="group relative w-full overflow-hidden rounded-xl py-4 text-[13px] font-bold uppercase tracking-[0.15em] text-[#020817] transition-all duration-300 focus:outline-none disabled:cursor-not-allowed disabled:opacity-30 hover:shadow-[0_0_45px_rgba(6,182,212,0.35)]"
            >
              <div className="absolute inset-0 bg-gradient-to-r from-cyan-400 to-cyan-300 transition-all duration-300 group-hover:from-cyan-300 group-hover:to-cyan-200" />
              <span className="relative flex items-center justify-center gap-2.5">
                {loading && (
                  <svg className="h-4 w-4 animate-spin" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                )}
                {loading ? "Evaluating policy…" : "Evaluate Policy"}
              </span>
            </button>
            <p className="text-center text-[11px] text-zinc-700">🔒 Encrypted before sending</p>
          </div>
        </form>

        {/* ── Error ── */}
        {error && (
          <div className="mt-5 w-full rounded-xl border border-red-500/20 bg-red-500/[0.05] px-5 py-4 text-sm text-red-400">
            {error}
          </div>
        )}

        {/* ── Result card ── */}
        {result !== null && error === null && (
          <div
            className={`mt-5 w-full rounded-2xl border p-10 text-center backdrop-blur-sm transition-all duration-500 ${
              result
                ? "border-green-500/20 bg-green-500/[0.04] shadow-[0_0_90px_rgba(34,197,94,0.11)]"
                : "border-red-500/20 bg-red-500/[0.04] shadow-[0_0_90px_rgba(239,68,68,0.11)]"
            }`}
          >
            <div className="mb-4 text-6xl sm:text-7xl">{result ? "✅" : "❌"}</div>

            <div className={`mb-2 text-4xl font-bold sm:text-5xl ${result ? "text-green-400" : "text-red-400"}`}>
              {result ? "true" : "false"}
            </div>

            {evaluated !== null && (
              <p className="mb-6 text-sm text-zinc-600">
                {evaluated} {evaluated === 1 ? "policy" : "policies"} evaluated
              </p>
            )}

            <div className={`inline-flex items-center gap-2 rounded-full border px-4 py-2 text-xs font-medium ${
              result
                ? "border-green-500/20 bg-green-500/[0.07] text-green-500/60"
                : "border-red-500/20 bg-red-500/[0.07] text-red-500/60"
            }`}>
              🔒 Encrypted with X25519 + AES-GCM-256
            </div>
          </div>
        )}

      </main>
    </div>
  );
}
