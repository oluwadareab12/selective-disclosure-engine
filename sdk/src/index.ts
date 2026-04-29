// ── Types ─────────────────────────────────────────────────────────────────────

export type Operator = ">=" | "<=" | ">" | "<" | "==";
export type LogicOperator = "AND" | "OR";
export type OutputType = "boolean" | "range" | "masked";

export interface LeafPolicy {
  field: string;
  operator: Operator;
  value: number;
  outputType?: OutputType;
}

export interface CompositePolicy {
  operator: LogicOperator;
  policies: Policy[];
}

export type Policy = LeafPolicy | CompositePolicy;

export interface EvaluationResult {
  result: boolean | string;
  outputType: OutputType;
  evaluated: number;
}

// ── Internal helpers ──────────────────────────────────────────────────────────

const COMPARATORS: Record<Operator, (a: number, b: number) => boolean> = {
  ">=": (a, b) => a >= b,
  "<=": (a, b) => a <= b,
  ">":  (a, b) => a > b,
  "<":  (a, b) => a < b,
  "==": (a, b) => a === b,
};

const SALARY_BRACKETS: { max: number; label: string }[] = [
  { max: 50_000,  label: "0–50k" },
  { max: 100_000, label: "50k–100k" },
  { max: 250_000, label: "100k–250k" },
];

function salaryRange(value: number): string {
  for (const b of SALARY_BRACKETS) {
    if (value <= b.max) return b.label;
  }
  return "250k+";
}

function maskValue(value: number): string {
  const s = String(Math.floor(value));
  return s[0] + "*".repeat(s.length - 1);
}

function evaluateBooleanLeaf(policy: LeafPolicy, input: Record<string, unknown>): boolean {
  const raw = input[policy.field];
  if (typeof raw !== "number") return false;
  return COMPARATORS[policy.operator](raw, policy.value);
}

function evaluateComposite(
  policy: CompositePolicy,
  input: Record<string, unknown>
): { result: boolean; evaluated: number } {
  let result = policy.operator === "AND";
  let evaluated = 0;
  for (const child of policy.policies) {
    let childResult: boolean;
    if ("policies" in child) {
      const r = evaluateComposite(child, input);
      childResult = r.result;
      evaluated += r.evaluated;
    } else {
      childResult = evaluateBooleanLeaf(child, input);
      evaluated += 1;
    }
    result = policy.operator === "AND" ? result && childResult : result || childResult;
  }
  return { result, evaluated };
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Evaluate a disclosure policy against a plaintext input record.
 *
 * Synchronous and pure — no I/O, no crypto, no runtime dependencies.
 * Safe to call inside any confidential compute environment (MXE, TEE, WASM, Node, browser).
 */
export function evaluatePolicy(
  policy: Policy,
  input: Record<string, unknown>
): EvaluationResult {
  if ("policies" in policy) {
    const { result, evaluated } = evaluateComposite(policy, input);
    return { result, outputType: "boolean", evaluated };
  }

  const raw = input[policy.field];
  if (typeof raw !== "number") return { result: false, outputType: "boolean", evaluated: 1 };

  const outputType = policy.outputType ?? "boolean";

  if (outputType === "range")  return { result: salaryRange(raw), outputType: "range",  evaluated: 1 };
  if (outputType === "masked") return { result: maskValue(raw),   outputType: "masked", evaluated: 1 };
  return { result: COMPARATORS[policy.operator](raw, policy.value), outputType: "boolean", evaluated: 1 };
}

/**
 * Produce the canonical JSON representation of a policy (sorted keys, no whitespace).
 * Deterministic across all runtimes — suitable as hash pre-image for commitment schemes.
 */
export function canonicalJSON(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + (value as unknown[]).map(canonicalJSON).join(",") + "]";
  const obj = value as Record<string, unknown>;
  return "{" + Object.keys(obj).sort().map(k => JSON.stringify(k) + ":" + canonicalJSON(obj[k])).join(",") + "}";
}

/**
 * Hash a policy using caller-supplied crypto.
 *
 * `hashFn` receives the canonical JSON string and must return a hex-encoded SHA-256 digest.
 * This keeps the SDK free of runtime-specific crypto imports — inject whichever
 * implementation is available in the target environment:
 *
 *   // Node.js
 *   import { createHash } from "node:crypto";
 *   const hash = await hashPolicy(policy, d => Promise.resolve(createHash("sha256").update(d).digest("hex")));
 *
 *   // Browser / edge
 *   const hash = await hashPolicy(policy, async d => {
 *     const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(d));
 *     return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
 *   });
 */
export async function hashPolicy(
  policy: Policy,
  hashFn: (data: string) => Promise<string>
): Promise<string> {
  return hashFn(canonicalJSON(policy));
}
