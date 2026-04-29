import { createHash } from "node:crypto";

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
  policyHash: string; // SHA-256 of canonical policy JSON (sorted keys, no whitespace)
  evaluated: number;
}

const COMPARATORS: Record<Operator, (a: number, b: number) => boolean> = {
  ">=": (a, b) => a >= b,
  "<=": (a, b) => a <= b,
  ">":  (a, b) => a > b,
  "<":  (a, b) => a < b,
  "==": (a, b) => a === b,
};

const SALARY_BRACKETS = [
  { max: 50_000,  label: "0–50k" },
  { max: 100_000, label: "50k–100k" },
  { max: 250_000, label: "100k–250k" },
];

function salaryRange(value: number): string {
  for (const bracket of SALARY_BRACKETS) {
    if (value <= bracket.max) return bracket.label;
  }
  return "250k+";
}

function maskValue(value: number): string {
  const s = String(Math.floor(value));
  return s[0] + "*".repeat(s.length - 1);
}

// Canonical JSON: sorted keys, no whitespace — deterministic across runtimes.
function canonicalJSON(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + (value as unknown[]).map(canonicalJSON).join(",") + "]";
  const obj = value as Record<string, unknown>;
  return "{" + Object.keys(obj).sort().map(k => JSON.stringify(k) + ":" + canonicalJSON(obj[k])).join(",") + "}";
}

function policyHashHex(policy: Policy): string {
  return createHash("sha256").update(canonicalJSON(policy)).digest("hex");
}

// Used internally for AND/OR composition — always returns a boolean regardless of outputType.
function evaluateBooleanLeaf(
  policy: LeafPolicy,
  input: Record<string, unknown>
): boolean {
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

export function evaluatePolicy(
  policy: Policy,
  input: Record<string, unknown>
): EvaluationResult {
  const policyHash = policyHashHex(policy);

  if ("policies" in policy) {
    const { result, evaluated } = evaluateComposite(policy, input);
    return { result, outputType: "boolean", policyHash, evaluated };
  }

  const raw = input[policy.field];
  if (typeof raw !== "number") return { result: false, outputType: "boolean", policyHash, evaluated: 1 };

  const outputType = policy.outputType ?? "boolean";

  if (outputType === "range") {
    return { result: salaryRange(raw), outputType: "range", policyHash, evaluated: 1 };
  }
  if (outputType === "masked") {
    return { result: maskValue(raw), outputType: "masked", policyHash, evaluated: 1 };
  }
  return { result: COMPARATORS[policy.operator](raw, policy.value), outputType: "boolean", policyHash, evaluated: 1 };
}
