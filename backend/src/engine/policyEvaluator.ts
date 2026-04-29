export type Operator = ">=" | "<=" | ">" | "<" | "==";

export interface Policy {
  field: string;
  operator: Operator;
  value: number;
}

export interface EvaluationResult {
  result: boolean;
  field: string;
  operator: Operator;
}

const OPERATORS: Record<Operator, (a: number, b: number) => boolean> = {
  ">=": (a, b) => a >= b,
  "<=": (a, b) => a <= b,
  ">":  (a, b) => a > b,
  "<":  (a, b) => a < b,
  "==": (a, b) => a === b,
};

export function evaluatePolicy(
  policy: Policy,
  input: Record<string, unknown>
): EvaluationResult {
  const raw = input[policy.field];

  if (typeof raw !== "number") {
    return { result: false, field: policy.field, operator: policy.operator };
  }

  const result = OPERATORS[policy.operator](raw, policy.value);
  return { result, field: policy.field, operator: policy.operator };
}
