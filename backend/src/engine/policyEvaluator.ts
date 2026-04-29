export type Operator = ">=" | "<=" | ">" | "<" | "==";
export type LogicOperator = "AND" | "OR";

export interface LeafPolicy {
  field: string;
  operator: Operator;
  value: number;
}

export interface CompositePolicy {
  operator: LogicOperator;
  policies: Policy[];
}

export type Policy = LeafPolicy | CompositePolicy;

export interface EvaluationResult {
  result: boolean;
  evaluated: number; // count of leaf policies checked
}

const COMPARATORS: Record<Operator, (a: number, b: number) => boolean> = {
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
  if ("policies" in policy) {
    let result = policy.operator === "AND"; // AND starts true, OR starts false
    let evaluated = 0;
    for (const child of policy.policies) {
      const r = evaluatePolicy(child, input);
      evaluated += r.evaluated;
      result =
        policy.operator === "AND"
          ? result && r.result
          : result || r.result;
    }
    return { result, evaluated };
  }

  const raw = input[policy.field];
  if (typeof raw !== "number") return { result: false, evaluated: 1 };
  return { result: COMPARATORS[policy.operator](raw, policy.value), evaluated: 1 };
}
