// Production: replace runMxeCompute with the Arcium SDK's confidential compute invocation,
// passing encryptedData as encrypted circuit inputs and policy as public program arguments.

export interface MxeComputeInput {
  encryptedData: Record<string, string>; // base64-encoded field values (simulates client-side encryption)
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
  const { encryptedData, policy } = input;

  // Decrypt inside MXE: decode each base64 value back to a number.
  const decrypted: Record<string, number> = {};
  for (const [key, encoded] of Object.entries(encryptedData)) {
    const decoded = Number(Buffer.from(encoded, "base64").toString("utf8"));
    if (isNaN(decoded)) throw new Error(`Field "${key}" did not decode to a number`);
    decrypted[key] = decoded;
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
