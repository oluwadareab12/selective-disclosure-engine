export interface MxeComputeInput {
  encryptedFields: Record<string, string>;
  policyHash: string;
}

export interface MxeComputeOutput {
  disclosedFields: Record<string, string>;
  proof: string;
}

// Stub for Arcium MXE confidential compute
export async function runMxeCompute(
  input: MxeComputeInput
): Promise<MxeComputeOutput> {
  throw new Error("MXE compute not yet implemented — wire up Arcium SDK here");
}
