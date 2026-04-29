import { Router } from "express";
import { z } from "zod";
import { runMxeCompute, getMxePublicKey } from "../../../mxe/src/compute";

export const policyRouter = Router();

const LEAF_OPERATORS  = [">=", "<=", ">", "<", "=="] as const;
const LOGIC_OPERATORS = ["AND", "OR"] as const;

const LeafPolicySchema = z.object({
  field:      z.string(),
  operator:   z.enum(LEAF_OPERATORS),
  value:      z.number(),
  outputType: z.enum(["boolean", "range", "masked"]).optional(),
});

// Discriminated union: operator is the discriminant.
// Leaf operators (>=, <=, >, <, ==) and logic operators (AND, OR) are disjoint,
// so Zod can narrow the type unambiguously. z.lazy handles the recursive case.
const PolicySchema: z.ZodType<any> = z.lazy(() =>
  z.union([
    LeafPolicySchema,
    z.object({
      operator: z.enum(LOGIC_OPERATORS),
      policies: z.array(PolicySchema).min(2),
    }),
  ])
);

const EvaluateSchema = z.object({
  policy:          PolicySchema,
  encryptedData:   z.record(z.string()),
  iv:              z.string(),
  clientPublicKey: z.string(),
});

policyRouter.get("/mxe-pubkey", async (_req, res) => {
  const publicKey = await getMxePublicKey();
  return res.json({ publicKey });
});

policyRouter.post("/evaluate", async (req, res) => {
  const parsed = EvaluateSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() });
  }

  const { policy, encryptedData, iv, clientPublicKey } = parsed.data;
  const result = await runMxeCompute({ encryptedData, iv, clientPublicKey, policy });
  return res.json(result);
});
