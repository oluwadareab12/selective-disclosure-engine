import { Router } from "express";
import { z } from "zod";
import { runMxeCompute } from "../../../mxe/src/compute";

export const policyRouter = Router();

const OPERATORS = [">=", "<=", ">", "<", "=="] as const;

const EvaluateSchema = z.object({
  policy: z.object({
    field: z.string(),
    operator: z.enum(OPERATORS),
    value: z.number(),
  }),
  encryptedData: z.record(z.string()),
  iv: z.string(),
  key: z.string(),
});

policyRouter.post("/evaluate", async (req, res) => {
  const parsed = EvaluateSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() });
  }

  const { policy, encryptedData, iv, key } = parsed.data;
  const result = await runMxeCompute({ encryptedData, iv, key, policy });
  return res.json(result);
});
