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
  input: z.record(z.number()),
});

policyRouter.post("/evaluate", async (req, res) => {
  const parsed = EvaluateSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() });
  }

  const { policy, input } = parsed.data;

  // Simulate client-side encryption: base64-encode each numeric field value
  // before handing it to the MXE compute boundary.
  const encryptedData: Record<string, string> = {};
  for (const [key, val] of Object.entries(input)) {
    encryptedData[key] = Buffer.from(String(val), "utf8").toString("base64");
  }

  const result = await runMxeCompute({ encryptedData, policy });
  return res.json(result);
});
