import { Router } from "express";
import { z } from "zod";
import { evaluatePolicy } from "../engine/policyEvaluator";

export const policyRouter = Router();

const DisclosureRequestSchema = z.object({
  subjectId: z.string(),
  requestedFields: z.array(z.string()),
  context: z.record(z.unknown()).optional(),
});

policyRouter.post("/evaluate", async (req, res) => {
  const parsed = DisclosureRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() });
  }

  const result = await evaluatePolicy(parsed.data);
  return res.json(result);
});
