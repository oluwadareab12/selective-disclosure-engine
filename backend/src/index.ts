import express from "express";
import { policyRouter } from "./routes/policy";

const app = express();
const PORT = process.env.PORT ?? 4000;

app.use(express.json());
app.use("/policy", policyRouter);

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.listen(PORT, () => {
  console.log(`Policy engine running on port ${PORT}`);
});
