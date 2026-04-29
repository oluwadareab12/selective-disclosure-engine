# Selective Disclosure Engine

Most privacy systems force a binary choice — reveal everything or reveal nothing. SDE introduces a third option: reveal only what a policy permits, computed inside an encrypted environment where even the executor never sees the raw data.

The engine accepts encrypted field values, evaluates a structured policy against them inside a simulated Arcium MXE node, and returns the minimum permissible output — a boolean, a salary bracket, or a masked value. No raw input ever exits the compute boundary.

## Problem it solves

Standard API-based eligibility checks require sending raw personal data to a server, which then stores, logs, or potentially leaks it. This engine inverts that model: the server receives only ciphertext and a policy, evaluates the policy inside a secure compute boundary, and returns the narrowest result the policy allows. No raw value ever appears in a server log, database, or network trace.

## Why Arcium

Traditional systems decrypt data before processing — the server that runs the check is a trust assumption. You are betting that every node in the pipeline handles your plaintext responsibly, keeps no logs, and is never compromised.

Arcium's MXE (Multi-party eXecution Environment) executes computation inside an encrypted enclave. The server that runs the code never sees the data it is computing on. There is no plaintext to leak, log, or subpoena.

SDE is designed specifically for this model:

- **Policies are data structures** passed into the MXE as arguments — not code that runs outside it
- **Inputs are encrypted client-side** with X25519 + HKDF-SHA-256 + AES-GCM-256 before transmission — the raw AES key is never sent over the wire
- **Only the policy result exits the enclave** — the output type is enforced structurally so raw values cannot be returned even by accident

> "The only thing that leaves the MXE is what the policy permits."

This model has direct applications where data minimisation is legally or commercially required:

| Use case | What gets disclosed | What stays private |
|---|---|---|
| KYC / age check | `age >= 18 → true` | Date of birth |
| Credit eligibility | `salary > 50,000 → true` | Exact salary |
| Salary bracket | `"50k–100k"` | Exact figure |
| Identity gate | `masked: "2*"` | Full value |

## What makes this a primitive

SDE is not an application — it is a composable building block for privacy-preserving data flows.

**`@sde/core` is runtime-agnostic.** The policy evaluator is pure TypeScript — no Node.js imports, no browser globals. Drop it into any MXE, TEE, WASM module, or edge function and it works without modification. Platform crypto is injected by the caller, not assumed by the library.

**Policies are JSON.** A policy is a plain JavaScript object — composable with `AND`/`OR`, serialisable, storable in a database or on-chain, and auditable by anyone without running code. The schema is validated with Zod at the API boundary; inside the enclave it is just data.

**Policy hash commitments make results verifiable.** Every evaluation returns a `policyHash` — a SHA-256 digest of the canonical policy JSON (sorted keys, no whitespace). In production this hash would be signed by the MXE node's attestation key, allowing any third party to verify that a specific result came from a specific policy without re-running the computation or learning anything about the inputs.

**Output minimisation is enforced at the type level.** `EvaluationResult.result` is typed as `boolean | string` — the three permitted output shapes. There is no field that could carry a raw numeric value. The type system makes accidental leakage a compile error.

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 1 — Input (frontend/)                                │
│  Next.js form. User enters age + salary. Browser generates  │
│  an ephemeral X25519 key pair, performs ECDH against the    │
│  MXE node's public key, derives an AES-GCM-256 key via      │
│  HKDF-SHA-256, and encrypts each field. The browser's       │
│  ephemeral public key is sent with the request — no raw     │
│  AES key or plaintext ever leaves the browser.              │
└────────────────────────┬────────────────────────────────────┘
                         │  POST /policy/evaluate
                         │  { policy, encryptedData, iv, clientPublicKey }
┌────────────────────────▼────────────────────────────────────┐
│  Layer 2 — Policy Engine (backend/)                         │
│  Express + TypeScript. Validates the request with Zod       │
│  (discriminated union: leaf operators vs AND/OR),           │
│  enforces the operator allow-list, and forwards the         │
│  encrypted payload to the MXE compute boundary unchanged.   │
└────────────────────────┬────────────────────────────────────┘
                         │  runMxeCompute(...)
┌────────────────────────▼────────────────────────────────────┐
│  Layer 3 — MXE Compute (mxe/)                               │
│  Simulates an Arcium MXE node. Performs ECDH with the       │
│  browser's ephemeral public key, derives the same AES key   │
│  via HKDF, decrypts the ciphertexts, and evaluates the      │
│  policy (supports recursive AND/OR composition). In         │
│  production this layer is replaced by a signed Arcium job   │
│  submission — see mxe/src/compute.ts.                       │
└────────────────────────┬────────────────────────────────────┘
                         │  { result, outputType, policyHash, evaluated, computedAt }
┌────────────────────────▼────────────────────────────────────┐
│  Layer 4 — Output (frontend/)                               │
│  Renders the permitted disclosure: boolean ✅/❌, salary    │
│  bracket badge, or masked value. Displays the policy hash   │
│  commitment. No raw field value is rendered at any point.   │
└─────────────────────────────────────────────────────────────┘
```

## SDK

`sdk/` is a standalone package (`@sde/core`) that exposes the policy engine as a runtime-agnostic primitive. Drop it into any confidential compute environment — MXE, TEE, or local — and evaluate structured disclosure policies without modification.

```ts
import { createHash } from "node:crypto";
import { evaluatePolicy, hashPolicy } from "@sde/core";

const policy = { field: "age", operator: ">=" as const, value: 18 };
const result = evaluatePolicy(policy, { age: 25 });
const hash   = await hashPolicy(policy, d => Promise.resolve(
  createHash("sha256").update(d).digest("hex")
));
```

See [`sdk/README.md`](sdk/README.md) for browser usage, composite policies, and output type examples.

## Running locally

**Backend** (policy engine + MXE simulation, port 4000):

```bash
cd backend
npm install
npm run dev
```

**Frontend** (Next.js, port 3000):

```bash
cd frontend
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000), fill in age and salary, pick a policy, and click Evaluate.

## Example request

```http
POST http://localhost:4000/policy/evaluate
Content-Type: application/json

{
  "policy": { "field": "age", "operator": ">=", "value": 18 },
  "encryptedData": {
    "age":    "a3F2...base64ciphertext...==",
    "salary": "zR9m...base64ciphertext...=="
  },
  "iv":              "dGhpcyBpcyBhbiBJVg==",
  "clientPublicKey": "x25519-ephemeral-pubkey-base64=="
}
```

Composite policy (AND):

```json
{
  "policy": {
    "operator": "AND",
    "policies": [
      { "field": "age",    "operator": ">=", "value": 18 },
      { "field": "salary", "operator": ">",  "value": 50000 }
    ]
  },
  "encryptedData": { "age": "...", "salary": "..." },
  "iv": "...",
  "clientPublicKey": "..."
}
```

## Example response

```json
{
  "result": true,
  "outputType": "boolean",
  "policyHash": "e3b0c44298fc1c149afb...a94d302d89",
  "evaluated": 2,
  "computedAt": "2026-04-29T14:23:01.042Z",
  "mxeSimulated": true
}
```

The response contains only the permitted disclosure, the output type, a policy commitment hash, the count of leaf policies checked, and a timestamp. No raw field value is ever returned.

## Deployment

The `frontend/` directory is a self-contained demo that can be deployed to Vercel without the backend. In demo mode the full X25519 key encapsulation and AES-GCM-256 encryption flow runs in the browser, and a local `mockMxeEvaluate` function simulates the MXE compute step (with a 600 ms delay) instead of calling the backend. A banner at the top of the page reads "Demo mode — MXE computation simulated in browser" so reviewers can see this immediately.

To deploy the frontend standalone:

```bash
cd frontend
npx vercel --prod
```

To run the full stack locally (frontend + backend), follow the steps in the **Running locally** section above.

## Plugging in the real Arcium SDK

Open `mxe/src/compute.ts`. The integration point is the `runMxeCompute` function. The comment block at the top of that file documents exactly what to replace:

- Swap the function body for `arcium.submitJob(...)` with the encrypted circuit inputs.
- Replace the plaintext `key` field with proper key encapsulation (ECIES / X25519) so the raw AES key never leaves the client.
- Update `MxeComputeOutput` to include the `outputCommitment` and `signature` fields the SDK returns for on-chain verification.

## Roadmap

- **Multi-party policy consensus** — require M-of-N MXE nodes to independently evaluate the same policy before a result is accepted; removes single-node trust
- **On-chain policy registry** — store policy hashes on-chain so verifiers can confirm which policy governed a disclosure without receiving the policy itself
- **ZK proof output mode** — wrap the MXE result in a zero-knowledge proof so the disclosed value (e.g. a salary bracket) can be verified without re-running the enclave computation
- **Arcium testnet integration** — replace the MXE simulation layer with a live Arcium job submission against the public testnet, producing a real signed attestation
