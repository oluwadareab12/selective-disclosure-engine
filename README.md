# Selective Disclosure Engine

A privacy-preserving policy evaluation system that lets a user prove a claim about their private data (e.g. "my age is ≥ 18") without ever revealing the underlying value to the server. Input fields are encrypted in the browser with AES-GCM-256 before leaving the client, passed as opaque ciphertexts to a policy engine, and decrypted only inside a simulated MXE (Multi-party eXecution Environment) node — designed to be backed by Arcium's confidential compute network in production.

## Problem it solves

Standard API-based eligibility checks require sending raw personal data to a server, which then stores, logs, or potentially leaks it. This engine inverts that model: the server receives only ciphertext and a policy, evaluates the policy inside a secure compute boundary, and returns a boolean result. No raw value ever appears in a server log, database, or network trace.

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
                         │  { result, evaluated, computedAt, mxeSimulated }
┌────────────────────────▼────────────────────────────────────┐
│  Layer 4 — Output (frontend/)                               │
│  Displays ✅ true or ❌ false and the policy count. No      │
│  raw field value is rendered at any point in the UI or      │
│  returned in any API response.                              │
└─────────────────────────────────────────────────────────────┘
```

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
  "evaluated": 2,
  "computedAt": "2026-04-29T14:23:01.042Z",
  "mxeSimulated": true
}
```

The response contains only the boolean outcome, the count of leaf policies checked, a timestamp, and the simulation flag. No raw field value is ever returned.

## Deployment

The `frontend/` directory is a self-contained demo that can be deployed to Vercel without the backend. In demo mode the full X25519 key encapsulation and AES-GCM-256 encryption flow runs in the browser, and a local `mockMxeEvaluate` function simulates the MXE compute step (with a 600 ms delay) instead of calling the backend. A banner at the top of the page reads "⚡ Demo mode — MXE computation simulated in browser" so reviewers can see this immediately.

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
