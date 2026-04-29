# @sde/core

Drop this into any confidential compute environment — MXE, TEE, or local — and evaluate structured disclosure policies without modification.

The package is **runtime-agnostic**: no Node.js imports, no browser globals, no bundler assumptions. Every dependency on platform crypto is injected by the caller via the `hashFn` parameter on `hashPolicy`.

## Exports

| Export | Kind | Description |
|---|---|---|
| `evaluatePolicy` | `function` | Synchronous policy evaluator — pure TypeScript, no I/O |
| `hashPolicy` | `async function` | SHA-256 commitment of a policy's canonical JSON; caller supplies `hashFn` |
| `canonicalJSON` | `function` | Deterministic JSON serialiser (sorted keys, no whitespace) |
| `Policy` | `type` | Union of `LeafPolicy \| CompositePolicy` |
| `LeafPolicy` | `interface` | Single-field comparison policy |
| `CompositePolicy` | `interface` | Recursive AND / OR composition |
| `EvaluationResult` | `interface` | `{ result, outputType, evaluated }` |
| `OutputType` | `type` | `"boolean" \| "range" \| "masked"` |
| `Operator` | `type` | `">=" \| "<=" \| ">" \| "<" \| "=="` |
| `LogicOperator` | `type` | `"AND" \| "OR"` |

## Usage

### Node.js

```ts
import { createHash } from "node:crypto";
import { evaluatePolicy, hashPolicy } from "@sde/core";

const policy = { field: "age", operator: ">=" as const, value: 18 };
const result = evaluatePolicy(policy, { age: 25 });
// { result: true, outputType: "boolean", evaluated: 1 }

const hash = await hashPolicy(policy, data =>
  Promise.resolve(createHash("sha256").update(data).digest("hex"))
);
```

### Browser / edge

```ts
import { evaluatePolicy, hashPolicy } from "@sde/core";

const policy = { field: "salary", operator: ">" as const, value: 50_000, outputType: "range" as const };
const result = evaluatePolicy(policy, { salary: 75_000 });
// { result: "50k–100k", outputType: "range", evaluated: 1 }

const hash = await hashPolicy(policy, async data => {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
});
```

### Composite policy

```ts
import { evaluatePolicy } from "@sde/core";

const result = evaluatePolicy(
  {
    operator: "AND",
    policies: [
      { field: "age",    operator: ">=", value: 18 },
      { field: "salary", operator: ">",  value: 50_000 },
    ],
  },
  { age: 22, salary: 80_000 }
);
// { result: true, outputType: "boolean", evaluated: 2 }
```

## Output types

| `outputType` | Input field | Returned `result` |
|---|---|---|
| `"boolean"` (default) | any | `true` or `false` |
| `"range"` | salary | bracket string: `"0–50k"`, `"50k–100k"`, `"100k–250k"`, `"250k+"` |
| `"masked"` | any numeric | first digit + `*` per remaining digit: `25 → "2*"`, `60000 → "6****"` |

## Building

```bash
npm install
npm run build   # emits dist/ with .js + .d.ts
```
