"use client";

import { useState } from "react";

type Operator = ">=" | "<=" | ">" | "<" | "==";

interface PolicyOption {
  label: string;
  field: string;
  operator: Operator;
  value: number;
}

const POLICIES: PolicyOption[] = [
  { label: "Age ≥ 18",        field: "age",    operator: ">=", value: 18 },
  { label: "Age ≥ 21",        field: "age",    operator: ">=", value: 21 },
  { label: "Salary > 50,000",  field: "salary", operator: ">",  value: 50000 },
  { label: "Salary > 100,000", field: "salary", operator: ">",  value: 100000 },
];

export default function Home() {
  const [age, setAge]               = useState("");
  const [salary, setSalary]         = useState("");
  const [policyIdx, setPolicyIdx]   = useState(0);
  const [result, setResult]         = useState<boolean | null>(null);
  const [loading, setLoading]       = useState(false);
  const [error, setError]           = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setResult(null);

    const { field, operator, value } = POLICIES[policyIdx];

    try {
      const res = await fetch("http://localhost:4000/policy/evaluate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          policy: { field, operator, value },
          input: { age: Number(age), salary: Number(salary) },
        }),
      });

      if (!res.ok) throw new Error(`Server responded with ${res.status}`);

      const data = await res.json();
      setResult(data.result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Request failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="min-h-screen bg-zinc-50 flex items-center justify-center p-6">
      <div className="w-full max-w-sm bg-white rounded-2xl border border-zinc-200 shadow-sm p-8">
        <h1 className="text-lg font-semibold text-zinc-900 mb-6">
          Policy Evaluator
        </h1>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1">
            <label className="block text-sm font-medium text-zinc-700">
              Age
            </label>
            <input
              type="number"
              required
              min={0}
              value={age}
              onChange={(e) => setAge(e.target.value)}
              placeholder="e.g. 25"
              className="w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm text-zinc-900 placeholder:text-zinc-400 focus:outline-none focus:ring-2 focus:ring-zinc-900"
            />
          </div>

          <div className="space-y-1">
            <label className="block text-sm font-medium text-zinc-700">
              Salary
            </label>
            <input
              type="number"
              required
              min={0}
              value={salary}
              onChange={(e) => setSalary(e.target.value)}
              placeholder="e.g. 60000"
              className="w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm text-zinc-900 placeholder:text-zinc-400 focus:outline-none focus:ring-2 focus:ring-zinc-900"
            />
          </div>

          <div className="space-y-1">
            <label className="block text-sm font-medium text-zinc-700">
              Policy
            </label>
            <select
              value={policyIdx}
              onChange={(e) => setPolicyIdx(Number(e.target.value))}
              className="w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 text-sm text-zinc-900 focus:outline-none focus:ring-2 focus:ring-zinc-900"
            >
              {POLICIES.map((p, i) => (
                <option key={i} value={i}>
                  {p.label}
                </option>
              ))}
            </select>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-zinc-700 disabled:opacity-50"
          >
            {loading ? "Evaluating…" : "Evaluate"}
          </button>
        </form>

        {error && (
          <p className="mt-6 text-sm text-red-500">{error}</p>
        )}

        {result !== null && error === null && (
          <div className="mt-8 flex flex-col items-center gap-1">
            <span className="text-5xl">{result ? "✅" : "❌"}</span>
            <span
              className={`text-2xl font-semibold ${
                result ? "text-green-600" : "text-red-600"
              }`}
            >
              {result ? "true" : "false"}
            </span>
          </div>
        )}
      </div>
    </main>
  );
}
