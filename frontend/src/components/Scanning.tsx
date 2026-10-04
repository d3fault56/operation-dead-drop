"use client";

import { useEffect, useState } from "react";
import { Check } from "lucide-react";

const STEPS = [
  "Securing artifact",
  "Extracting indicators",
  "Static link forensics",
  "Impersonation checks",
  "Social-engineering scan",
  "AI analyst reviewing evidence",
  "Grounding claims against artifact",
];

export default function Scanning() {
  const [i, setI] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setI((x) => Math.min(x + 1, STEPS.length - 1)), 320);
    return () => clearInterval(t);
  }, []);
  return (
    <main className="mx-auto flex min-h-[70vh] max-w-md flex-col justify-center px-6" aria-live="polite">
      <div className="label text-brass">Investigation in progress</div>
      <div className="relative mt-4 h-px w-full overflow-hidden bg-ink-700">
        <div className="scanbar absolute inset-y-0 w-1/4 bg-brass" />
      </div>
      <ol className="mt-6 space-y-2.5 font-mono text-[13px]">
        {STEPS.map((s, n) => (
          <li key={s} className={`flex items-center gap-3 transition-opacity ${n > i ? "opacity-25" : "opacity-100"}`}>
            <span className={`grid h-4 w-4 place-items-center rounded-sm border ${n < i ? "border-safe/60 text-safe" : n === i ? "border-brass text-brass" : "border-ink-600"}`}>
              {n < i ? <Check size={10} /> : n === i ? <span className="h-1.5 w-1.5 rounded-full bg-brass pulse-dot" /> : null}
            </span>
            <span className={n === i ? "text-ink-100" : "text-ink-300"}>{s}</span>
          </li>
        ))}
      </ol>
    </main>
  );
}
