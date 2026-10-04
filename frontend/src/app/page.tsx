"use client";

import { useEffect, useRef, useState } from "react";
import { Briefcase, Landmark, Package, ScanSearch, ShieldAlert, TriangleAlert, Lock, Eye } from "lucide-react";
import type { Demo, Investigation } from "@/lib/types";
import InvestigationReport from "@/components/InvestigationReport";
import Scanning from "@/components/Scanning";

const DEMO_ICONS: Record<string, typeof Landmark> = { bank: Landmark, job: Briefcase, delivery: Package };
const MAX_CHARS = 10_000;

export default function Home() {
  const [demos, setDemos] = useState<Demo[]>([]);
  const [text, setText] = useState("");
  const [demoId, setDemoId] = useState<string | null>(null);
  const [phase, setPhase] = useState<"ops" | "scanning" | "report">("ops");
  const [result, setResult] = useState<Investigation | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [aiReady, setAiReady] = useState<boolean | null>(null);
  const topRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetch("/api/demos").then((r) => r.json()).then(setDemos).catch(() => setDemos([]));
    fetch("/api/health").then((r) => r.json()).then((h) => setAiReady(!!h.ai_configured)).catch(() => setAiReady(null));
  }, []);

  async function run(content: string, demo: string | null) {
    if (content.trim().length < 3) return;
    setError(null);
    setPhase("scanning");
    const minDelay = new Promise((r) => setTimeout(r, 2200)); // let the pipeline animation read
    try {
      const [res] = await Promise.all([
        fetch("/api/investigate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ content, demo_id: demo }),
        }),
        minDelay,
      ]);
      const data = await res.json();
      if (!res.ok) throw new Error(typeof data.detail === "string" ? data.detail : "Investigation failed");
      setResult(data);
      setPhase("report");
      window.scrollTo({ top: 0 });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Investigation failed");
      setPhase("ops");
    }
  }

  function loadDemo(d: Demo) {
    setText(d.content);
    setDemoId(d.id);
    run(d.content, d.id);
  }

  function reset() {
    setPhase("ops");
    setResult(null);
    setText("");
    setDemoId(null);
    window.scrollTo({ top: 0 });
  }

  return (
    <div ref={topRef} className="min-h-screen">
      <TopBar aiReady={aiReady} onHome={reset} opId={phase === "report" ? result?.operation_id : undefined} />

      {phase === "scanning" && <Scanning />}

      {phase === "report" && result && <InvestigationReport inv={result} onNew={reset} />}

      {phase === "ops" && (
        <main className="mx-auto max-w-5xl px-4 sm:px-6 pb-24 pt-14 sm:pt-20">
          <div className="rise">
            <div className="label flex items-center gap-2 text-brass">
              <span className="h-1.5 w-1.5 rounded-full bg-brass pulse-dot" /> Digital Threat Investigation
            </div>
            <h1 className="mt-4 font-mono text-4xl sm:text-6xl font-semibold tracking-tight text-ink-100">
              OPERATION<br />DEAD DROP
            </h1>
            <p className="mt-5 max-w-2xl text-lg text-ink-200">
              Something is targeting you. Hand over the evidence — we reconstruct the attack, expose how you&apos;re being
              manipulated, and tell you exactly what to do <span className="text-brass">before the heist lands.</span>
            </p>
          </div>

          <section className="panel mt-10 overflow-hidden rise" style={{ animationDelay: "80ms" }}>
            <div className="flex items-center justify-between border-b border-ink-700 px-4 py-2.5">
              <span className="label flex items-center gap-2"><Eye size={13} /> Evidence intake</span>
              <span className={`font-mono text-[11px] ${text.length > MAX_CHARS * 0.9 ? "text-high" : "text-ink-400"}`}>
                {text.length.toLocaleString()} / {MAX_CHARS.toLocaleString()}
              </span>
            </div>
            <textarea
              value={text}
              onChange={(e) => { setText(e.target.value.slice(0, MAX_CHARS)); setDemoId(null); }}
              onKeyDown={(e) => { if ((e.metaKey || e.ctrlKey) && e.key === "Enter") run(text, demoId); }}
              placeholder={"Paste the suspicious message, email (with headers if you have them), or URL…\n\nFrom: Security Team <alerts@your-bank-verify.com>\nYour account will be suspended within 24 hours…"}
              spellCheck={false}
              className="block h-64 w-full resize-y bg-ink-900 px-4 py-4 font-mono text-[13.5px] leading-relaxed text-ink-100 placeholder:text-ink-500 focus:outline-none"
            />
            <div className="flex flex-col gap-3 border-t border-ink-700 bg-ink-850 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
              <p className="flex items-center gap-2 text-xs text-ink-400">
                <Lock size={12} /> Links are analyzed statically. Nothing you paste is ever visited or executed.
              </p>
              <button
                onClick={() => run(text, demoId)}
                disabled={text.trim().length < 3}
                className="inline-flex items-center justify-center gap-2 rounded bg-brass px-5 py-2.5 font-mono text-sm font-semibold tracking-wider text-ink-950 transition hover:bg-[#e8b555] disabled:cursor-not-allowed disabled:opacity-40"
              >
                <ScanSearch size={16} /> INITIATE INVESTIGATION
              </button>
            </div>
          </section>

          {error && (
            <div className="mt-4 flex items-center gap-2 rounded border border-crit/40 bg-crit/10 px-4 py-3 text-sm text-red-200">
              <TriangleAlert size={16} /> {error}
            </div>
          )}

          <section className="mt-12 rise" style={{ animationDelay: "160ms" }}>
            <div className="label mb-4">Case files — live demo investigations</div>
            <div className="grid gap-3 sm:grid-cols-3">
              {demos.map((d) => {
                const Icon = DEMO_ICONS[d.id] ?? ShieldAlert;
                return (
                  <button
                    key={d.id}
                    onClick={() => loadDemo(d)}
                    className="group panel flex flex-col items-start p-4 text-left transition hover:border-brass/60 hover:bg-ink-850"
                  >
                    <div className="flex w-full items-center justify-between">
                      <Icon size={18} className="text-brass" />
                      <span className="font-mono text-[10px] tracking-widest text-ink-400 group-hover:text-brass">OPEN CASE →</span>
                    </div>
                    <div className="mt-4 font-mono text-sm font-semibold tracking-wider text-ink-100">{d.title.toUpperCase()}</div>
                    <div className="mt-1 text-[13px] text-ink-300">{d.subtitle}</div>
                  </button>
                );
              })}
              {demos.length === 0 && (
                <div className="panel col-span-full p-4 text-sm text-ink-400">Backend offline — start the API to load case files.</div>
              )}
            </div>
          </section>

          <section className="mt-16 grid gap-6 border-t border-ink-700 pt-10 sm:grid-cols-3 rise" style={{ animationDelay: "240ms" }}>
            {[
              ["01 · Forensics", "Deterministic engine extracts URLs, domains, senders and 11 classes of manipulation — no AI guesswork."],
              ["02 · Analysis", "An AI analyst interprets the evidence. Every claim is checked back against the artifact."],
              ["03 · Response", "A reconstruction of the attack, MITRE ATT&CK mapping, and concrete steps to protect yourself."],
            ].map(([h, b]) => (
              <div key={h}>
                <div className="font-mono text-xs font-semibold tracking-wider text-brass">{h}</div>
                <p className="mt-2 text-sm leading-relaxed text-ink-300">{b}</p>
              </div>
            ))}
          </section>
        </main>
      )}
    </div>
  );
}

function TopBar({ aiReady, onHome, opId }: { aiReady: boolean | null; onHome: () => void; opId?: string }) {
  return (
    <header className="sticky top-0 z-30 border-b border-ink-700 bg-ink-950/85 backdrop-blur">
      <div className="mx-auto flex h-12 max-w-6xl items-center justify-between px-4 sm:px-6">
        <button onClick={onHome} className="flex items-center gap-2.5 font-mono text-[13px] font-semibold tracking-[0.18em] text-ink-100">
          <span className="grid h-6 w-6 place-items-center rounded-sm border border-brass/60 text-brass">
            <ShieldAlert size={13} />
          </span>
          DEAD DROP
          {opId && <span className="hidden text-ink-400 sm:inline">/ {opId}</span>}
        </button>
        <div className="flex items-center gap-2 font-mono text-[11px] tracking-wider text-ink-300">
          <span className={`h-1.5 w-1.5 rounded-full ${aiReady ? "bg-safe" : aiReady === false ? "bg-med" : "bg-ink-500"}`} />
          {aiReady ? "AI ANALYST ONLINE" : aiReady === false ? "DETERMINISTIC MODE" : "CONNECTING"}
        </div>
      </div>
    </header>
  );
}
