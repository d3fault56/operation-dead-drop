"use client";

import { useMemo, useState } from "react";
import {
  Activity, AtSign, Check, ChevronRight, Copy, Cpu, Crosshair, Download, FileSearch, Globe, Info, Link2,
  Phone, RotateCcw, ShieldCheck, Siren, Target, TriangleAlert, UserX,
} from "lucide-react";
import type { Investigation, Severity, ThreatLevel } from "@/lib/types";

const LEVEL: Record<ThreatLevel, { text: string; bg: string; border: string; hex: string }> = {
  CRITICAL: { text: "text-crit", bg: "bg-crit", border: "border-crit/50", hex: "#ef4444" },
  HIGH: { text: "text-high", bg: "bg-high", border: "border-high/50", hex: "#f97316" },
  MEDIUM: { text: "text-med", bg: "bg-med", border: "border-med/50", hex: "#eab308" },
  LOW: { text: "text-low", bg: "bg-low", border: "border-low/50", hex: "#38bdf8" },
  BENIGN: { text: "text-safe", bg: "bg-safe", border: "border-safe/50", hex: "#34d399" },
};
const SEV: Record<Severity, string> = {
  critical: "text-crit border-crit/40 bg-crit/10",
  high: "text-high border-high/40 bg-high/10",
  medium: "text-med border-med/40 bg-med/10",
  low: "text-low border-low/40 bg-low/10",
  info: "text-ink-300 border-ink-600 bg-ink-800",
};

export const defang = (s: string) => s.replace(/^http/i, "hxxp").replace(/\./g, "[.]").replace(/@/g, "[@]");

function Section({ n, title, icon: Icon, children, className = "", delay = 0 }: {
  n: string; title: string; icon: typeof Info; children: React.ReactNode; className?: string; delay?: number;
}) {
  return (
    <section className={`rise ${className}`} style={{ animationDelay: `${delay}ms` }}>
      <div className="mb-3 flex items-center gap-3">
        <span className="font-mono text-[11px] text-brass">{n}</span>
        <Icon size={14} className="text-ink-300" />
        <h2 className="label !text-ink-200">{title}</h2>
        <div className="h-px flex-1 bg-ink-700" />
      </div>
      {children}
    </section>
  );
}

export default function InvestigationReport({ inv, onNew }: { inv: Investigation; onNew: () => void }) {
  const lv = LEVEL[inv.threat_level];
  const benign = inv.threat_level === "BENIGN" || inv.threat_level === "LOW";
  const ts = new Date(inv.timestamp);

  function exportJson() {
    const blob = new Blob([JSON.stringify(inv, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `operation-${inv.operation_id}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  return (
    <main className="mx-auto max-w-6xl px-4 sm:px-6 pb-24 pt-8">
      {/* ── case header ───────────────────────────── */}
      <div className="rise flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div className="label">Case file · {inv.input_type} artifact</div>
          <h1 className="mt-1 font-mono text-3xl sm:text-4xl font-semibold tracking-tight">
            OPERATION <span className="text-brass">{inv.operation_id}</span>
          </h1>
          <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[11px] text-ink-400">
            <span>OPENED {ts.toLocaleString()}</span>
            <span>ANALYZED IN {inv.duration_ms < 1000 ? `${inv.duration_ms}ms` : `${(inv.duration_ms / 1000).toFixed(1)}s`}</span>
            <span className="flex items-center gap-1.5">
              <Cpu size={11} /> {inv.engine === "claude" ? `AI ANALYST · ${inv.model}` : "DETERMINISTIC ANALYST"}
            </span>
          </div>
        </div>
        <div className="flex gap-2">
          <button onClick={exportJson} className="inline-flex items-center gap-2 rounded border border-ink-600 px-3 py-2 font-mono text-xs text-ink-200 hover:border-ink-400">
            <Download size={13} /> EXPORT
          </button>
          <button onClick={onNew} className="inline-flex items-center gap-2 rounded border border-ink-600 px-3 py-2 font-mono text-xs text-ink-200 hover:border-ink-400">
            <RotateCcw size={13} /> NEW CASE
          </button>
        </div>
      </div>

      {/* ── verdict strip ───────────────────────────── */}
      <div className={`rise panel mt-6 grid overflow-hidden sm:grid-cols-[1.2fr_1fr_1.4fr_0.9fr] ${lv.border}`} style={{ animationDelay: "60ms" }}>
        <div className="relative border-b border-ink-700 p-5 sm:border-b-0 sm:border-r">
          <div className={`absolute inset-y-0 left-0 w-1 ${lv.bg}`} />
          <div className="label">Threat level</div>
          <div className={`mt-2 flex items-center gap-2 font-mono text-3xl font-semibold tracking-wider ${lv.text}`}>
            {!benign && <Siren size={24} />} {inv.threat_level}
          </div>
        </div>
        <div className="border-b border-ink-700 p-5 sm:border-b-0 sm:border-r">
          <div className="label">Confidence</div>
          <div className="mt-2 font-mono text-3xl font-semibold">{inv.confidence}<span className="text-lg text-ink-400">%</span></div>
          <div className="mt-2 h-1 w-full bg-ink-700"><div className={`h-1 ${lv.bg}`} style={{ width: `${inv.confidence}%` }} /></div>
          <div className="mt-1.5 text-[11px] text-ink-400">in classification — not proof of malice</div>
        </div>
        <div className="border-b border-ink-700 p-5 sm:border-b-0 sm:border-r">
          <div className="label">Attack type</div>
          <div className="mt-2 font-mono text-xl font-semibold uppercase leading-tight tracking-wide">{inv.attack_type}</div>
        </div>
        <div className="p-5">
          <div className="label">Signal score</div>
          <div className="mt-2 font-mono text-3xl font-semibold">{inv.deterministic.risk_score}<span className="text-lg text-ink-400">/100</span></div>
          <div className="mt-1.5 text-[11px] text-ink-400">{inv.deterministic.findings.length} deterministic findings</div>
        </div>
      </div>

      {/* ── summary + objective + artifact ───────────────── */}
      <div className="mt-10 grid gap-8 lg:grid-cols-[1fr_1.05fr]">
        <div className="space-y-8">
          <Section n="01" title="Attack summary" icon={FileSearch} delay={120}>
            <p className="text-[15px] leading-relaxed text-ink-100">{inv.summary}</p>
          </Section>
          <Section n="02" title="Attacker objective" icon={Target} delay={160}>
            <div className="panel flex gap-3 border-l-2 !border-l-brass p-4">
              <Crosshair size={18} className="mt-0.5 shrink-0 text-brass" />
              <p className="text-[15px] leading-relaxed">{inv.attacker_objective}</p>
            </div>
          </Section>
          {inv.social_engineering_tactics.length > 0 && (
            <Section n="03" title="How you're being manipulated" icon={UserX} delay={200}>
              <div className="space-y-3">
                {inv.social_engineering_tactics.map((t, i) => (
                  <div key={i} className="panel p-4">
                    <div className="font-mono text-xs font-semibold uppercase tracking-wider text-high">{t.tactic}</div>
                    <blockquote className="mt-2 border-l border-ink-500 pl-3 font-mono text-[12.5px] text-ink-200">&ldquo;{t.quote}&rdquo;</blockquote>
                    <p className="mt-2 text-sm text-ink-300">{t.explanation}</p>
                  </div>
                ))}
              </div>
            </Section>
          )}
        </div>
        <Section n="04" title="Seized artifact — annotated" icon={FileSearch} delay={160}>
          <ArtifactViewer inv={inv} />
        </Section>
      </div>

      {/* ── heist reconstruction ───────────────────────── */}
      <Section n="05" title="Heist reconstruction" icon={Activity} className="mt-14" delay={220}>
        <AttackChain inv={inv} />
      </Section>

      {/* ── evidence ───────────────────────── */}
      <Section n="06" title="Evidence board" icon={TriangleAlert} className="mt-14" delay={260}>
        {inv.evidence.length === 0 ? (
          <div className="panel p-4 text-sm text-ink-300">No significant threat evidence was found in this artifact.</div>
        ) : (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {inv.evidence.map((e, i) => (
              <div key={i} className="panel flex flex-col p-4 rise" style={{ animationDelay: `${300 + i * 50}ms` }}>
                <div className="flex items-start justify-between gap-2">
                  <span className="font-mono text-[11px] font-semibold tracking-wider text-ink-100">{e.label.toUpperCase()}</span>
                  <span className={`shrink-0 rounded-sm border px-1.5 py-0.5 font-mono text-[9.5px] uppercase tracking-wider ${SEV[e.severity]}`}>{e.severity}</span>
                </div>
                <div className="mt-2.5 break-all rounded-sm bg-ink-950 px-2 py-1.5 font-mono text-[12px] text-ink-200 line-clamp-3">{e.value}</div>
                <p className="mt-2.5 flex-1 text-[13px] leading-snug text-ink-300">{e.explanation}</p>
                <div className="mt-3 font-mono text-[10px] tracking-wider">
                  {e.basis === "observed"
                    ? <span className="text-safe">● OBSERVED IN ARTIFACT</span>
                    : <span className="text-ink-400">◌ ANALYST INFERENCE</span>}
                </div>
              </div>
            ))}
          </div>
        )}
      </Section>

      {/* ── timeline + mitre ───────────────────────── */}
      <div className="mt-14 grid gap-8 lg:grid-cols-2">
        <Section n="07" title="Investigation timeline" icon={Activity} delay={300}>
          <ol className="panel relative p-5">
            {inv.timeline.map((t, i) => (
              <li key={i} className="relative flex gap-4 pb-4 last:pb-0">
                {i < inv.timeline.length - 1 && <span className="absolute left-[54px] top-4 h-full w-px bg-ink-700" />}
                <span className="w-11 shrink-0 pt-px text-right font-mono text-[11px] text-ink-400">+{t.t_ms}ms</span>
                <span className={`relative z-10 mt-1 h-2.5 w-2.5 shrink-0 rounded-full border ${i === inv.timeline.length - 1 ? "border-safe bg-safe" : "border-brass bg-ink-900"}`} />
                <div className="min-w-0">
                  <div className="text-sm text-ink-100">{t.event}</div>
                  {t.detail && <div className="font-mono text-[11.5px] text-ink-400 break-words">{t.detail}</div>}
                </div>
              </li>
            ))}
          </ol>
          <p className="mt-2 text-[11px] text-ink-500">Offsets are measured from this investigation&apos;s actual processing pipeline.</p>
        </Section>

        <Section n="08" title="MITRE ATT&CK mapping" icon={Crosshair} delay={340}>
          {inv.mitre_techniques.length === 0 ? (
            <div className="panel p-4 text-sm text-ink-300">No ATT&amp;CK techniques apply to this artifact.</div>
          ) : (
            <div className="space-y-3">
              {inv.mitre_techniques.map((m) => (
                <a key={m.id} href={`https://attack.mitre.org/techniques/${m.id.replace(".", "/")}/`} target="_blank" rel="noopener noreferrer"
                   className="panel group block p-4 transition hover:border-ink-500">
                  <div className="flex items-baseline justify-between gap-3">
                    <span className="font-mono text-lg font-semibold text-brass">{m.id}</span>
                    <span className="font-mono text-[10px] uppercase tracking-wider text-ink-400">{m.tactic}</span>
                  </div>
                  <div className="mt-0.5 text-sm font-medium text-ink-100">{m.name}</div>
                  <p className="mt-1.5 text-[13px] text-ink-300">{m.relevance}</p>
                </a>
              ))}
            </div>
          )}
        </Section>
      </div>

      {/* ── indicators ───────────────────────── */}
      <Section n="09" title="Indicators of compromise" icon={Globe} className="mt-14" delay={360}>
        <IOCTable inv={inv} />
      </Section>

      {/* ── save the victim ───────────────────────── */}
      <Section n="10" title="Save the victim" icon={ShieldCheck} className="mt-14" delay={380}>
        <SaveTheVictim inv={inv} />
      </Section>

      {/* ── analyst notes ───────────────────────── */}
      <div className="mt-10 panel flex gap-3 p-4 text-[13px] text-ink-300">
        <Info size={16} className="mt-0.5 shrink-0 text-ink-400" />
        <div className="space-y-1.5">
          <p>{inv.analyst_notes}</p>
          <p className="text-ink-400">No external threat-intelligence lookups were performed and no links were visited. Domain assessments are based on static analysis only.</p>
          {inv.grounding_corrections.length > 0 && (
            <p className="text-med">Grounding check discarded {inv.grounding_corrections.length} AI claim(s) that could not be traced to the artifact.</p>
          )}
          {inv.ai_error && <p className="text-ink-400">AI analyst unavailable ({inv.ai_error}); deterministic analyst produced this report.</p>}
        </div>
      </div>

      {/* ── threat contained ───────────────────────── */}
      <div className="mt-14 flex flex-col items-center text-center">
        <div className={`stamp rounded border-2 px-6 py-3 font-mono text-2xl sm:text-3xl font-semibold tracking-[0.2em] ${benign ? "border-safe text-safe" : "border-safe text-safe"}`}>
          {benign ? "CASE CLOSED" : "THREAT CONTAINED"}
        </div>
        <p className="mt-5 max-w-md text-sm text-ink-300">
          Operation {inv.operation_id} has been analyzed. {benign ? "No active heist detected." : "The heist has been exposed — follow the steps above and it fails."}
        </p>
        <button onClick={onNew} className="mt-6 inline-flex items-center gap-2 rounded bg-brass px-5 py-2.5 font-mono text-sm font-semibold tracking-wider text-ink-950 hover:bg-[#e8b555]">
          OPEN NEW CASE <ChevronRight size={15} />
        </button>
      </div>
    </main>
  );
}

/* ── Attack chain ─────────────────────────── */
function AttackChain({ inv }: { inv: Investigation }) {
  const chain = inv.attack_chain;
  const style = (s: string) =>
    s === "potential_impact"
      ? { box: "border-crit/70 bg-crit/10", txt: "text-crit", tag: "IMPACT" }
      : s === "observed"
      ? { box: "border-brass/60 bg-ink-850", txt: "text-brass", tag: "OBSERVED" }
      : { box: "border-dashed border-ink-500 bg-ink-900", txt: "text-ink-200", tag: "INFERRED" };
  return (
    <div className="panel p-5">
      <div className="flex flex-col lg:flex-row lg:items-stretch">
        {chain.map((c, i) => {
          const st = style(c.status);
          return (
            <div key={i} className="flex flex-col lg:flex-1 lg:flex-row lg:items-stretch rise" style={{ animationDelay: `${260 + i * 130}ms` }}>
              <div className={`flex flex-col rounded border p-3 lg:flex-1 ${st.box}`}>
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[10px] text-ink-400">{String(i + 1).padStart(2, "0")}</span>
                  <span className={`font-mono text-[8.5px] tracking-widest ${st.txt} opacity-80`}>{st.tag}</span>
                </div>
                <div className={`mt-2 font-mono text-[12.5px] font-semibold uppercase leading-tight tracking-wide ${st.txt}`}>{c.stage}</div>
                <p className="mt-1.5 text-[12px] leading-snug text-ink-300">{c.detail}</p>
              </div>
              {i < chain.length - 1 && (
                <div className="flex h-6 shrink-0 items-center justify-center text-ink-500 lg:h-auto lg:w-6"><ChevronRight size={16} className="rotate-90 lg:rotate-0" /></div>
              )}
            </div>
          );
        })}
      </div>
      <div className="mt-4 flex flex-wrap gap-4 font-mono text-[10px] tracking-wider text-ink-400">
        <span><span className="mr-1.5 inline-block h-2 w-3 border border-brass/60 align-middle" />OBSERVED</span>
        <span><span className="mr-1.5 inline-block h-2 w-3 border border-dashed border-ink-500 align-middle" />INFERRED</span>
        <span><span className="mr-1.5 inline-block h-2 w-3 border border-crit/70 bg-crit/10 align-middle" />POTENTIAL IMPACT</span>
      </div>
    </div>
  );
}

/* ── Annotated artifact (React-escaped; never injects HTML) ─────────────── */
type Mark = { start: number; end: number; kind: "link" | "contact" | "tactic"; note: string };

function ArtifactViewer({ inv }: { inv: Investigation }) {
  const text = inv.artifact;
  const segments = useMemo(() => {
    const lower = text.toLowerCase();
    const terms: { s: string; kind: Mark["kind"]; note: string }[] = [];
    const ind = inv.deterministic.indicators;
    for (const f of inv.deterministic.findings) {
      if (f.category === "social_engineering") terms.push({ s: f.evidence.replace(/^…|…$/g, ""), kind: "tactic", note: f.indicator });
    }
    for (const t of inv.social_engineering_tactics) terms.push({ s: t.quote, kind: "tactic", note: t.tactic });
    for (const e of ind.emails) terms.push({ s: e, kind: "contact", note: "Email address" });
    for (const p of ind.phone_numbers) terms.push({ s: p, kind: "contact", note: "Phone number" });
    for (const u of ind.urls) terms.push({ s: u.replace(/^http:\/\//, ""), kind: "link", note: "Link — not visited" });
    const marks: Mark[] = [];
    // links/contacts first so they win overlaps with tactic sentences
    const order = { link: 0, contact: 1, tactic: 2 };
    terms.sort((a, b) => order[a.kind] - order[b.kind]);
    for (const t of terms) {
      const needle = t.s.trim().toLowerCase();
      if (needle.length < 4) continue;
      let idx = lower.indexOf(needle);
      while (idx !== -1) {
        const end = idx + needle.length;
        if (t.kind === "tactic") {
          // tactic marks may contain links; split around existing marks
          let cur = idx;
          const inside = marks.filter((m) => m.start < end && m.end > idx).sort((a, b) => a.start - b.start);
          if (inside.some((m) => m.kind === "tactic")) { idx = lower.indexOf(needle, end); continue; }
          for (const m of inside) { if (m.start > cur) marks.push({ start: cur, end: m.start, kind: "tactic", note: t.note }); cur = Math.max(cur, m.end); }
          if (cur < end) marks.push({ start: cur, end, kind: "tactic", note: t.note });
        } else if (!marks.some((m) => m.start < end && m.end > idx)) {
          marks.push({ start: idx, end, kind: t.kind, note: t.note });
        }
        idx = lower.indexOf(needle, end);
      }
    }
    marks.sort((a, b) => a.start - b.start);
    const out: { text: string; mark?: Mark }[] = [];
    let pos = 0;
    for (const m of marks) {
      if (m.start < pos) continue;
      if (m.start > pos) out.push({ text: text.slice(pos, m.start) });
      out.push({ text: text.slice(m.start, m.end), mark: m });
      pos = m.end;
    }
    if (pos < text.length) out.push({ text: text.slice(pos) });
    return out;
  }, [inv, text]);

  const cls = { link: "bg-crit/20 text-red-200 underline decoration-crit/60 decoration-dotted underline-offset-2", contact: "bg-low/15 text-sky-200", tactic: "bg-brass/15 text-amber-100" };
  return (
    <div className="panel overflow-hidden">
      <div className="flex flex-wrap gap-4 border-b border-ink-700 px-4 py-2 font-mono text-[10px] tracking-wider text-ink-400">
        <span><span className="mr-1.5 inline-block h-2 w-2 bg-crit/50 align-middle" />LINK</span>
        <span><span className="mr-1.5 inline-block h-2 w-2 bg-low/40 align-middle" />CONTACT</span>
        <span><span className="mr-1.5 inline-block h-2 w-2 bg-brass/40 align-middle" />MANIPULATION</span>
      </div>
      <pre className="max-h-[560px] overflow-auto whitespace-pre-wrap break-words p-4 font-mono text-[12.5px] leading-relaxed text-ink-300">
        {segments.map((s, i) =>
          s.mark ? <mark key={i} title={s.mark.note} className={`rounded-[2px] px-0.5 ${cls[s.mark.kind]}`}>{s.text}</mark> : <span key={i}>{s.text}</span>
        )}
      </pre>
    </div>
  );
}

/* ── IOC table ─────────────────────────── */
function IOCTable({ inv }: { inv: Investigation }) {
  const ind = inv.deterministic.indicators;
  const rows: { type: string; icon: typeof Link2; value: string }[] = [
    ...ind.urls.map((v) => ({ type: "URL", icon: Link2, value: v })),
    ...ind.domains.map((v) => ({ type: "DOMAIN", icon: Globe, value: v })),
    ...ind.ip_addresses.map((v) => ({ type: "IP", icon: Globe, value: v })),
    ...ind.emails.map((v) => ({ type: "EMAIL", icon: AtSign, value: v })),
    ...ind.phone_numbers.map((v) => ({ type: "PHONE", icon: Phone, value: v })),
  ];
  const [copied, setCopied] = useState<number | null>(null);
  if (!rows.length)
    return <div className="panel p-4 text-sm text-ink-300">No network or contact indicators were present. {ind.brands.length > 0 && `Brands referenced: ${ind.brands.join(", ")}.`}</div>;
  return (
    <div className="panel overflow-hidden">
      <table className="w-full text-left">
        <thead>
          <tr className="border-b border-ink-700 bg-ink-850">
            <th className="label px-4 py-2 font-normal">Type</th>
            <th className="label px-4 py-2 font-normal">Value (defanged)</th>
            <th className="w-12" />
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i} className="border-b border-ink-800 last:border-0">
              <td className="whitespace-nowrap px-4 py-2.5 font-mono text-[11px] text-ink-400"><r.icon size={12} className="mr-2 inline" />{r.type}</td>
              <td className="break-all px-4 py-2.5 font-mono text-[12.5px] text-ink-200">{defang(r.value)}</td>
              <td className="px-2">
                <button aria-label="Copy defanged indicator" onClick={() => { navigator.clipboard?.writeText(defang(r.value)); setCopied(i); setTimeout(() => setCopied(null), 1200); }}
                  className="grid h-7 w-7 place-items-center rounded text-ink-400 hover:bg-ink-800 hover:text-ink-100">
                  {copied === i ? <Check size={13} className="text-safe" /> : <Copy size={13} />}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {ind.brands.length > 0 && (
        <div className="border-t border-ink-700 px-4 py-2.5 font-mono text-[11px] text-ink-400">BRANDS REFERENCED: <span className="text-ink-200">{ind.brands.join(" · ")}</span></div>
      )}
    </div>
  );
}

/* ── Save the victim ─────────────────────────── */
function SaveTheVictim({ inv }: { inv: Investigation }) {
  const groups: { key: "immediate" | "if_exposed" | "preventive"; title: string; sub: string; accent: string }[] = [
    { key: "immediate", title: "Do this now", sub: "Before anything else", accent: "border-crit/60 text-crit" },
    { key: "if_exposed", title: "If you already engaged", sub: "Clicked, replied, paid, or shared info", accent: "border-high/60 text-high" },
    { key: "preventive", title: "Stop the next one", sub: "Harden & report", accent: "border-safe/60 text-safe" },
  ];
  return (
    <div className="grid gap-4 lg:grid-cols-3">
      {groups.map((g) => {
        const items = inv.recommended_actions.filter((a) => a.priority === g.key);
        if (!items.length) return null;
        return (
          <div key={g.key} className={`panel border-t-2 p-5 ${g.accent.split(" ")[0]}`}>
            <div className={`font-mono text-sm font-semibold uppercase tracking-wider ${g.accent.split(" ")[1]}`}>{g.title}</div>
            <div className="text-[12px] text-ink-400">{g.sub}</div>
            <ul className="mt-4 space-y-3.5">
              {items.map((a, i) => (
                <li key={i} className="flex gap-3">
                  <Check size={15} className={`mt-0.5 shrink-0 ${g.accent.split(" ")[1]}`} />
                  <div>
                    <div className="text-sm font-semibold text-ink-100">{a.action}</div>
                    <div className="mt-0.5 text-[13px] leading-snug text-ink-300">{a.detail}</div>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        );
      })}
    </div>
  );
}
