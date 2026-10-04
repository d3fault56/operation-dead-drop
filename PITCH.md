# Operation Dead Drop — Hackathon Materials

## Project description (Devpost)

**Operation Dead Drop turns suspicious messages into cyber investigations.**

Most phishing tools answer one question: *is this bad?* Victims need more. They need to know what's happening, how they're being manipulated, what the attacker wants, and what to do right now.

Paste a suspicious email, text, or link. Dead Drop runs a deterministic forensics engine — look-alike and homoglyph domains, punycode, @-symbol URL tricks, raw-IP hosts, high-abuse TLDs, sender spoofing, and 11 classes of social-engineering language — then hands that evidence to an AI analyst (Claude) that returns a schema-constrained investigation. A grounding gate checks every claim against the original message and discards anything the AI can't trace to it.

The result is a case file: threat level, attacker objective, an annotated copy of the message, an evidence board separating *observed* from *inferred*, a step-by-step heist reconstruction, MITRE ATT&CK mapping, defanged IOCs, and a "Save the Victim" action plan. Links are never visited; nothing is executed. If the AI is unavailable, a deterministic analyst produces the same report so it always works.

## Technical innovation
1. **Evidence-first AI.** The model doesn't detect threats — it interprets evidence a deterministic engine already extracted. That makes results explainable and hard to hallucinate.
2. **Grounding gate.** Every "observed" evidence value and every manipulation quote must appear verbatim in the artifact or indicator set; MITRE IDs must come from a curated allowlist. Failures are discarded and disclosed in the report.
3. **Schema-constrained output.** Claude is forced into a typed tool call — no prose parsing.
4. **Graceful degradation.** Same schema from a rule-based analyst when the AI is down. The UI shows which engine ran.
5. **Zero-touch link analysis.** Static only — no fetching, no SSRF surface, no tipping off the attacker.

## Real-world impact
Phishing and scam texts are the front door for most account takeovers and consumer fraud, and the people they hit hardest — older adults, students, job seekers — don't have a SOC. Dead Drop gives them an analyst's read in seconds, in plain English, with the one thing that actually reduces harm: concrete next steps (don't click, call the bank on the number on your card, freeze credit if you shared your SSN, forward to 7726).

## Future roadmap
- Screenshot/OCR intake (most scams arrive as screenshots)
- Optional enrichment: Google Safe Browsing, VirusTotal, WHOIS domain age — clearly labeled as external
- Browser extension + "forward to Dead Drop" email address
- Campaign clustering: link reports that share infrastructure
- Family mode: share a case file with a relative in one link
- Report automation: pre-filled FTC / IC3 / provider abuse submissions

---

## 3-minute pitch

**[0:00 — Hook]**
"Someone doesn't need to hack your computer anymore. They just need to convince you to click."
Every one of us has gotten this text. The fake bank alert. The recruiter who wants your SSN. The $1.99 redelivery fee. Most people get one question answered — *is this a scam?* — if they're lucky.

**[0:25 — Product]**
Operation Dead Drop turns suspicious messages into cyber investigations. You hand over the evidence; we reconstruct the heist before it lands.

**[0:40 — Demo, see script below]**

**[2:05 — How it works]**
The key idea: the AI isn't the security engine — it's the analyst. A deterministic engine finds the evidence first: typosquats, homoglyphs, brand-in-subdomain tricks, sender spoofing, eleven kinds of manipulation language. Claude interprets that evidence into a structured, schema-constrained case file. Then a grounding gate checks every claim back against the original message — if the AI says something it can't prove, we throw it out. And if the AI goes down, the deterministic analyst still produces the full report.

**[2:35 — Safety & impact]**
We never visit the link, never execute anything, and never claim verification we didn't do. This is the analyst most people will never have: in seconds, in plain English, with exactly what to do next.

**[2:50 — Close]**
Operation Dead Drop. Turn suspicious messages into cyber investigations.

---

## Demo script (≈80 seconds)

1. **Operations Center.** "This is the intake. Paste anything — email, text, URL." Point at *Links are analyzed statically — never visited.*
2. **Click BANK PHISHING.** While scanning: "Forensics first, then the AI analyst, then a grounding check."
3. **Verdict strip.** "Critical. Credential phishing. Note confidence is *in the classification*, not proof — we're honest about that."
4. **Annotated artifact.** "Here's the message with the evidence highlighted — the link, the contact, every manipulation line."
5. **Heist reconstruction.** Walk the chain left to right: "Impersonation → pressure → malicious link → credential harvest → account takeover. Solid boxes are observed; dashed are inferred; red is what happens if you comply."
6. **Evidence board.** Point at *Brand name in subdomain*: "It says chase — but the real domain is account-verify.xyz."
7. **MITRE.** "T1598.003 — phishing for information via link. Small and accurate beats long and wrong."
8. **Save the Victim → Threat Contained.** "Do this now, if you already clicked, and how to stop the next one."
9. **(If time)** Open **FAKE JOB OFFER**: "Completely different attack — advance-fee and identity theft — and the reconstruction changes with it." Point at *Free-mail contact claiming Amazon*.
10. **(Q&A backup)** Paste `Hey, still on for lunch Friday?` → **BENIGN / Case Closed**: "It doesn't manufacture threats."

**Backup plan:** if Wi-Fi or the API dies, the header switches to *DETERMINISTIC MODE* and every demo still produces a complete investigation.

## Tech list
Next.js 15 (App Router), React 19, TypeScript, Tailwind CSS 4, Lucide, IBM Plex · Python 3, FastAPI, Pydantic, Uvicorn, tldextract · Anthropic Claude API (Sonnet-tier, forced tool-use structured output) · MITRE ATT&CK
