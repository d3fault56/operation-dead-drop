"""Deterministic security analysis layer.

Runs entirely locally. Never resolves, fetches, or visits any submitted URL.
Produces structured, evidence-backed findings that the AI analyst then interprets.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field, asdict
from urllib.parse import urlsplit, unquote, parse_qsl

import tldextract

# Offline extractor: uses the bundled public-suffix snapshot, never hits the network.
_TLD = tldextract.TLDExtract(suffix_list_urls=())

# ---------------------------------------------------------------- reference data
BRANDS: dict[str, list[str]] = {
    "PayPal": ["paypal.com"],
    "Chase": ["chase.com"],
    "Bank of America": ["bankofamerica.com", "bofa.com"],
    "Wells Fargo": ["wellsfargo.com"],
    "Citibank": ["citi.com", "citibank.com"],
    "Capital One": ["capitalone.com"],
    "USAA": ["usaa.com"],
    "Navy Federal": ["navyfederal.org"],
    "Amazon": ["amazon.com"],
    "Apple": ["apple.com", "icloud.com"],
    "Microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com"],
    "Google": ["google.com", "gmail.com"],
    "Netflix": ["netflix.com"],
    "USPS": ["usps.com"],
    "UPS": ["ups.com"],
    "FedEx": ["fedex.com"],
    "DHL": ["dhl.com"],
    "IRS": ["irs.gov"],
    "Venmo": ["venmo.com"],
    "Zelle": ["zellepay.com"],
    "Coinbase": ["coinbase.com"],
    "LinkedIn": ["linkedin.com"],
    "Indeed": ["indeed.com"],
    "Facebook": ["facebook.com"],
    "Instagram": ["instagram.com"],
    "Steam": ["steampowered.com", "steamcommunity.com"],
}
# Lowercase keyword -> canonical brand. Keywords are matched as whole words.
BRAND_KEYWORDS = {
    "paypal": "PayPal", "chase": "Chase", "bank of america": "Bank of America", "bofa": "Bank of America",
    "wells fargo": "Wells Fargo", "wellsfargo": "Wells Fargo", "citibank": "Citibank", "citi": "Citibank",
    "capital one": "Capital One", "usaa": "USAA", "navy federal": "Navy Federal", "amazon": "Amazon",
    "apple": "Apple", "icloud": "Apple", "microsoft": "Microsoft", "office 365": "Microsoft", "outlook": "Microsoft",
    "google": "Google", "gmail": "Google", "netflix": "Netflix", "usps": "USPS", "postal service": "USPS",
    "ups": "UPS", "fedex": "FedEx", "dhl": "DHL", "irs": "IRS", "venmo": "Venmo", "zelle": "Zelle",
    "coinbase": "Coinbase", "linkedin": "LinkedIn", "indeed": "Indeed", "facebook": "Facebook",
    "instagram": "Instagram", "steam": "Steam",
}
# label (e.g. "paypal") -> brand, for typosquat comparison
BRAND_LABELS = {d.split(".")[0]: b for b, ds in BRANDS.items() for d in ds if d.split(".")[0] not in {"live", "office", "outlook"}}
OFFICIAL_DOMAINS = {d for ds in BRANDS.values() for d in ds}

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "link", "buzz", "cam", "rest", "zip", "mov", "tk", "ml", "ga", "cf", "gq",
    "icu", "cyou", "sbs", "live", "shop", "online", "site", "support", "help", "info", "ru", "cn",
    "work", "loan", "win", "bid", "monster", "quest", "lol", "country",
}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
                  "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc"}
SENSITIVE_PARAMS = {"redirect", "redirect_uri", "return", "returnurl", "next", "url", "continue", "dest",
                    "destination", "target", "goto", "token", "session", "auth", "password", "pass", "email",
                    "account", "acct", "ssn", "card"}
LURE_PATH_WORDS = ["login", "signin", "sign-in", "verify", "verification", "secure", "account", "update",
                   "confirm", "unlock", "suspend", "billing", "payment", "wallet", "reset", "auth"]

HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a"})

# Social-engineering pattern library: category -> (display name, severity, [regex])
SE_PATTERNS: dict[str, tuple[str, str, list[str]]] = {
    "urgency": ("Urgency pressure", "high", [
        r"\b(immediately|urgent(ly)?|right away|as soon as possible|asap|act now|don'?t delay|without delay)\b",
        r"\bwithin\s+\d+\s*(hours?|hrs?|minutes?|mins?|days?)\b",
        r"\b(today only|final (notice|warning|reminder)|last chance|expires? (today|soon|tonight))\b",
    ]),
    "deadline": ("Hard deadline", "medium", [
        r"\b(by|before)\s+(\d{1,2}(:\d{2})?\s*(am|pm)|midnight|end of (the )?day|tomorrow|tonight)\b",
        r"\b(deadline|due date|time[- ]sensitive)\b",
    ]),
    "account_threat": ("Account suspension threat", "high", [
        r"\b(suspend(ed|sion)?|lock(ed)?|restrict(ed|ion)?|disabled?|deactivat(ed|ion)|frozen|terminat(ed|ion)|closed?)\b[^.\n]{0,40}\b(account|access|card|profile|service)\b",
        r"\b(account|access|card|profile)\b[^.\n]{0,40}\b(suspend(ed)?|lock(ed)?|restrict(ed)?|disabled|deactivated|frozen|terminated|closed)\b",
    ]),
    "fear": ("Fear / alarm", "medium", [
        r"\b(unauthori[sz]ed|suspicious|unusual|fraudulent)\s+(activity|login|sign[- ]in|access|transaction|charge)s?\b",
        r"\b(security (alert|breach|warning|notice)|compromised|breach(ed)?|hacked)\b",
        r"\b(legal action|lawsuit|arrest|warrant|penalt(y|ies)|police|prosecut)\w*\b",
    ]),
    "credential_request": ("Credential request", "critical", [
        r"\b(verify|confirm|update|validate|re-?enter|provide|enter)\b[^.\n]{0,40}\b(password|passcode|login|credentials?|username|pin|security (code|question)|one[- ]time (code|password)|otp|2fa|mfa code|verification code)\b",
        r"\b(log ?in|sign ?in)\b[^.\n]{0,30}\b(verify|confirm|restore|unlock|reactivate)\b",
        r"\b(verify|confirm|restore|unlock|reactivate)\b[^.\n]{0,30}\b(log ?in|sign ?in|identity|account)\b",
    ]),
    "pii_request": ("Personal data request", "high", [
        r"\b(social security( number)?|ssn|date of birth|dob|driver'?s licen[cs]e|passport|bank account (number|details|info)|routing number|mother'?s maiden name)\b",
        r"\b(full name, address|copy of your (id|identification))\b",
    ]),
    "financial_pressure": ("Payment demand", "high", [
        r"\b(pay|payment|fee|charge|deposit|invoice|outstanding balance|amount due|redelivery fee|processing fee|customs fee)\b[^.\n]{0,40}(\$\s?\d+([.,]\d{2})?|\d+([.,]\d{2})?\s?(usd|dollars))",
        r"(\$\s?\d+([.,]\d{2})?)[^.\n]{0,40}\b(fee|payment|charge|deposit)\b",
        r"\b(gift ?cards?|wire transfer|western union|moneygram|bitcoin|btc|crypto(currency)?|usdt|zelle|cash ?app|venmo)\b",
        r"\b(training (kit|materials?|equipment)|starter kit|equipment fee|background check fee|registration fee)\b",
    ]),
    "reward_lure": ("Reward / too-good-to-be-true lure", "medium", [
        r"\b(congratulations|you('ve| have) (won|been selected)|winner|prize|reward|free gift|claim your|refund (of|pending)|cash ?back)\b",
        r"\$\s?\d{2,3}(,\d{3})?\s*(per|/)\s*(hour|hr|week|day)\b",
        r"\b(no experience (needed|required)|work from home|remote position)\b[^.\n]{0,60}\b(\$|pay|earn|salary)",
    ]),
    "authority": ("Authority impersonation", "medium", [
        r"\b(security (team|department|center)|fraud (department|team|prevention)|compliance (team|department)|it (department|support|helpdesk)|account services|customer protection|hr department|hiring manager|recruit(er|ment) (team|officer))\b",
        r"\b(official notice|government|federal|department of)\b",
    ]),
    "secrecy_channel": ("Off-platform / secrecy request", "medium", [
        r"\b(do not (share|tell|discuss)|keep (this|it)?\s?(\w+ )?(confidential|secret|private)|don'?t tell)\b",
        r"\b(telegram|whatsapp|signal app|text (me|us) at|google hangouts|teams chat)\b",
    ]),
    "link_lure": ("Call-to-action link", "medium", [
        r"\b(click|tap|visit|follow|open|go to)\b[^.\n]{0,30}\b(link|here|below|button|url|website)\b",
    ]),
}

URL_RE = re.compile(r"""(?i)\b((?:https?://|hxxps?://|www\.)[^\s<>"'`()\[\]{}]+)""")
BARE_DOMAIN_RE = re.compile(r"""(?i)(?<![@\w./-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:xn--[a-z0-9-]+|[a-z]{2,24})(?:/[^\s<>"'`]*)?)""")
EMAIL_RE = re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,24}\b")
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
PHONE_RE = re.compile(r"(?<!\w)(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}(?!\w)")
SENDER_RE = re.compile(r"(?im)^\s*(from|sender|reply-to)\s*:\s*(.+)$")

SEV_WEIGHT = {"critical": 30, "high": 18, "medium": 9, "low": 3, "info": 0}


@dataclass
class Finding:
    id: str
    category: str
    indicator: str
    evidence: str
    severity: str
    detail: str = ""
    source: str = "deterministic"


@dataclass
class UrlReport:
    url: str
    domain: str
    registered_domain: str
    flags: list[str] = field(default_factory=list)


# ---------------------------------------------------------------- helpers
def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _sentence_around(text: str, start: int, end: int, limit: int = 180) -> str:
    bounds = [m.end() for m in re.finditer(r"[.!?](?=\s)|\n", text)]
    left = max([b for b in bounds if b <= start], default=0)
    right = min([b for b in bounds if b >= end], default=len(text))
    s = " ".join(text[left:right].split())
    if len(s) > limit:
        mid = text[start:end]
        i = s.find(mid)
        lo = max(0, i - 60) if i >= 0 else 0
        s = ("…" if lo else "") + s[lo:lo + limit].strip() + "…"
    return s


def _defang(u: str) -> str:
    return re.sub(r"(?i)^hxxp", "http", u).replace("[.]", ".").replace("(.)", ".")


def _host_of(raw: str) -> tuple[str, str]:
    """Return (normalized url, hostname) WITHOUT any network access."""
    u = _defang(raw).rstrip(".,;:!?)'\"")
    if not re.match(r"(?i)^https?://", u):
        u = "http://" + u
    try:
        parts = urlsplit(u)
        host = (parts.hostname or "").lower()
    except ValueError:
        host = ""
    return u, host


def _brand_match_for_label(label: str) -> tuple[str | None, str]:
    """Detect typosquats / homoglyph / combosquat against known brand labels."""
    norm = label.lower().translate(HOMOGLYPHS).replace("rn", "m").replace("vv", "w")
    tokens = [t for t in re.split(r"[-_.]", norm) if t]
    for brand_label, brand in BRAND_LABELS.items():
        if len(brand_label) < 4:
            # short labels (ups, dhl, irs, usaa...) only via exact token match = combosquat
            if brand_label in tokens and norm != brand_label:
                return brand, "combosquat"
            continue
        if norm == brand_label and label.lower() != brand_label:
            return brand, "homoglyph"
        if brand_label in tokens and norm != brand_label:
            return brand, "combosquat"
        if len(brand_label) >= 5 and brand_label in norm and norm != brand_label:
            return brand, "combosquat"
        for t in tokens + [norm]:
            if t != brand_label and abs(len(t) - len(brand_label)) <= 2 and _levenshtein(t, brand_label) <= (1 if len(brand_label) <= 5 else 2):
                return brand, "typosquat"
    return None, ""


# ---------------------------------------------------------------- core
def analyze(text: str) -> dict:
    text = text.replace("\x00", "")
    findings: list[Finding] = []
    fid = iter(range(1, 10_000))

    def add(cat, indicator, evidence, sev, detail=""):
        key = (cat, indicator, evidence)
        if any((f.category, f.indicator, f.evidence) == key for f in findings):
            return
        findings.append(Finding(f"F{next(fid):02d}", cat, indicator, evidence[:300], sev, detail))

    lowered = text.lower()

    # ---- extract emails first so their domains are not treated as bare URLs
    emails = sorted({e.lower() for e in EMAIL_RE.findall(text)})
    text_wo_emails = EMAIL_RE.sub(" ", text)

    # ---- URLs
    raw_urls: list[str] = [m.group(1) for m in URL_RE.finditer(text_wo_emails)]
    covered = " ".join(raw_urls).lower()
    for m in BARE_DOMAIN_RE.finditer(URL_RE.sub(" ", text_wo_emails)):
        cand = m.group(1).rstrip(".,;:!?)")
        _, host = _host_of(cand)
        if not host or host in covered:
            continue
        ext = _TLD(host)
        if ext.suffix and ext.domain and not re.fullmatch(r"\d+(\.\d+)*", host):
            raw_urls.append(cand)

    url_reports: list[UrlReport] = []
    seen = set()
    for raw in raw_urls:
        url, host = _host_of(raw)
        if not host or url in seen:
            continue
        seen.add(url)
        rep = UrlReport(url=url, domain=host, registered_domain=host)
        is_ip = False
        try:
            ipaddress.ip_address(host.strip("[]"))
            is_ip = True
        except ValueError:
            pass

        if is_ip:
            rep.flags.append("ip_host")
            add("url", "IP-address URL", url, "high", "Link points to a raw IP address instead of a named domain — legitimate organizations almost never do this.")
        else:
            ext = _TLD(host)
            rep.registered_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else host
            sub_parts = [p for p in ext.subdomain.split(".") if p]
            if "xn--" in host:
                rep.flags.append("punycode")
                try:
                    decoded = host.encode("ascii").decode("idna")
                except Exception:
                    decoded = host
                add("url", "Punycode / IDN domain", host, "high", f"Internationalized domain decodes to '{decoded}'. Look-alike Unicode characters are a classic impersonation trick.")
            if ext.suffix.split(".")[-1] in SUSPICIOUS_TLDS:
                rep.flags.append("suspicious_tld")
                add("url", "High-abuse top-level domain", rep.registered_domain, "medium", f"The '.{ext.suffix}' TLD is disproportionately used in phishing and scam campaigns. This alone does not prove malice.")
            if len(sub_parts) >= 3:
                rep.flags.append("excessive_subdomains")
                add("url", "Excessive subdomains", host, "medium", f"{len(sub_parts)} subdomain levels — often used to bury a fake brand name in front of the real registered domain.")
            if rep.registered_domain in URL_SHORTENERS:
                rep.flags.append("shortener")
                add("url", "URL shortener", url, "medium", "Shortened link hides the true destination. It was NOT expanded — Dead Drop never visits submitted links.")

            official = rep.registered_domain in OFFICIAL_DOMAINS
            if not official:
                brand, kind = _brand_match_for_label(ext.domain)
                if brand:
                    rep.flags.append(kind)
                    sev = "critical" if kind in ("typosquat", "homoglyph") else "high"
                    label = {"typosquat": "Typosquatted domain", "homoglyph": "Homoglyph look-alike domain", "combosquat": "Brand-combo look-alike domain"}[kind]
                    add("impersonation", label, rep.registered_domain, sev,
                        f"Resembles {brand} (official: {', '.join(BRANDS[brand])}) but is a different registered domain.")
                if not any(f in rep.flags for f in ("typosquat", "homoglyph")):
                    for sp in sub_parts:
                        b2, _ = _brand_match_for_label(sp)
                        if b2 or sp in BRAND_LABELS:
                            b2 = b2 or BRAND_LABELS[sp]
                            rep.flags.append("brand_in_subdomain")
                            add("impersonation", "Brand name in subdomain", host, "high",
                                f"'{b2}' appears in the subdomain, but the real registered domain is '{rep.registered_domain}'.")
                            break

        parts = urlsplit(url)
        if parts.username or "@" in (parts.netloc or ""):
            rep.flags.append("at_symbol")
            add("url", "@-symbol URL trick", url, "high", "Everything before '@' in a URL is ignored by browsers; the real destination is after it.")
        if re.search(r"%[0-9a-fA-F]{2}", url) and unquote(url) != url:
            rep.flags.append("encoded")
            add("url", "URL-encoded characters", url, "low", f"Decodes to: {unquote(url)[:160]}")
        if len(url) > 100:
            rep.flags.append("long_url")
            add("url", "Unusually long URL", url[:120] + "…", "low", f"{len(url)} characters — long URLs can hide the real destination on mobile screens.")
        bad_params = [k for k, _ in parse_qsl(parts.query, keep_blank_values=True) if k.lower() in SENSITIVE_PARAMS]
        if bad_params:
            rep.flags.append("sensitive_params")
            add("url", "Sensitive / redirect query parameters", url, "medium", f"Parameters: {', '.join(sorted(set(bad_params)))}")
        if parts.scheme == "http" and not is_ip and rep.registered_domain not in OFFICIAL_DOMAINS and re.match(r"(?i)^http://", _defang(raw)):
            rep.flags.append("no_tls")
            add("url", "Unencrypted HTTP link", url, "low", "Link uses plain HTTP — any data entered would be sent unencrypted.")
        path_hits = [w for w in LURE_PATH_WORDS if w in (parts.path + "?" + parts.query).lower() or w in host]
        if path_hits and rep.registered_domain not in OFFICIAL_DOMAINS:
            rep.flags.append("lure_keywords")
            add("url", "Credential-lure keywords in link", url, "medium", f"Contains: {', '.join(path_hits[:5])}")
        url_reports.append(rep)

    # ---- other indicators
    ips = sorted(set(IPV4_RE.findall(text)))
    phones = sorted({re.sub(r"\s+", " ", p.strip()) for p in PHONE_RE.findall(text) if len(re.sub(r"\D", "", p)) >= 10})

    brands_mentioned = []
    for kw, brand in BRAND_KEYWORDS.items():
        if re.search(rf"(?<![\w.-]){re.escape(kw)}(?![\w-])", text_wo_emails.lower()) and brand not in brands_mentioned:
            brands_mentioned.append(brand)

    # ---- sender analysis
    for m in SENDER_RE.finditer(text):
        line = m.group(2).strip()
        em = EMAIL_RE.search(line)
        if not em:
            continue
        addr = em.group(0).lower()
        dom = addr.split("@", 1)[1]
        ext = _TLD(dom)
        reg = f"{ext.domain}.{ext.suffix}"
        display = line[: em.start()].strip(" <\"'")
        if reg in OFFICIAL_DOMAINS:
            continue
        brand, kind = _brand_match_for_label(ext.domain)
        claimed = [b for kw, b in BRAND_KEYWORDS.items() if re.search(rf"(?<!\w){re.escape(kw)}(?!\w)", display.lower())]
        if brand:
            add("impersonation", "Look-alike sender domain", addr, "critical" if kind != "combosquat" else "high",
                f"Sender domain imitates {brand} (official: {', '.join(BRANDS[brand])}).")
        elif claimed:
            add("impersonation", "Display-name spoofing", line[:120], "high",
                f"Display name claims '{claimed[0]}' but the address is from '{reg}'.")
        elif reg.split(".")[0] in {"gmail", "yahoo", "outlook", "hotmail", "aol", "proton", "protonmail", "icloud"} and brands_mentioned:
            add("impersonation", "Free-mail sender claiming an organization", addr, "medium",
                f"Message references {brands_mentioned[0]} but was sent from a free consumer mailbox.")

    # ---- free-mail address in body while claiming to represent an organization
    if brands_mentioned and not SENDER_RE.search(text):
        FREE = {"gmail", "yahoo", "outlook", "hotmail", "aol", "proton", "protonmail", "icloud"}
        for addr in emails:
            if addr.split("@", 1)[1].split(".")[0] in FREE:
                add("impersonation", "Free-mail contact claiming an organization", addr, "high",
                    f"Message claims to represent {brands_mentioned[0]} but asks you to contact a free consumer mailbox.")
                break

    # ---- brand mentioned but every link is off-brand
    if brands_mentioned and url_reports:
        official_for_mentioned = {d for b in brands_mentioned for d in BRANDS.get(b, [])}
        off = [r for r in url_reports if r.registered_domain not in official_for_mentioned and r.registered_domain not in OFFICIAL_DOMAINS]
        if off and len(off) == len(url_reports):
            add("impersonation", "Brand / link mismatch", off[0].registered_domain, "high",
                f"Message claims to be from {', '.join(brands_mentioned[:2])}, but the link goes to '{off[0].registered_domain}', not an official domain.")

    # ---- social engineering patterns
    se_hits: dict[str, list[str]] = {}
    for cat, (name, sev, pats) in SE_PATTERNS.items():
        for pat in pats:
            for m in re.finditer(pat, text, flags=re.I):
                ev = _sentence_around(text, m.start(), m.end())
                se_hits.setdefault(cat, [])
                if ev not in se_hits[cat] and len(se_hits[cat]) < 3:
                    se_hits[cat].append(ev)
                    add("social_engineering", name, ev, sev, f"Matched: “{m.group(0).strip()}”")
    # credential request is only critical if there's somewhere to send them (link) or explicit ask for password
    if "credential_request" in se_hits and not url_reports and not re.search(r"\b(password|pin|otp|code)\b", lowered):
        for f in findings:
            if f.indicator == "Credential request":
                f.severity = "high"

    # ---- score (deterministic, explainable)
    score = sum(SEV_WEIGHT[f.severity] for f in findings)
    combo = {"credential_request", "urgency"} <= se_hits.keys() and url_reports
    if combo:
        score += 15
    if any(f.category == "impersonation" for f in findings) and url_reports:
        score += 10
    score = max(0, min(100, score))

    keywords = sorted({re.search(p, text, re.I).group(0).lower()  # type: ignore[union-attr]
                       for _, (_, _, pats) in SE_PATTERNS.items() for p in pats
                       if re.search(p, text, re.I) and len(re.search(p, text, re.I).group(0)) <= 40})[:20]  # type: ignore[union-attr]

    return {
        "risk_score": score,
        "findings": [asdict(f) for f in findings],
        "social_engineering_categories": sorted(se_hits.keys()),
        "indicators": {
            "urls": [r.url for r in url_reports],
            "domains": sorted({r.registered_domain for r in url_reports}),
            "ip_addresses": ips,
            "emails": emails,
            "phone_numbers": phones,
            "brands": brands_mentioned,
            "keywords": keywords,
        },
        "url_analysis": [asdict(r) for r in url_reports],
        "stats": {"characters": len(text), "words": len(text.split()), "lines": text.count("\n") + 1},
    }


def classify_input(text: str) -> str:
    t = text.strip()
    if re.fullmatch(r"(?i)(https?://|hxxps?://|www\.)?\S+\.\S+", t) and " " not in t:
        return "url"
    if SENDER_RE.search(t) or re.search(r"(?im)^\s*subject\s*:", t):
        return "email"
    return "message"
