# Copyright (c) 2025 CyberViser. All Rights Reserved.
# Licensed under the CyberViser Proprietary License — see LICENSE for details.
# Unauthorized commercial use, redistribution, or AI training is prohibited.
"""
Hancock Agent — NVIDIA NIM Inference Backend
CyberViser | hancock_agent.py

Two modes:
  python hancock_agent.py          → interactive CLI chat
  python hancock_agent.py --server → REST API server (port 5000)

CLI mode commands:
  /mode pentest   — switch to Pentest Specialist persona
  /mode soc       — switch to SOC Analyst persona
  /mode auto      — combined persona (default)
  /mode code      — security code generation (Qwen Coder 32B)
  /mode ciso      — CISO strategy, compliance & board reporting
  /mode sigma     — Sigma detection rule authoring
  /mode yara      — YARA malware detection rule authoring
  /mode ioc       — IOC threat intelligence enrichment
  /clear          — clear conversation history
  /history        — show history
  /model <id>     — switch model
  /exit           — quit

Set your key:
  export NVIDIA_API_KEY="nvapi-..."
  or pass --api-key "nvapi-..."
"""
import argparse
import hashlib
import hmac
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
import readline  # noqa: F401 — enables arrow-key history in CLI

try:
    from openai import OpenAI
except ImportError:
    sys.exit("Run: .venv/bin/pip install openai flask")

# ── Hancock identity ──────────────────────────────────────────────────────────
PENTEST_SYSTEM = """You are Hancock, an elite penetration tester and offensive security specialist built by CyberViser.

Your expertise covers:
- Reconnaissance: OSINT, subdomain enumeration, port scanning (nmap, amass, subfinder)
- Web Application Testing: SQLi, XSS, SSRF, auth bypass, IDOR, JWT attacks (Burp Suite, sqlmap)
- Network Exploitation: Metasploit, lateral movement, credential attacks (CrackMapExec, impacket)
- Post-Exploitation: Privilege escalation (LinPEAS, WinPEAS, GTFOBins), persistence, pivoting
- Vulnerability Analysis: CVE research, CVSS scoring, PoC analysis, patch prioritization
- Reporting: PTES methodology, professional finding write-ups, executive summaries

You operate STRICTLY within authorized scope. You always:
1. Confirm authorization before suggesting active techniques
2. Recommend responsible disclosure and remediation
3. Reference real tools, commands, and CVEs with accuracy
4. Provide actionable, technically precise answers

You are Hancock. You are methodical, precise, and professional."""

SOC_SYSTEM = """You are Hancock, an expert SOC Tier-2/3 analyst and incident responder built by CyberViser.

Your expertise covers:
- Alert Triage: Classify and prioritize SIEM/EDR/IDS/IPS alerts using MITRE ATT&CK mapping
- Log Analysis: Windows Event Logs (4624/4625/4688/7045), Syslog, Apache/Nginx, firewall, DNS
- SIEM Queries: Splunk SPL, Elastic KQL, Microsoft Sentinel KQL — writing precise detection queries
- Incident Response: NIST SP 800-61 / PICERL (Prepare, Identify, Contain, Eradicate, Recover, Lessons Learned)
- Threat Hunting: Hypothesis-driven hunting, IOC sweeps, behavioral analytics, UEBA
- IOC Analysis: Hash analysis, domain/IP reputation, WHOIS, passive DNS, file/process/network pivoting
- Detection Engineering: Sigma rules, YARA rules, custom alerts, tuning FP reduction
- Malware Triage: Static (strings, PE headers, imports) + dynamic (sandbox detonation, behavior analysis)
- Threat Intelligence: MISP, OpenCTI, TAXII/STIX, APT group TTPs, attribution

You always:
1. Follow the PICERL framework for incident response
2. Document findings with timestamps, evidence, and chain of custody
3. Write precise detection logic (Sigma, SPL, KQL) with comments
4. Escalate appropriately and communicate clearly to stakeholders
5. Stay calm under pressure — triage by impact and urgency

You are Hancock. You are methodical, calm, and thorough."""

AUTO_SYSTEM = """You are Hancock, an elite cybersecurity specialist built by CyberViser. You operate as both a penetration tester and SOC analyst, depending on context.

**Pentest Mode:** Reconnaissance, exploitation, post-exploitation, CVE analysis, Metasploit, Burp Suite, authorized engagements only.
**SOC Mode:** Alert triage, SIEM queries (Splunk SPL / Elastic KQL / Sentinel KQL), incident response (PICERL), threat hunting, detection engineering, IOC analysis.

You always:
- Operate within authorized scope
- Follow PICERL for IR and PTES for pentesting
- Provide accurate, actionable technical guidance
- Reference real tools, real CVEs, and real detection logic

You are Hancock. Built by CyberViser."""

CODE_SYSTEM = """You are Hancock Code, CyberViser's expert security code assistant powered by Qwen 2.5 Coder 32B.

You write production-quality security tooling code in Python, Bash, PowerShell, and Go.

Your specialties:
- Security automation: scanners, parsers, log analyzers, alert enrichers
- Exploit PoC code (authorized research only — always add warnings)
- SIEM query writing: Splunk SPL, Elastic KQL, Sentinel KQL, Sigma YAML
- Detection scripts: YARA rules, Suricata/Snort rules, custom IDS signatures
- Pentest helpers: recon scripts, payload generators, C2 scaffolding (authorized only)
- Secure code review: identify vulns (OWASP Top 10, CWE), suggest fixes with examples
- CTF solvers: rev, pwn, web, crypto — with explanations

You always:
1. Add authorization/legal warnings to offensive tooling
2. Include error handling, type hints, and docstrings
3. Explain what the code does and any security implications
4. Suggest safer alternatives when relevant

You are Hancock Code. Precision over verbosity. Ship working code."""

CISO_SYSTEM = """You are Hancock CISO, CyberViser's AI-powered Chief Information Security Officer advisor.

Your expertise covers:
- Risk Management: NIST RMF, ISO 27001/27005, FAIR quantitative risk analysis, risk register management
- Compliance & Frameworks: SOC 2, ISO 27001, PCI-DSS, HIPAA, GDPR, DORA, NIST CSF 2.0, CIS Controls v8
- Board & Executive Reporting: security posture summaries, risk-adjusted metrics, budget justification, KRI/KPI dashboards
- Security Program Strategy: maturity assessments (CMMI, C2M2), roadmap planning, control gap analysis
- Vendor & Third-Party Risk: TPRM frameworks, questionnaire assessment, supply chain risk, SLA review
- Incident Communication: breach notification drafting, regulatory reporting, stakeholder messaging
- Security Architecture Review: zero trust, cloud security posture (CSPM), identity governance, data classification
- Budget & ROI: security spend optimization, tool consolidation, make-vs-buy analysis, cyber insurance guidance

You always:
1. Translate technical risk into business impact (financial, reputational, regulatory)
2. Prioritize by likelihood × impact × cost-to-remediate
3. Align recommendations to the organization's risk appetite and industry sector
4. Provide executive-ready language — clear, concise, no jargon unless requested
5. Reference specific control numbers (CIS Control 5.1, NIST CSF ID.AM-1) where relevant

You are Hancock CISO. You speak business and security fluently."""

SIGMA_SYSTEM = """You are Hancock Sigma, CyberViser's expert detection engineer specializing in Sigma rule authoring.

Your expertise covers:
- Sigma rule syntax (title, id, status, description, references, author, date, modified, tags, logsource, detection, falsepositives, level, fields)
- Log sources: Windows Event Logs, Sysmon, Linux auditd, cloud (AWS CloudTrail, Azure Activity, GCP Audit), web proxy, firewall, DNS, EDR
- MITRE ATT&CK tagging: correct attack.tXXXX technique and sub-technique IDs
- Detection logic: selection/filter patterns, keywords, regex, aggregations, near/timeframe conditions
- False positive analysis and tuning recommendations
- Converting IOCs, TTPs, threat intel reports → detection rules
- Sigma rule quality: specificity vs. coverage trade-offs, noise reduction

You always:
1. Output valid, well-formed SIGMA YAML with all required fields
2. Include `falsepositives` and `level` (informational/low/medium/high/critical)
3. Tag correctly with MITRE ATT&CK technique IDs in the `tags` field
4. Add a `filter` condition when the detection is prone to noise
5. After the rule, briefly explain what it detects and any tuning notes

You are Hancock Sigma. Every rule you write is ready to deploy."""

SYSTEMS = {
    "pentest": PENTEST_SYSTEM,
    "soc":     SOC_SYSTEM,
    "auto":    AUTO_SYSTEM,
    "code":    CODE_SYSTEM,
    "ciso":    CISO_SYSTEM,
    "sigma":   SIGMA_SYSTEM,
    "yara":    None,  # filled below after YARA_SYSTEM is defined
}

YARA_SYSTEM = """You are Hancock YARA, CyberViser's expert malware analyst and detection engineer.

Your expertise covers:
- YARA rule syntax: meta, strings ($hex, $ascii, $regex, $wide, $nocase), condition logic
- Malware families: ransomware, RATs, stealers, loaders, botnets, APT tooling
- File-format artefacts: PE headers, macros, packer signatures, shellcode patterns
- Memory scanning: process injection, reflective loading, hollow process indicators
- YARA best practices: performance (all of them at filesize, pe.imports), specificity vs coverage
- YARA modules: pe, elf, math, hash, dotnet, magic, androguard

You always:
1. Output a complete, syntactically valid YARA rule with meta (description, author, date, hash if known)
2. Use multiple string conditions to reduce false positives
3. Add a condition that limits to relevant file type/size when possible
4. After the rule, explain what it detects and list any known false positive sources

You are Hancock YARA. Every rule you write is ready to run with `yara64 -r rule.yar /path`."""

SYSTEMS["yara"] = YARA_SYSTEM

IOC_SYSTEM = """You are Hancock IOC, CyberViser's threat intelligence analyst.
When given an indicator of compromise (IP address, domain, URL, file hash, or email),
you provide a structured enrichment report covering:
- Indicator type and classification
- Threat intelligence context (known malware families, threat actors, campaigns)
- MITRE ATT&CK techniques associated with this indicator
- Risk score (1–10) with justification
- Recommended defensive actions (block, monitor, investigate)
- Relevant CVEs or GHSA advisories if applicable

Format your response as a clear, structured threat intel report."""

SYSTEMS["ioc"] = IOC_SYSTEM
DEFAULT_MODE = "auto"
# Keep backward-compatible alias
HANCOCK_SYSTEM = AUTO_SYSTEM

NIM_BASE_URL    = "https://integrate.api.nvidia.com/v1"
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434") + "/v1"
DEFAULT_MODEL   = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
CODER_MODEL     = os.getenv("OLLAMA_CODER_MODEL", "qwen2.5-coder:7b")
VERSION         = "0.5.0"
REQUIRE_SCOPE_ACK = os.getenv("HANCOCK_REQUIRE_SCOPE_ACK", "1") != "0"

# ── Available models ──────────────────────────────────────────────────────────
MODELS = {
    # Ollama models (local)
    "llama3.1":     "llama3.1:8b",
    "llama3.2":     "llama3.2:3b",
    "mistral":      "mistral:7b",
    "qwen-coder":   "qwen2.5-coder:7b",
    "gemma3":       "gemma3:12b",
    # NVIDIA NIM models (used when HANCOCK_LLM_BACKEND=nvidia)
    "nim-mistral":  "mistralai/mistral-7b-instruct-v0.3",
    "nim-qwen":     "qwen/qwen2.5-coder-32b-instruct",
    "nim-llama":    "meta/llama-3.1-8b-instruct",
}

# ── OpenAI fallback ───────────────────────────────────────────────────────────
OPENAI_MODEL      = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
OPENAI_CODER_MODEL = os.getenv("OPENAI_CODER_MODEL", "gpt-4o")

BANNER = """
╔══════════════════════════════════════════════════════════╗
║  ██╗  ██╗ █████╗ ███╗   ██╗ ██████╗ ██████╗  ██████╗██╗ ║
║  ██║  ██║██╔══██╗████╗  ██║██╔════╝██╔═══██╗██╔════╝██║ ║
║  ███████║███████║██╔██╗ ██║██║     ██║   ██║██║     ██║ ║
║  ██╔══██║██╔══██║██║╚██╗██║██║     ██║   ██║██║     ██╚╗║
║  ██║  ██║██║  ██║██║ ╚████║╚██████╗╚██████╔╝╚██████╗╚═╝║║
║  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝  ╚═════╝   ║
║          CyberViser — Pentest + SOC + CISO + Code        ║
║   Llama 3.1 · Qwen 2.5 Coder · Ollama (local)           ║
╚══════════════════════════════════════════════════════════╝
  Modes : /mode pentest | soc | auto | code | ciso | sigma | yara
  Models: /model llama3.1 | llama3.2 | mistral | qwen-coder | gemma3
  Other : /clear  /history  /exit
"""


def _scope_token() -> str:
    """Required scope acknowledgement token (lowercase)."""
    return os.getenv("HANCOCK_SCOPE_VALUE", "authorized").strip().lower()


def _scope_ack_env() -> bool:
    """Return True if the user explicitly acknowledged authorized use via env."""
    ack = os.getenv("HANCOCK_SCOPE_ACK", "").strip().lower()
    token = _scope_token()
    return bool(token) and ack == token


def make_ollama_client() -> OpenAI:
    """Returns an OpenAI-compatible client pointed at the local Ollama server."""
    return OpenAI(base_url=OLLAMA_BASE_URL, api_key="ollama")


def make_client(api_key: str) -> OpenAI:
    """Returns an OpenAI-compatible client pointed at NVIDIA NIM (legacy)."""
    return OpenAI(base_url=NIM_BASE_URL, api_key=api_key)


def make_openai_client() -> OpenAI | None:
    """Returns an OpenAI client if credentials are available, else None."""
    key = os.getenv("OPENAI_API_KEY", "")
    org = os.getenv("OPENAI_ORG_ID", "")
    if not key or key.startswith("sk-your"):
        return None
    return OpenAI(api_key=key, organization=org or None)


def chat(client: OpenAI, history: list[dict], model: str, stream: bool = True,
         system_prompt: str | None = None) -> str:
    system = system_prompt or HANCOCK_SYSTEM
    messages = [{"role": "system", "content": system}] + history
    try:
        return _do_chat(client, messages, model, stream)
    except Exception as primary_err:
        # Auto-fallback to OpenAI if primary backend (Ollama or NIM) fails
        fallback = make_openai_client()
        if fallback:
            print(f"\n[Hancock] Backend error ({primary_err}) — falling back to OpenAI {OPENAI_MODEL}...")
            return _do_chat(fallback, messages, OPENAI_MODEL, stream)
        raise


def _do_chat(client: OpenAI, messages: list[dict], model: str, stream: bool) -> str:
    if stream:
        response_text = ""
        print("\n\033[1;32mHancock:\033[0m ", end="", flush=True)
        stream_resp = client.chat.completions.create(
            model=model, messages=messages, max_tokens=1024,
            temperature=0.7, top_p=0.95, stream=True,
        )
        for chunk in stream_resp:
            if chunk.choices and chunk.choices[0].delta.content:
                delta = chunk.choices[0].delta.content
                print(delta, end="", flush=True)
                response_text += delta
        print()
        return response_text
    resp = client.chat.completions.create(
        model=model, messages=messages, max_tokens=1024,
        temperature=0.7, top_p=0.95,
    )
    return resp.choices[0].message.content


# ── CLI mode ──────────────────────────────────────────────────────────────────
def run_cli(client: OpenAI, model: str):
    print(BANNER)
    print(f"  Model : {model}")
    backend = os.getenv("HANCOCK_LLM_BACKEND", "ollama").lower()
    if backend == "ollama":
        print(f"  Endpoint: {OLLAMA_BASE_URL}")
    elif backend == "nvidia":
        print(f"  Endpoint: {NIM_BASE_URL}")
    print(f"  Mode  : auto (Pentest + SOC)")
    print()

    if REQUIRE_SCOPE_ACK and not _scope_ack_env():
        token = _scope_token()
        try:
            ack = input(f"[Hancock] Authorized use only. Type '{token}' to confirm scope: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n[Hancock] Scope not confirmed. Exiting.")
            return
        if ack != token:
            print("[Hancock] Scope not confirmed. Exiting.")
            return

    history: list[dict] = []
    current_mode = DEFAULT_MODE

    while True:
        try:
            user_input = input("\033[1;34m[You]\033[0m ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[Hancock] Signing off. Stay in scope.")
            break

        if not user_input:
            continue

        if user_input.lower() in ("/exit", "/quit", "exit", "quit"):
            print("[Hancock] Signing off. Stay in scope.")
            break

        if user_input == "/clear":
            history.clear()
            print("[Hancock] Conversation cleared.")
            continue

        if user_input == "/history":
            for i, m in enumerate(history):
                role = m["role"].upper()
                print(f"  [{i}] {role}: {m['content'][:80]}...")
            continue

        if user_input.startswith("/mode"):
            parts = user_input.split()
            if len(parts) == 2 and parts[1] in SYSTEMS:
                current_mode = parts[1]
                history.clear()
                # Auto-switch to coder model when entering code mode
                if current_mode == "code" and model == DEFAULT_MODEL:
                    model = CODER_MODEL
                    print(f"[Hancock] Auto-switched to {CODER_MODEL} for code mode.")
                label = {
                    "pentest": "Pentest Specialist 🔴",
                    "soc":     "SOC Analyst 🔵",
                    "auto":    "Auto (Pentest+SOC) ⚡",
                    "code":    "Code Assistant 💻 (Qwen 2.5 Coder 32B)",
                    "ciso":    "CISO Advisor 👔",
                }
                print(f"[Hancock] Switched to {label[current_mode]} — history cleared.")
            else:
                print("[Hancock] Usage: /mode pentest | /mode soc | /mode auto | /mode code | /mode ciso | /mode sigma | /mode yara | /mode ioc")
            continue

        if user_input.startswith("/model "):
            alias = user_input[7:].strip()
            model = MODELS.get(alias, alias)  # resolve alias or use raw model ID
            print(f"[Hancock] Switched to model: {model}")
            continue

        history.append({"role": "user", "content": user_input})

        try:
            response = chat(client, history, model, stream=True,
                            system_prompt=SYSTEMS[current_mode])
            history.append({"role": "assistant", "content": response})
        except Exception as e:
            print(f"\033[1;31m[Error]\033[0m {e}")
            history.pop()  # remove failed user message


# ── REST API server mode ──────────────────────────────────────────────────────
def build_app(client, model: str):
    """Build and return the Flask app (used by both run_server and tests)."""
    try:
        from flask import Flask, g, request, jsonify, Response, stream_with_context
    except ImportError:
        sys.exit("Run: .venv/bin/pip install flask")

    app = Flask("hancock")

    # ── Metrics counters ──────────────────────────────────────────────────────
    _metrics_lock = threading.Lock()
    _metrics: dict = {
        "requests_total": 0,
        "errors_total": 0,
        "requests_by_endpoint": {},
        "requests_by_mode": {},
    }

    def _inc(key: str, label: str = ""):
        with _metrics_lock:
            if label:
                _metrics[key][label] = _metrics[key].get(label, 0) + 1
            else:
                _metrics[key] += 1

    # ── Auth + rate limiting ───────────────────────────────────────────────────
    _HANCOCK_API_KEY = os.getenv("HANCOCK_API_KEY", "")
    _rate_counts: dict = {}  # ip → [timestamp, ...]
    _RATE_LIMIT  = int(os.getenv("HANCOCK_RATE_LIMIT", "60"))   # requests/min
    _RATE_WINDOW = 60  # seconds

    def _check_auth_and_rate() -> "tuple[bool, str, int]":
        """Returns (ok, error_message, remaining). Empty HANCOCK_API_KEY disables auth."""
        # Auth check (skip if key not configured)
        if _HANCOCK_API_KEY:
            auth = request.headers.get("Authorization", "")
            token = auth.removeprefix("Bearer ").strip()
            if token != _HANCOCK_API_KEY:
                return False, "Unauthorized: provide Authorization: Bearer <HANCOCK_API_KEY>", 0

        # In-memory rate limiter (per source IP) — evicts stale entries to prevent memory leak
        now = time.time()
        ip  = request.remote_addr or "unknown"
        timestamps = _rate_counts.get(ip, [])
        timestamps = [t for t in timestamps if now - t < _RATE_WINDOW]
        if len(timestamps) >= _RATE_LIMIT:
            return False, f"Rate limit exceeded: {_RATE_LIMIT} requests/min", 0
        timestamps.append(now)
        _rate_counts[ip] = timestamps
        # Evict IPs whose timestamps have all expired (keep dict bounded)
        if len(_rate_counts) > 10_000:
            stale = [k for k, v in _rate_counts.items()
                     if all(now - t >= _RATE_WINDOW for t in v)]
            for k in stale:
                del _rate_counts[k]
        remaining = _RATE_LIMIT - len(timestamps)
        g.rate_remaining = remaining
        return True, "", remaining

    def _check_scope_ack(payload: dict) -> "tuple[bool, str]":
        """Require explicit authorized-use acknowledgement, unless disabled."""
        if not REQUIRE_SCOPE_ACK:
            return True, ""
        if _scope_ack_env():
            return True, ""
        if not isinstance(payload, dict):
            return False, "Request payload must be a JSON object"
        token = _scope_token()
        provided = (payload.get("scope") or "").strip().lower()
        if provided != token:
            return False, f"Authorized use only. Provide scope='{token}' in the request body."
        return True, ""

    @app.after_request
    def _add_rate_headers(response):
        """Attach X-RateLimit-* headers to every response."""
        remaining = getattr(g, "rate_remaining", _RATE_LIMIT)
        response.headers["X-RateLimit-Limit"]     = str(_RATE_LIMIT)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Window"]    = "60s"
        return response

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({
            "status": "ok", "agent": "Hancock",
            "model": model, "company": "CyberViser",
            "modes": ["pentest", "soc", "auto", "code", "ciso", "sigma", "yara", "ioc"],
            "models_available": MODELS,
            "endpoints": ["/v1/chat", "/v1/ask", "/v1/triage",
                          "/v1/hunt", "/v1/respond", "/v1/code",
                          "/v1/ciso", "/v1/sigma", "/v1/yara", "/v1/ioc", "/v1/webhook", "/metrics"],
        })

    @app.route("/metrics", methods=["GET"])
    def metrics_endpoint():
        """Prometheus-compatible plain-text metrics."""
        with _metrics_lock:
            snap = {
                "requests_total": _metrics["requests_total"],
                "errors_total":   _metrics["errors_total"],
                "by_endpoint":    dict(_metrics["requests_by_endpoint"]),
                "by_mode":        dict(_metrics["requests_by_mode"]),
            }
        lines = [
            "# HELP hancock_requests_total Total API requests",
            "# TYPE hancock_requests_total counter",
            f'hancock_requests_total {snap["requests_total"]}',
            "# HELP hancock_errors_total Total 4xx/5xx errors",
            "# TYPE hancock_errors_total counter",
            f'hancock_errors_total {snap["errors_total"]}',
            "# HELP hancock_requests_by_endpoint Requests per endpoint",
            "# TYPE hancock_requests_by_endpoint counter",
        ]
        for ep, cnt in snap["by_endpoint"].items():
            lines.append(f'hancock_requests_by_endpoint{{endpoint="{ep}"}} {cnt}')
        lines += [
            "# HELP hancock_requests_by_mode Requests per mode",
            "# TYPE hancock_requests_by_mode counter",
        ]
        for m, cnt in snap["by_mode"].items():
            lines.append(f'hancock_requests_by_mode{{mode="{m}"}} {cnt}')
        return Response("\n".join(lines) + "\n", mimetype="text/plain; version=0.0.4")

    @app.route("/v1/chat", methods=["POST"])
    def chat_endpoint():
        ok, err, _ = _check_auth_and_rate()
        if not ok:
            _inc("errors_total")
            return jsonify({"error": err}), 401 if "Unauthorized" in err else 429
        _inc("requests_total"); _inc("requests_by_endpoint", "/v1/chat")
        data = request.get_json(force=True)
        ok_scope, scope_err = _check_scope_ack(data)
        if not ok_scope:
            _inc("errors_total"); return jsonify({"error": scope_err}), 403
        user_msg = data.get("message", "")
        history  = data.get("history", [])
        stream   = data.get("stream", False)
        mode     = data.get("mode", "auto")

        if not user_msg:
            _inc("errors_total"); return jsonify({"error": "message required"}), 400
        if mode not in SYSTEMS and mode != "auto":
            _inc("errors_total"); return jsonify({"error": f"invalid mode '{mode}'; valid: {list(SYSTEMS.keys())}"}), 400
        if not isinstance(history, list):
            _inc("errors_total"); return jsonify({"error": "history must be a list"}), 400

        _inc("requests_by_mode", mode)

        system = SYSTEMS.get(mode, AUTO_SYSTEM)
        history.append({"role": "user", "content": user_msg})
        messages = [{"role": "system", "content": system}] + history

        if stream:
            def generate():
                full = ""
                stream_resp = client.chat.completions.create(
                    model=model, messages=messages, max_tokens=1024,
                    temperature=0.7, top_p=0.95, stream=True,
                )
                for chunk in stream_resp:
                    if chunk.choices and chunk.choices[0].delta.content:
                        delta = chunk.choices[0].delta.content
                        full += delta
                        yield f"data: {json.dumps({'delta': delta})}\n\n"
                yield f"data: {json.dumps({'done': True, 'response': full})}\n\n"
            return Response(stream_with_context(generate()), mimetype="text/event-stream")

        resp = client.chat.completions.create(
            model=model, messages=messages, max_tokens=1024,
            temperature=0.7, top_p=0.95,
        )
        response_text = resp.choices[0].message.content
        if not response_text:
            return jsonify({"error": "model returned empty response"}), 502
        return jsonify({"response": response_text, "model": model, "mode": mode})

    @app.route("/v1/ask", methods=["POST"])
    def ask_endpoint():
        """Simple single-shot endpoint — no history needed."""
        ok, err, _ = _check_auth_and_rate()
        if not ok:
            _inc("errors_total"); return jsonify({"error": err}), 401 if "Unauthorized" in err else 429
        _inc("requests_total"); _inc("requests_by_endpoint", "/v1/ask")
        data = request.get_json(force=True)
        ok_scope, scope_err = _check_scope_ack(data)
        if not ok_scope:
            _inc("errors_total"); return jsonify({"error": scope_err}), 403
        question = data.get("question", "")
        mode     = data.get("mode", "auto")
        if not question:
            _inc("errors_total"); return jsonify({"error": "question required"}), 400

        system = SYSTEMS.get(mode, AUTO_SYSTEM)
        messages = [
            {"role": "system",  "content": system},
            {"role": "user",    "content": question},
        ]
        resp = client.chat.completions.create(
            model=model, messages=messages, max_tokens=1024,
            temperature=0.7, top_p=0.95,
        )
        return jsonify({"answer": resp.choices[0].message.content, "model": model, "mode": mode})

    @app.route("/v1/triage", methods=["POST"])
    def triage_endpoint():
        """SOC alert triage — classify and prioritize a security alert."""
        ok, err, _ = _check_auth_and_rate()
        if not ok:
            _inc("errors_total"); return jsonify({"error": err}), 401 if "Unauthorized" in err else 429
        _inc("requests_total"); _inc("requests_by_endpoint", "/v1/triage"); _inc("requests_by_mode", "soc")
        data  = request.get_json(force=True)
        ok_scope, scope_err = _check_scope_ack(data)
        if not ok_scope:
            _inc("errors_total"); return jsonify({"error": scope_err}), 403
        alert = data.get("alert", "")
        if not alert:
            _inc("errors_total"); return jsonify({"error": "alert required"}), 400

        prompt = (
            f"Triage the following security alert. Classify severity (Critical/High/Medium/Low/Info), "
            f"identify the MITRE ATT&CK technique(s), determine if it is a True Positive or likely False "
            f"Positive, list immediate containment actions, and recommend next steps.\n\nAlert:\n{alert}"
        )
        messages = [
            {"role": "system", "content": SOC_SYSTEM},
            {"role": "user",   "content": prompt},
        ]
        resp = client.chat.completions.create(
            model=model, messages=messages, max_tokens=1200,
            temperature=0.4, top_p=0.95,
        )
        return jsonify({"triage": resp.choices[0].message.content, "model": model})

    @app.route("/v1/hunt", methods=["POST"])
    def hunt_endpoint():
        """Threat hunting query generator — generate SIEM queries for a given TTP."""
        ok, err, _ = _check_auth_and_rate()
        if not ok:
            _inc("errors_total"); return jsonify({"error": err}), 401 if "Unauthorized" in err else 429
        _inc("requests_total"); _inc("requests_by_endpoint", "/v1/hunt"); _inc("requests_by_mode", "soc")
        data   = request.get_json(force=True)
        ok_scope, scope_err = _check_scope_ack(data)
        if not ok_scope:
            _inc("errors_total"); return jsonify({"error": scope_err}), 403
        target = data.get("target", "")
        siem   = data.get("siem", "splunk")
        if not target:
            _inc("errors_total"); return jsonify({"error": "target required"}), 400

        prompt = (
            f"Generate a {siem.upper()} threat hunting query for: {target}\n"
            f"Include: the query, what data sources are needed, expected fields to review, "
            f"and MITRE ATT&CK mapping. Add comments to explain the logic."
        )
        messages = [
            {"role": "system", "content": SOC_SYSTEM},
            {"role": "user",   "content": prompt},
        ]
        resp = client.chat.completions.create(
            model=model, messages=messages, max_tokens=1200,
            temperature=0.4, top_p=0.95,
        )
        return jsonify({"query": resp.choices[0].message.content, "siem": siem, "model": model})

    @app.route("/v1/respond", methods=["POST"])
    def respond_endpoint():
        """Incident response guidance — PICERL playbook for an incident type."""
        ok, err, _ = _check_auth_and_rate()
        if not ok:
            _inc("errors_total"); return jsonify({"error": err}), 401 if "Unauthorized" in err else 429
        _inc("requests_total"); _inc("requests_by_endpoint", "/v1/respond"); _inc("requests_by_mode", "soc")
        data          = request.get_json(force=True)
        ok_scope, scope_err = _check_scope_ack(data)
        if not ok_scope:
            _inc("errors_total"); return jsonify({"error": scope_err}), 403
        incident_type = data.get("incident", "")
        if not incident_type:
            _inc("errors_total"); return jsonify({"error": "incident required"}), 400

        prompt = (
            f"Provide a detailed PICERL incident response playbook for: {incident_type}\n"
            f"For each phase (Prepare, Identify, Contain, Eradicate, Recover, Lessons Learned), "
            f"provide specific actions, tools to use, evidence to collect, and stakeholder communication steps."
        )
        messages = [
            {"role": "system", "content": SOC_SYSTEM},
            {"role": "user",   "content": prompt},
        ]
        resp = client.chat.completions.create(
            model=model, messages=messages, max_tokens=1500,
            temperature=0.4, top_p=0.95,
        )
        return jsonify({"playbook": resp.choices[0].message.content, "incident": incident_type, "model": model})

    @app.route("/v1/code", methods=["POST"])
    def code_endpoint():
        """Security code generation — uses Qwen 2.5 Coder 32B for best results."""
        ok, err, _ = _check_auth_and_rate()
        if not ok:
            _inc("errors_total"); return jsonify({"error": err}), 401 if "Unauthorized" in err else 429
        _inc("requests_total"); _inc("requests_by_endpoint", "/v1/code"); _inc("requests_by_mode", "code")
        data     = request.get_json(force=True)
        ok_scope, scope_err = _check_scope_ack(data)
        if not ok_scope:
            _inc("errors_total"); return jsonify({"error": scope_err}), 403
        task     = data.get("task", "")
        language = data.get("language", "")
        if not task:
            _inc("errors_total"); return jsonify({"error": "task required"}), 400

        lang_hint = f" Write the solution in {language}." if language else ""
        prompt = f"{task}{lang_hint}\nProvide working, production-ready code with comments."
        messages = [
            {"role": "system", "content": CODE_SYSTEM},
            {"role": "user",   "content": prompt},
        ]
        # Prefer the coder model; fall back to whatever is configured
        code_model = os.getenv("HANCOCK_CODER_MODEL", CODER_MODEL)
        resp = client.chat.completions.create(
            model=code_model, messages=messages, max_tokens=2048,
            temperature=0.2, top_p=0.7,
        )
        return jsonify({
            "code":     resp.choices[0].message.content,
            "model":    code_model,
            "language": language or "auto",
            "task":     task,
        })

    @app.route("/v1/ciso", methods=["POST"])
    def ciso_endpoint():
        """CISO advisor — risk, compliance, board reporting, framework guidance."""
        ok, err, _ = _check_auth_and_rate()
        if not ok:
            _inc("errors_total"); return jsonify({"error": err}), 401 if "Unauthorized" in err else 429
        _inc("requests_total"); _inc("requests_by_endpoint", "/v1/ciso"); _inc("requests_by_mode", "ciso")
        data     = request.get_json(force=True)
        ok_scope, scope_err = _check_scope_ack(data)
        if not ok_scope:
            _inc("errors_total"); return jsonify({"error": scope_err}), 403
        question = data.get("question", "") or data.get("query", "") or data.get("message", "")
        context  = data.get("context", "")
        output   = data.get("output", "advice")
        if not question:
            _inc("errors_total"); return jsonify({"error": "question required"}), 400

        output_hints = {
            "report":        "Format your response as a structured risk report with Executive Summary, Findings, Risk Ratings, and Recommendations.",
            "gap-analysis":  "Format your response as a gap analysis table: Control | Current State | Target State | Gap | Priority.",
            "board-summary": "Format your response as a concise board-ready executive summary (max 300 words, no jargon, business impact focus).",
            "advice":        "",
        }
        hint     = output_hints.get(output, "")
        ctx_line = f"\n\nOrganisation context: {context}" if context else ""
        prompt   = f"{question}{ctx_line}\n\n{hint}".strip()

        messages = [
            {"role": "system", "content": CISO_SYSTEM},
            {"role": "user",   "content": prompt},
        ]
        resp = client.chat.completions.create(
            model=model, messages=messages, max_tokens=2048,
            temperature=0.3, top_p=0.95,
        )
        answer = resp.choices[0].message.content
        if not answer:
            _inc("errors_total"); return jsonify({"error": "model returned empty response"}), 502
        return jsonify({"advice": answer, "output": output, "model": model})

    @app.route("/v1/sigma", methods=["POST"])
    def sigma_endpoint():
        """Sigma detection rule generator — convert a TTP or alert description into a Sigma rule."""
        ok, err, _ = _check_auth_and_rate()
        if not ok:
            _inc("errors_total"); return jsonify({"error": err}), 401 if "Unauthorized" in err else 429
        _inc("requests_total"); _inc("requests_by_endpoint", "/v1/sigma"); _inc("requests_by_mode", "sigma")
        data        = request.get_json(force=True)
        ok_scope, scope_err = _check_scope_ack(data)
        if not ok_scope:
            _inc("errors_total"); return jsonify({"error": scope_err}), 403
        description = data.get("description", "") or data.get("ttp", "") or data.get("query", "")
        logsource   = data.get("logsource", "")    # e.g. "windows sysmon", "linux auditd", "aws cloudtrail"
        technique   = data.get("technique", "")    # e.g. "T1059.001" — auto-tagged if provided
        if not description:
            _inc("errors_total"); return jsonify({"error": "description required"}), 400

        hints = []
        if logsource:
            hints.append(f"Target log source: {logsource}.")
        if technique:
            hints.append(f"MITRE ATT&CK technique: {technique} — use this in the tags field.")
        hint_text = " ".join(hints)

        prompt = (
            f"Write a complete, production-ready Sigma rule for the following:\n\n"
            f"{description}\n\n"
            f"{hint_text}\n\n"
            f"Output the full YAML rule first, then a brief explanation of what it detects "
            f"and any false positive tuning advice."
        ).strip()
        messages = [
            {"role": "system", "content": SIGMA_SYSTEM},
            {"role": "user",   "content": prompt},
        ]
        resp = client.chat.completions.create(
            model=model, messages=messages, max_tokens=2048,
            temperature=0.2, top_p=0.7,
        )
        rule_text = resp.choices[0].message.content
        if not rule_text:
            _inc("errors_total"); return jsonify({"error": "model returned empty response"}), 502
        return jsonify({
            "rule":      rule_text,
            "logsource": logsource or "auto",
            "technique": technique or "auto",
            "model":     model,
        })

    @app.route("/v1/yara", methods=["POST"])
    def yara_endpoint():
        """YARA malware detection rule generator."""
        ok, err, _ = _check_auth_and_rate()
        if not ok:
            _inc("errors_total"); return jsonify({"error": err}), 401 if "Unauthorized" in err else 429
        _inc("requests_total"); _inc("requests_by_endpoint", "/v1/yara"); _inc("requests_by_mode", "yara")
        data        = request.get_json(force=True)
        ok_scope, scope_err = _check_scope_ack(data)
        if not ok_scope:
            _inc("errors_total"); return jsonify({"error": scope_err}), 403
        description = data.get("description", "") or data.get("malware", "") or data.get("query", "")
        file_type   = data.get("file_type", "")   # e.g. "PE", "Office macro", "PDF", "script"
        sample_hash = data.get("hash", "")         # optional SHA256 for meta
        if not description:
            _inc("errors_total"); return jsonify({"error": "description required"}), 400

        hints = []
        if file_type:
            hints.append(f"Target file type: {file_type}.")
        if sample_hash:
            hints.append(f"Known sample hash: {sample_hash} — include in rule meta.")
        hint_text = " ".join(hints)

        prompt = (
            f"Write a complete, production-ready YARA rule for the following:\n\n"
            f"{description}\n\n"
            f"{hint_text}\n\n"
            f"Output the full YARA rule first, then a brief explanation of what it detects "
            f"and any known false positive sources."
        ).strip()
        messages = [
            {"role": "system", "content": YARA_SYSTEM},
            {"role": "user",   "content": prompt},
        ]
        resp = client.chat.completions.create(
            model=model, messages=messages, max_tokens=2048,
            temperature=0.2, top_p=0.7,
        )
        rule_text = resp.choices[0].message.content
        if not rule_text:
            _inc("errors_total"); return jsonify({"error": "model returned empty response"}), 502
        return jsonify({
            "rule":      rule_text,
            "file_type": file_type or "auto",
            "model":     model,
        })

    @app.route("/v1/ioc", methods=["POST"])
    def ioc_endpoint():
        """IOC enrichment — threat intel report for IP, domain, URL, hash, or email."""
        ok, err, _ = _check_auth_and_rate()
        if not ok:
            _inc("errors_total"); return jsonify({"error": err}), 401 if "Unauthorized" in err else 429
        _inc("requests_total"); _inc("requests_by_endpoint", "/v1/ioc"); _inc("requests_by_mode", "ioc")

        data = request.get_json(force=True)
        ok_scope, scope_err = _check_scope_ack(data)
        if not ok_scope:
            _inc("errors_total"); return jsonify({"error": scope_err}), 403
        indicator = (data.get("indicator") or data.get("ioc") or data.get("query") or "").strip()
        ioc_type  = data.get("type", "auto")
        context   = data.get("context", "")
        if not indicator:
            _inc("errors_total"); return jsonify({"error": "indicator required"}), 400

        prompt = f"Indicator: {indicator}\nType: {ioc_type}\n"
        if context:
            prompt += f"Additional context: {context}\n"
        prompt += "\nProvide a full threat intelligence enrichment report."

        messages = [
            {"role": "system", "content": IOC_SYSTEM},
            {"role": "user",   "content": prompt},
        ]
        resp = client.chat.completions.create(
            model=model, messages=messages, max_tokens=1000,
            temperature=0.3, top_p=0.9,
        )
        report = resp.choices[0].message.content
        return jsonify({"indicator": indicator, "type": ioc_type,
                        "report": report, "model": model})

    @app.route("/v1/webhook", methods=["POST"])
    def webhook_endpoint():
        """SIEM/EDR push webhook — auto-triage incoming alerts, optionally notify Slack/Teams."""
        ok, err, _ = _check_auth_and_rate()
        if not ok:
            _inc("errors_total"); return jsonify({"error": err}), 401 if "Unauthorized" in err else 429
        _inc("requests_total"); _inc("requests_by_endpoint", "/v1/webhook"); _inc("requests_by_mode", "soc")

        # ── Optional HMAC-SHA256 signature verification ────────────────────────
        _WEBHOOK_SECRET = os.getenv("HANCOCK_WEBHOOK_SECRET", "")
        if _WEBHOOK_SECRET:
            sig_header = request.headers.get("X-Hancock-Signature", "")
            body_bytes  = request.get_data()
            expected    = "sha256=" + hmac.new(
                _WEBHOOK_SECRET.encode(), body_bytes, hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(sig_header, expected):
                _inc("errors_total")
                return jsonify({"error": "Invalid webhook signature"}), 401

        data     = request.get_json(force=True)
        ok_scope, scope_err = _check_scope_ack(data)
        if not ok_scope:
            _inc("errors_total"); return jsonify({"error": scope_err}), 403
        alert    = data.get("alert", "")
        source   = data.get("source", "unknown")
        severity = data.get("severity", "unknown")
        if not alert:
            _inc("errors_total"); return jsonify({"error": "alert required"}), 400

        prompt = (
            f"[WEBHOOK ALERT from {source.upper()} | Reported severity: {severity.upper()}]\n\n"
            f"Triage this alert. Classify severity (Critical/High/Medium/Low), "
            f"map to MITRE ATT&CK TTP(s), determine True Positive vs False Positive likelihood, "
            f"list immediate containment actions, and recommend next steps.\n\nAlert:\n{alert}"
        )
        messages = [
            {"role": "system", "content": SOC_SYSTEM},
            {"role": "user",   "content": prompt},
        ]
        resp = client.chat.completions.create(
            model=model, messages=messages, max_tokens=1200,
            temperature=0.4, top_p=0.95,
        )
        triage_text = resp.choices[0].message.content

        # ── Optional Slack/Teams notification ─────────────────────────────────
        _send_notification(source, severity, alert, triage_text)

        return jsonify({
            "status":   "triaged",
            "source":   source,
            "severity": severity,
            "triage":   triage_text,
            "model":    model,
        })

    return app  # ← returned for testing


def _send_notification(source: str, severity: str, alert: str, triage: str):
    """Send triage result to Slack or Teams webhook (if configured via env vars)."""
    slack_url = os.getenv("HANCOCK_SLACK_WEBHOOK", "")
    teams_url = os.getenv("HANCOCK_TEAMS_WEBHOOK", "")
    summary   = triage[:400] + "..." if len(triage) > 400 else triage

    if slack_url:
        color = {"critical": "#ff3366", "high": "#ff9900", "medium": "#ffcc00"}.get(
            severity.lower(), "#36a64f")
        payload = json.dumps({
            "attachments": [{
                "color": color,
                "title": f"🔔 Hancock Alert — {source.upper()} [{severity.upper()}]",
                "text":  f"*Alert:* {alert[:200]}\n\n*Triage:* {summary}",
                "footer": "CyberViser Hancock",
            }]
        }).encode()
        try:
            req = urllib.request.Request(slack_url, data=payload,
                                         headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5)
        except urllib.error.URLError:
            pass  # non-fatal

    if teams_url:
        payload = json.dumps({
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": f"Hancock Alert [{severity.upper()}]",
            "themeColor": "FF3366",
            "title": f"🔔 Hancock Alert — {source.upper()} [{severity.upper()}]",
            "text": f"**Alert:** {alert[:200]}\n\n**Triage:** {summary}",
        }).encode()
        try:
            req = urllib.request.Request(teams_url, data=payload,
                                         headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5)
        except urllib.error.URLError:
            pass  # non-fatal


def run_server(client, model: str, port: int):
    """Start the Hancock REST API server."""
    app = build_app(client, model)
    print(f"\n[CyberViser] Hancock API server starting on port {port}")
    print(f"  POST http://localhost:{port}/v1/chat     — conversational (mode: auto|pentest|soc|code)")
    print(f"  POST http://localhost:{port}/v1/ask      — single question")
    print(f"  POST http://localhost:{port}/v1/triage   — SOC alert triage")
    print(f"  POST http://localhost:{port}/v1/hunt     — threat hunting query generator")
    print(f"  POST http://localhost:{port}/v1/respond  — IR playbook (PICERL)")
    print(f"  POST http://localhost:{port}/v1/code     — security code gen (Qwen 2.5 Coder 32B)")
    print(f"  POST http://localhost:{port}/v1/webhook  — SIEM push webhook + Slack/Teams notify")
    print(f"  GET  http://localhost:{port}/health      — status check\n")
    app.run(host="0.0.0.0", port=port, debug=False)


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Hancock — CyberViser AI Agent")
    parser.add_argument("--api-key", default=os.getenv("NVIDIA_API_KEY"), help="NVIDIA NIM API key (only needed for --backend nvidia)")
    parser.add_argument("--model",   default=None, help="Model ID (overrides backend default)")
    parser.add_argument("--server",  action="store_true", help="Run as REST API server")
    parser.add_argument("--port",    type=int, default=int(os.getenv("HANCOCK_PORT", "5000")))
    args = parser.parse_args()

    backend = os.getenv("HANCOCK_LLM_BACKEND", "ollama").lower()

    if backend == "ollama":
        client = make_ollama_client()
        model  = args.model or DEFAULT_MODEL
        print(f"[Hancock] Using Ollama backend ({OLLAMA_BASE_URL}).")
    elif backend == "nvidia" and args.api_key:
        client = make_client(args.api_key)
        model  = args.model or os.getenv("HANCOCK_MODEL", "mistralai/mistral-7b-instruct-v0.3")
        print("[Hancock] Using NVIDIA NIM backend.")
    else:
        client = make_openai_client()
        if not client:
            sys.exit(
                "ERROR: No backend configured.\n"
                "  Option A (local): Install Ollama (https://ollama.com) and set HANCOCK_LLM_BACKEND=ollama\n"
                "  Option B (cloud): Set OPENAI_API_KEY or NVIDIA_API_KEY + HANCOCK_LLM_BACKEND=nvidia"
            )
        model = args.model or OPENAI_MODEL
        print("[Hancock] Using OpenAI backend.")

    if args.server:
        run_server(client, model, args.port)
    else:
        run_cli(client, model)


if __name__ == "__main__":
    main()
