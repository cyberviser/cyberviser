<div align="center">

```
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██╗   ██╗██╗███████╗███████╗██████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██║   ██║██║██╔════╝██╔════╝██╔══██╗
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║   ██║██║███████╗█████╗  ██████╔╝
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚██╗ ██╔╝██║╚════██║██╔══╝  ██╔══██╗
╚██████╗   ██║   ██████╔╝███████╗██║  ██║ ╚████╔╝ ██║███████║███████╗██║  ██║
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝
```

</div>


<div align="center">

```
**AI-powered cybersecurity. Built for operators.**
[![Email](https://img.shields.io/badge/Contact-contact@cyberviser.ai-00e5ff?style=flat-square&logo=gmail)](cyberviser@cyberviserai.com)
```

</div>

<div align="center">

Operated by **Johnny Watters** under the GitHub identities
`cyberviser`, `cyberviser-dotcom`, and `0ai-Cyberviser`.

</div>



<iframe src="https://www.linkedin.com/embed/feed/update/urn:li:ugcPost:7433487692803346432?collapsed=1" height="508" width="504" frameborder="0" allowfullscreen="" title="Embedded post"></iframe>
---

### 🛡️ What We Build

We build **Hancock** — an AI cybersecurity agent fine-tuned on Mistral 7B using MITRE ATT&CK, NVD/CVE, CISA KEV, Atomic Red Team, and GitHub Advisories. One agent. Eight specialist modes. A full REST API with 12 endpoints.

```
🔴 Pentest    →  Recon · Exploitation · CVE Research · PTES Reporting
🔵 SOC        →  Alert Triage · SIEM Queries · Incident Response · Threat Hunting
👔 CISO       →  Risk Reporting · Compliance · Board Summaries · Gap Analysis
⚡ Auto       →  Context-aware switching between all modes
💻 Code       →  YARA · KQL · SPL · Sigma · Python · Bash
🔍 Sigma      →  Detection rule authoring with ATT&CK tagging
🦠 YARA       →  Malware detection rule authoring
🔎 IOC        →  Threat intelligence enrichment for IOCs
```

---

### 📦 Repositories

| Repo | Description | Status |
|------|-------------|--------|
| [**Hancock**](https://github.com/cyberviser/Hancock) | 🤖 AI security agent — Mistral 7B + NVIDIA NIM | ✅ Live |

---

### 🚀 Quick Deploy Hancock

```bash
git clone https://github.com/cyberviser/Hancock.git
cd Hancock && make setup
python hancock_agent.py --server
# POST http://localhost:5000/v1/triage  {"alert": "..."}
# All API POST requests require scope acknowledgement: include {"scope": "authorized"}
# or set env HANCOCK_SCOPE_ACK=authorized (set HANCOCK_REQUIRE_SCOPE_ACK=0 to disable).
```

---

### 📬 Commercial Licensing

CyberViser software and branding are operated by Johnny Watters
(`0ai-Cyberviser`). For enterprise licensing, integrations, or partnerships:
**0ai@cyberviserai.com** · **cyberviser@proton.me**

---

<div align="center">
  <sub>© 2026 Johnny Watters / CyberViser · All Rights Reserved · <a href="https://cyberviser.netlify.app">cyberviser.netlify.app</a></sub>
</div>
