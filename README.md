<div align="center">

```
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██╗   ██╗██╗███████╗███████╗██████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██║   ██║██║██╔════╝██╔════╝██╔══██╗
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║   ██║██║███████╗█████╗  ██████╔╝
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚██╗ ██╔╝██║╚════██║██╔══╝  ██╔══██╗
╚██████╗   ██║   ██████╔╝███████╗██║  ██║ ╚████╔╝ ██║███████║███████╗██║  ██║
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝
```

**AI-powered cybersecurity. Built for operators.**

[![Website](https://img.shields.io/badge/Website-cyberviser.github.io-00ff88?style=flat-square&logo=github)](https://cyberviser.github.io/Hancock/)
[![Email](https://img.shields.io/badge/Contact-contact@cyberviser.ai-00e5ff?style=flat-square&logo=gmail)](mailto:contact@cyberviser.ai)

</div>

---

### 🛡️ What We Build

We're building **Hancock** — an AI cybersecurity agent fine-tuned on Mistral 7B using MITRE ATT&CK, NVD/CVE, and real-world pentest knowledge. One agent. Three specialist modes. A full REST API.

```
Pentest Mode  →  Recon · Exploitation · CVE Research · PTES Reporting
SOC Mode      →  Alert Triage · SIEM Queries · Incident Response · Threat Hunting
CISO Mode     →  Risk Reporting · Compliance · Board Summaries  [Phase 3]
```

---

### 📦 Repositories

| Repo | Description | Status |
|------|-------------|--------|
| [**Hancock**](https://github.com/cyberviser/Hancock) | 🤖 AI security agent — Mistral 7B + NVIDIA NIM | 🔨 Building |
| [**TerminalPressure**](https://github.com/cyberviser/TerminalPressure) | 💥 Authorized pentest toolkit — nmap, scapy, exploit chains | ✅ Live |

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

All software is proprietary. For enterprise licensing, integrations, or partnerships:
**contact@cyberviser.ai**

---

<div align="center">
  <sub>© 2025 CyberViser · All Rights Reserved · <a href="https://cyberviser.github.io/Hancock/">cyberviser.github.io/Hancock</a></sub>
</div>
