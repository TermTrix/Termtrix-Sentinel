# Termtrix-Sentinel

- Termtrix Sentinel is a **human-in-the-loop SecOps automation platform** built on the
  Model Context Protocol (MCP).

It helps security teams **enrich alerts, investigate threats, and orchestrate
incident response** safely using deterministic tools and AI-assisted reasoning.

---

## 🎯 What Termtrix Does (v1)

- Enrich IPs, domains, hashes using MCP tools
- Aggregate threat intelligence
- Produce SOC-ready risk summaries
- Keep full audit logs
- No automatic destructive actions

---

## 🧠 Architecture Overview

- **FastAPI** → API & orchestration
- **FastMCP** → Tool servers (WHOIS, Threat Intel, DNS)
- **LLM** → Summarization & reasoning only
- **Human approval** → Required for actions (future)

---

## 📦 Tech Stack

- Python
- FastAPI
- FastMCP
- Docker
- (Optional) Next.js UI

---

## 🚀 Quick Start (Local)

```bash
git clone https://github.com/TermTrix/Termtrix-Sentinel/
cd Termtrix-Sentinel
cp .env.example .env
docker-compose up --build









# PHASE 3 FLOW

# LangGraph controls flow
#    ↓
# LLM plans actions
#    ↓
# LangGraph pauses
#    ↓
# Human approves
#    ↓
# LangGraph resumes
#    ↓
# MCP executes





# You can add Shodan, AbuseIPDB, GreyNoise later
```

    <!-- Think of Phase 2 as a SOC Analyst Brain 🧠

    Phase 1 = Research Intern
    Phase 2 = L2 SOC Analyst
    Phase 3 = SOAR Engineer

    Your Phase 2 is effectively:

    “Given all evidence, what would a trained SOC analyst do?” -->
