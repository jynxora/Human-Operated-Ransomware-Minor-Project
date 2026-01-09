# Human-Operated Anti-Ransomware  
### Background Research, Tradecraft Analysis & Defensive Modeling  
*(Semester 2 Minor Project — Ongoing)*

---

## Overview

This repository contains **background research, technical notes, and evolving design work** for a Semester 2 minor project focused on **human-operated ransomware** and **pre-encryption attack detection**.

The objective is **not** to build another signature-based ransomware detector, but to study and model:

- how human-operated ransomware campaigns actually unfold
- why most detections happen *after* irreversible damage
- where realistic defensive intervention windows exist *before encryption*

This repository will evolve over time as research deepens and implementation begins.

---

## Problem Statement

Most ransomware defenses trigger **too late**.

By the time encryption or extortion occurs, attackers have often already:
- gained persistent access
- escalated privileges
- performed reconnaissance
- harvested credentials
- tested lateral movement paths
- disabled or bypassed security controls

Human-operated ransomware behaves less like malware and more like **manual intrusion followed by monetization**.

This project asks:

> **Can we identify and disrupt ransomware campaigns *before* encryption by detecting attacker tradecraft rather than payloads?**

---

## Scope of the Project

### In Scope
- Human-operated ransomware campaigns
- Pre-ransom attack chains
- Attacker tradecraft & behavioral patterns
- Detection windows before encryption
- DFIR-informed defensive modeling
- Host- and network-level telemetry analysis
- Research-driven, explainable detection logic

### Out of Scope
- Commodity-only ransomware samples
- Signature-based AV detection
- Fully automated SOC replacement systems
- Generic “AI-powered” detection claims
- Encryption-stage-only defenses

---

## Repository Structure (Planned & Evolving)

.
├── research/
│ ├── incident-reports/
│ ├── campaign-analysis/
│ ├── tradecraft-mapping/
│ └── references.md
│
├── notes/
│ ├── attacker-behaviors.md
│ ├── detection-failures.md
│ ├── soc-blindspots.md
│ └── assumptions.md
│
├── design/
│ ├── threat-model.md
│ ├── detection-hypotheses.md
│ └── system-architecture.md
│
├── experiments/
│ ├── lab-setup/
│ ├── simulations/
│ └── observations.md
│
├── writeups/
│ ├── background-research.pdf
│ └── background-research.md
│
└── README.md

yaml
Copy code

> This structure will expand as the project moves from **research → modeling → experimentation → implementation**.

---

## Current Status

- ✅ Background research on human-operated ransomware
- ✅ Study of real-world campaigns (Ryuk, DoppelPaymer, Dharma/Wadhrama, etc.)
- ✅ Pre-ransom attack chain mapping
- ✅ Identification of recurring attacker behaviors
- ⏳ Defensive modeling (in progress)
- ⏳ Lab-based experimentation
- ⏳ Prototype development

No claims of a finished solution are made at this stage.

---

## Research Methodology

The research in this repository is based on:
- Public DFIR reports
- Incident response case studies
- Post-breach timelines
- ATT&CK-aligned behavior mapping
- Cross-campaign pattern analysis
- Practical lab replication where feasible

Emphasis is placed on **why attacks succeed**, not just *what tools were used*.

---

## Design Philosophy

- Detection over prevention
- Behavior over indicators
- Explainability over black-box models
- Practical SOC relevance
- Failures are documented, not hidden

This is a **learning-first engineering project**, not a product pitch.

---

## Disclaimer

This repository is:
- academic
- educational
- defensive in nature

No offensive tooling or live exploitation code is intended for misuse.

---

## Author

**Jinay Shah**  
DFIR • Exploitation • Systems Security  
#700DaysOfSkill

---

## License

This project is currently shared for educational and research purposes only.  
Licensing will be clarified as the project matures.
