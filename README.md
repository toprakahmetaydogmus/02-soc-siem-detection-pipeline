# 🛡️ SOC & SIEM Detection Pipeline Lab (Wazuh, Elastic, Sigma)

[![GitHub release (latest by date)](https://img.shields.io/github/v/release/toprakahmetaydogmus/02-soc-siem-detection-pipeline?color=blue&label=Release)](https://github.com/toprakahmetaydogmus/02-soc-siem-detection-pipeline/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![Sigma Rules](https://img.shields.io/badge/Sigma-Detection%20Engineering-orange.svg)](https://github.com/SigmaHQ/sigma)

Developer: **Toprak Ahmet Aydoğmuş**

---

## 🎯 1. Overview
A production-grade SOC/SIEM telemetry processing and detection engine. Translates generic Sigma rules into Elastic DSL / Lucene queries, correlates log streams (Sysmon, Windows Event Logs, Linux Auth), and flags high-fidelity security alerts with real-time web visualization.

### Key Capabilities:
- **Sigma Compiler & Parser:** Automated translation of Sigma YAML rules into Elasticsearch and Wazuh queries.
- **Real-time Pipeline:** High-throughput event ingestion and alert dispatching engine.
- **Alert Correlation:** MITRE ATT&CK tactic/technique tagging and anomaly score generation.

---

## 🚀 2. Quick Start

```bash
git clone https://github.com/toprakahmetaydogmus/02-soc-siem-detection-pipeline.git
cd 02-soc-siem-detection-pipeline

# Run test verification
python -m unittest discover tests/

# Launch SIEM Event Ingestion Engine
python -m src.siem_engine --ingest sample_logs/
```

---

## 📜 3. License
Licensed under the [MIT License](LICENSE).  
Developer: **Toprak Ahmet Aydoğmuş**.
