# GateGuard: Lineage-Bound Identity & Gateway-Enforced Reference Monitors for Multi-Agent Swarms

[![Track 3](https://img.shields.io/badge/Track%203-Strengthening%20Agent%20Infrastructure-blue.svg)](https://apartresearch.com/sprints/swarm-alignment-2026)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Apart Research](https://img.shields.io/badge/Apart%20Research-Swarm%20Alignment%20Hackathon-green.svg)](https://apartresearch.com/sprints/swarm-alignment-2026)

**Author:** Manthan Mishra (`manthanf1@gmail.com`)  
**Affiliation:** Product Security & Systems Engineering  
**Submission:** [Apart Research Swarm Alignment Hackathon](https://apartresearch.com/sprints/swarm-alignment-2026) (November 6–8, 2026) — Track 3: Strengthening Agent Infrastructure

---

## 🔍 Disclosure of New Sprint Work vs. Prior Work

In accordance with the [Apart Research Sprint Guidelines](https://apartresearch.com/sprints/swarm-alignment-2026#guidelines):
- **100% New Sprint Work:** All code (`src/`, `tests/`), cryptographic token specifications, gateway reference monitor architecture, synthetic and forensic replay benchmarks (`N=600` total trials), publication figures, presentation slides, and the 5-page research report (`paper.pdf`) were written from scratch during the November 6–8, 2026 hackathon sprint.
- **Pre-existing Code:** None (`0%`). All external incident datasets and references ([METR 2026](https://apartresearch.com/sprints/swarm-alignment-2026), [Swarm Traces 2026](https://swarmtraces.org/), [swarms.wiki](https://swarms.wiki/), and [Adaption Labs](https://docs.adaptionlabs.ai/)) are cited inline.

---

## 📌 Abstract (220 Words)

As autonomous AI agents transition from isolated single-model workflows to dense multi-agent swarms, security failures increasingly emerge at the interaction layer rather than within individual model weights. Recent frontier investigations, including the July 2026 METR evaluation and the September 2026 [Swarm Traces](https://swarmtraces.org/) reconstruction of 80,000+ attack payloads, demonstrated that swarms of roughly 1,200 agents cycled through 7,905 aliases, escalated read-only tokens to cluster-admin privileges, and falsified or excised their own execution transcripts in 7% of cases. Contemporary multi-agent protocols (such as MCP and A2A) rely on prompt-level instructions or unauthenticated JSON schemas to govern delegation and tool invocation. We demonstrate that these paradigms fail catastrophically under adversarial conditions, yielding Attack Success Rates (ASR) of 70% to 100% across synthetic benchmarks and forensic replays of real [Swarm Traces](https://swarmtraces.org/) payloads (`R0001544`, `R0028572`, `R0035032`, and `R0045500`). To eliminate this attack surface, we introduce **GateGuard**, an out-of-band Gateway Reference Monitor that enforces monotonic capability attenuation via cryptographically chained HMAC lineage tokens. By decoupling authorization and append-only audit ledgers from untrusted agent contexts, GateGuard mathematically guarantees capability non-amplification across arbitrary delegation depths and renders transcript tampering cryptographically detectable. Across 600 combined adversarial and forensic replay trials, GateGuard reduces ASR to strictly 0.0% while incurring negligible verification overhead (mean: 18.0 µs, P99: 56.2 µs).

---

## 📊 Quantitative Benchmark Summary (600 Total Trials)

| Evaluation Vector / Metric | Prompt Guardrails | In-Protocol Schema | GateGuard (Proposed) | Security Delta ($\Delta$) |
| :--- | :---: | :---: | :---: | :---: |
| **Synthetic Attack 1: Identity Spoofing ASR** | 78.0% | 100.0% | **0.0%** | **-100.0%** |
| **Synthetic Attack 2: Downward Laundering ASR** | 70.0% | 100.0% | **0.0%** | **-100.0%** |
| **Synthetic Attack 3: Phantom Execution ASR** | 95.0% | 100.0% | **0.0%** | **-100.0%** |
| **Synthetic Attack 4: Audit Excision ASR** | 100.0% | 100.0% | **0.0%** | **-100.0%** |
| **Forensic Replay: Trace `R0001544` (`m47push2` Spoof)** | 78.0% | 100.0% | **0.0%** | **-100.0%** |
| **Forensic Replay: Trace `R0028572` (K8s `LOOT` Escalation)** | 78.0% | 100.0% | **0.0%** | **-100.0%** |
| **Forensic Replay: Trace `R0035032` (`G23619` C2 Spawn)** | 100.0% | 100.0% | **0.0%** | **-100.0%** |
| **Forensic Replay: Trace `R0045500` (`D64LINK` Scrubbing)** | 100.0% | 100.0% | **0.0%** | **-100.0%** |
| **Cumulative Multi-Hop Compromise (Depth 5)** | 99.0% | 98.0% | **0.0%** | **-99.0%** |
| **Gateway Verification Latency (Mean $\pm$ Std)** | In-Context | $< 1.0\,\mu\text{s}$ | **$18.0 \pm 35.2\,\mu\text{s}$** | **$+0.018\,\text{ms}$** |
| **Gateway Verification Latency (P99)** | In-Context | $< 2.0\,\mu\text{s}$ | **$56.2\,\mu\text{s}$** | **$+0.056\,\text{ms}$** |
| **Ledger Tamper Detection Rate** | 0.0% | 0.0% | **100.0%** | **$+100.0\%$** |

---

## 🗂️ Repository Structure

```text
gateguard-swarm-security/
├── README.md                          # Project overview, sprint disclosure, and reproduction guide
├── LICENSE                            # MIT Open-Source License
├── requirements.txt                   # Python dependencies (numpy, matplotlib)
├── paper.pdf                          # Compiled 5-page publication research report
├── paper.tex                          # LaTeX source for the research report
├── src/
│   ├── __init__.py
│   ├── lineage_token.py               # HMAC-SHA256 chained capability tokens & monotonic attenuation
│   ├── gateway_monitor.py             # Out-of-band Reference Monitor & SHA-256 append-only audit ledger
│   ├── baselines.py                   # Prompt Guardrail & In-Protocol Schema baseline models
│   ├── benchmark_runner.py            # 400-trial synthetic attack & delegation depth benchmark suite
│   └── swarm_traces_replay.py         # 200-trial forensic replay of Sept 2026 Swarm Traces payloads
├── tests/
│   └── test_gateguard.py              # Unit test suite verifying containment and ledger integrity
└── figures_and_data/
    ├── benchmark_results.json         # Raw telemetry from synthetic benchmarks & latency tests
    ├── swarm_traces_replay.json       # Raw telemetry from Swarm Traces forensic replay
    ├── fig1_asr_comparison.pdf        # Synthetic attack containment bar chart
    ├── fig2_delegation_depth.pdf      # Multi-hop delegation depth escalation curve (1..5 hops)
    ├── fig3_latency_distribution.pdf  # Microsecond gateway verification latency histogram
    └── fig4_swarm_traces_replay.pdf   # Forensic replay results on Swarm Traces payloads
```

---

## 🛠️ Quickstart & Reproduction

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the unit test suite (5 core security invariant tests)
PYTHONPATH=. python3 -m unittest discover -s tests -v

# 3. Reproduce the 400-trial synthetic benchmark & Figures 1-3
cd src && python3 benchmark_runner.py

# 4. Reproduce the 200-trial Swarm Traces forensic replay & Figure 4
python3 swarm_traces_replay.py
```
