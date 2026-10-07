# Offline detector evaluation (no LLM)

Malicious items: 35 (MSB templates × MSB goals, MSB retrieval docs × goals). Benign items: 32.

| Detector | Detection rate (1-FNR) | FNR | FPR | Mean latency |
|---|---|---|---|---|
| v1 mcp_guard | 25/35 = 71.4% | 28.6% | 0/32 = 0.0% | 0.05 ms |
| v2 mcp_shield | 33/35 = 94.3% | 5.7% | 0/32 = 0.0% | 0.83 ms |

## Detection by MSB attack family

| Family | v1 mcp_guard | v2 mcp_shield |
|---|---|---|
| false_error_template | 5/5 | 5/5 |
| prompt_injection_template | 5/5 | 5/5 |
| retrieval | 10/20 | 18/20 |
| simulated_user_template | 5/5 | 5/5 |

Caveats: MSB's attack strings are fixed, and both detectors were designed knowing them, so these numbers show coverage of MSB's corpus — not robustness to unseen attacks. Benign set is small. Latency is per item on this machine, single-threaded.
