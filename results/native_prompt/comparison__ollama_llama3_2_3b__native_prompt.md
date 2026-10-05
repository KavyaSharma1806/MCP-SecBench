# MSB Baseline vs. mcp_guard-Defended — ASR Comparison (ollama/llama3.2:3b)

| attack_type | n (base/def) | Baseline ASR % | Defended ASR % | Mitigation rate |
|---|---|---|---|---|
| false_error | 25/25 | 0.0 | 0.0 | n/a (baseline 0) |
| out_of_scope_parameter | 25/25 | 24.0 | 0.0 | 100.0% |
| prompt_injection | 25/25 | 0.0 | 0.0 | n/a (baseline 0) |

## Overall

| attack_type | Baseline ASR % | Defended ASR % | Mitigation rate | guard_blocks | guard_signature | guard_parameter | guard_response |
|---|---|---|---|---|---|---|---|
| Overall | 8.0 | 0.0 | 100.0% | 39 | 0 | 13 | 26 |
