# MSB Baseline vs. mcp_guard-Defended — ASR Comparison (ollama/llama3.2:3b)

| attack_type | n (base/def) | Baseline ASR % | Defended ASR % | Mitigation rate |
|---|---|---|---|---|
| false_error | 25/25 | 0.0 | 0.0 | n/a (baseline 0) |
| name_overlap | 1/1 | 0.0 | 0.0 | n/a (baseline 0) |
| out_of_scope_parameter | 25/25 | 36.0 | 0.0 | 100.0% |
| preference_manipulation | 1/1 | 0.0 | 0.0 | n/a (baseline 0) |
| preference_manipulation-out_of_scope_parameter | 1/1 | 0.0 | 0.0 | n/a (baseline 0) |
| preference_manipulation-simulated_user | 1/1 | 0.0 | 0.0 | n/a (baseline 0) |
| prompt_injection | 25/25 | 0.0 | 0.0 | n/a (baseline 0) |
| prompt_injection-false_error | 1/1 | 0.0 | 0.0 | n/a (baseline 0) |
| prompt_injection-simulated_user | 1/1 | 0.0 | 0.0 | n/a (baseline 0) |
| simulated_user | 1/1 | 0.0 | 0.0 | n/a (baseline 0) |
| tool_transfer | 1/1 | 0.0 | 0.0 | n/a (baseline 0) |

## Overall

| attack_type | Baseline ASR % | Defended ASR % | Mitigation rate | guard_blocks | guard_signature | guard_parameter | guard_response |
|---|---|---|---|---|---|---|---|
| Overall | 10.84 | 0.0 | 100.0% | 46 | 0 | 10 | 1 |
