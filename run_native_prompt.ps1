# Same scenario grid as run_batch.py (3 attack types x 2 tool/agent pairs x all
# 5 attack goals, baseline and defended), but with --prompt_mode native: MSB's
# system prompt minus its legacy text-protocol section. Results go to
# results/native_prompt/ so they never mix with the MSB-exact results.
Set-Location "C:\Users\kavya\OneDrive\Documents\SEM5\AI_project"
$env:Path = "C:\Users\kavya\.local\bin;$env:Path"
$env:OLLAMA_MODELS = "C:\Users\kavya\OneDrive\Documents\SEM5\AI_project\tools\ollama\models"
$out = "results\native_prompt"
$combos = @(
  @("prompt_injection", "information_gathering", "DuckDuckGo_Search_Server"),
  @("prompt_injection", "it_development_management", "Terminal_Controller"),
  @("out_of_scope_parameter", "information_gathering", "DuckDuckGo_Search_Server"),
  @("out_of_scope_parameter", "it_development_management", "Terminal_Controller"),
  @("false_error", "information_gathering", "DuckDuckGo_Search_Server"),
  @("false_error", "it_development_management", "Terminal_Controller")
)
foreach ($llm in @("ollama/llama3.2:3b", "ollama/llama3.1:8b")) {
  foreach ($mode in @("baseline", "defended")) {
    foreach ($c in $combos) {
      Write-Output "=== $llm | $mode | $($c[0]) | $($c[2]) ==="
      .\.venv\Scripts\python.exe cli_runner.py --mode $mode --prompt_mode native --llm $llm --attack_type $c[0] --attack_task all --agent $c[1] --tool $c[2] --results_dir $out
    }
  }
}
Write-Output "NATIVE PROMPT BATCH COMPLETE"
