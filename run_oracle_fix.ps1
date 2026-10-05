# Re-measures every attack type whose original scoring used the wrong oracle
# (operation-file instead of MSB's parameter-leak definition). Overwrites the
# stale rows in results/*.csv via cli_runner's (mode, llm, scenario) dedup key.
Set-Location "C:\Users\kavya\OneDrive\Documents\SEM5\AI_project"
$env:Path = "C:\Users\kavya\.local\bin;$env:Path"
$env:OLLAMA_MODELS = "C:\Users\kavya\OneDrive\Documents\SEM5\AI_project\tools\ollama\models"

foreach ($llm in @("ollama/llama3.2:3b", "ollama/llama3.1:8b")) {
  foreach ($mode in @("baseline", "defended")) {
    Write-Output "=== $llm | $mode | out_of_scope_parameter | DuckDuckGo ==="
    .\.venv\Scripts\python.exe cli_runner.py --mode $mode --llm $llm --attack_type out_of_scope_parameter --attack_task all --agent information_gathering --tool DuckDuckGo_Search_Server
    Write-Output "=== $llm | $mode | out_of_scope_parameter | Terminal_Controller ==="
    .\.venv\Scripts\python.exe cli_runner.py --mode $mode --llm $llm --attack_type out_of_scope_parameter --attack_task all --agent it_development_management --tool Terminal_Controller
  }
}

# Coverage rows (n=1) for the other two parameter-leak attack types
foreach ($mode in @("baseline", "defended")) {
  foreach ($at in @("tool_transfer", "preference_manipulation-out_of_scope_parameter")) {
    Write-Output "=== llama3.2:3b | $mode | $at (coverage, n=1) ==="
    .\.venv\Scripts\python.exe cli_runner.py --mode $mode --llm ollama/llama3.2:3b --attack_type $at --attack_task obtain_agent_interaction_data --agent it_development_management --tool Terminal_Controller --limit 1
  }
}
Write-Output "ORACLE FIX RERUN COMPLETE"
