"""
Windows-compatible environment setup for the MSB baseline.

baseline/setup.py (the upstream script) assumes a POSIX shell: it shells out to
`which uv` and *moves* baseline/scripts/agent.py into the installed langchain
package. Neither works cleanly on Windows (no `which`, and moving the file
would delete it from the baseline copy we want to keep untouched for
comparison/auditing purposes).

This script performs the same setup steps, but:
  - resolves `uv` with shutil.which() instead of `which`
  - writes Windows-native paths, correctly escaped for JSON
  - COPIES scripts/agent.py into langchain instead of moving it, so
    baseline/ remains a faithful, complete copy of the upstream repo
"""
import json
import os
import shutil
import sys

import langchain

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
BASELINE_DIR = os.path.join(ROOT_DIR, "baseline")


def replace_content(file_path, target_str, new_str, uv_abs_path=None):
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
    content = content.replace(target_str, new_str)
    if uv_abs_path is not None:
        content = content.replace('"uv"', f'"{uv_abs_path}"')
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)


def to_json_path(path: str) -> str:
    """Return a path safe to splice into a JSON string literal (escaped backslashes)."""
    return path.replace("\\", "\\\\")


def main():
    log_path = os.path.join(BASELINE_DIR, "logs")
    os.makedirs(log_path, exist_ok=True)
    output_path = os.path.join(BASELINE_DIR, "operation_space", "output")
    os.makedirs(output_path, exist_ok=True)

    # 1. Locate uv
    uv_path = shutil.which("uv")
    if uv_path is None:
        print("ERROR: uv executable not found in PATH. Please check if uv is installed.")
        sys.exit(1)
    uv_path_json = to_json_path(uv_path)

    # 2. Rewrite attack_tools + matching normal_tools mcp_config.json paths
    tools_dir = os.path.join(BASELINE_DIR, "data", "tools")
    for root, dirs, files in os.walk(tools_dir):
        if "attack_tools" in root and "mcp_config.json" in files:
            attack_tool_path = os.path.join(root, "mcp_config.json")
            parent_dir_abs_path = to_json_path(os.path.abspath(root))
            replace_content(
                attack_tool_path,
                "/ABSOLUTE/PATH/TO/PARENT/FOLDER/",
                parent_dir_abs_path,
                uv_path_json,
            )

            mcp_name = os.path.basename(root)
            normal_tool_path = os.path.join(
                BASELINE_DIR, "data", "tools", "normal_tools", f"{mcp_name}.json"
            )
            if os.path.exists(normal_tool_path):
                replace_content(
                    normal_tool_path,
                    "/ABSOLUTE/PATH/TO/PARENT/FOLDER/",
                    parent_dir_abs_path,
                    uv_path_json,
                )
            print(f"Configured attack tool: {mcp_name}")

    # 3. Filesystem support tool paths
    info_path = os.path.join(BASELINE_DIR, "operation_space", "information")
    os.makedirs(info_path, exist_ok=True)
    output_path = os.path.join(BASELINE_DIR, "operation_space", "output")
    support_tool_path = os.path.join(
        BASELINE_DIR, "data", "tools", "support_tools", "Filesystem_MCP_Server.json"
    )
    replace_content(
        support_tool_path,
        "/ABSOLUTE/PATH/TO/operation_space/information",
        to_json_path(info_path),
    )
    replace_content(
        support_tool_path,
        "/ABSOLUTE/PATH/TO/operation_space/output",
        to_json_path(output_path),
    )

    # 4. Copy (not move) the MSB langchain AgentExecutor patch into the active venv's langchain install
    langchain_path = os.path.dirname(langchain.__file__)
    target_file = os.path.join(langchain_path, "agents", "agent.py")
    src_file = os.path.join(BASELINE_DIR, "scripts", "agent.py")
    if os.path.exists(src_file):
        shutil.copy(src_file, target_file)
        print(f"Patched {target_file} (copied from baseline/scripts/agent.py)")
    else:
        print("WARNING: baseline/scripts/agent.py not found; langchain AgentExecutor was not patched. "
              "Tool-response attacks (false_error / simulated_user / search_term_deception) will not work.")

    # 5. Task file placeholders
    agent_task_path = os.path.join(BASELINE_DIR, "data", "agent_task.jsonl")
    replace_content(
        agent_task_path,
        "/ABSOLUTE/PATH/TO/SPACE/INFORMATION",
        to_json_path(info_path),
    )

    attack_task_path = os.path.join(BASELINE_DIR, "data", "attack_task.jsonl")
    attack_output_path = to_json_path(os.path.join(output_path, "file_name.txt"))
    replace_content(
        attack_task_path,
        "/ABSOLUTE/PATH/TO/SPACE/OUTPUT/FILENAME",
        attack_output_path,
    )
    personal_info_path = to_json_path(os.path.join(info_path, "personal_information.json"))
    replace_content(
        attack_task_path,
        "/ABSOLUTE/PATH/TO/SPACE/INFORMATION/PERSONAL",
        personal_info_path,
    )

    print("Windows setup completed successfully!")


if __name__ == "__main__":
    main()
