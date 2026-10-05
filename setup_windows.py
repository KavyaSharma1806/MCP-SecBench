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
  - dynamically rewrites hardcoded author paths and placeholders to current paths
"""
import json
import os
import re
import shutil
import sys

import langchain

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
BASELINE_DIR = os.path.join(ROOT_DIR, "baseline")


def to_json_path(path: str) -> str:
    """Return a path safe to splice into a JSON string literal (escaped backslashes)."""
    return path.replace("\\", "\\\\")


def update_mcp_config(file_path: str, uv_path: str, server_dir: str):
    """Load an MCP config JSON and ensure the command points to the current uv and server dir."""
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    for server_name, server_cfg in data.get("mcpServers", {}).items():
        server_cfg["command"] = uv_path
        if "args" in server_cfg and len(server_cfg["args"]) >= 2 and server_cfg["args"][0] == "--directory":
            server_cfg["args"][1] = server_dir
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


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

    # 2. Rewrite attack_tools + matching normal_tools mcp_config.json paths
    tools_dir = os.path.join(BASELINE_DIR, "data", "tools")
    for root, dirs, files in os.walk(tools_dir):
        if "attack_tools" in root and "mcp_config.json" in files:
            attack_tool_path = os.path.join(root, "mcp_config.json")
            parent_dir_abs_path = os.path.abspath(root)
            update_mcp_config(attack_tool_path, uv_path, parent_dir_abs_path)

            mcp_name = os.path.basename(root)
            normal_tool_path = os.path.join(
                BASELINE_DIR, "data", "tools", "normal_tools", f"{mcp_name}.json"
            )
            if os.path.exists(normal_tool_path):
                update_mcp_config(normal_tool_path, uv_path, parent_dir_abs_path)
            print(f"Configured attack tool: {mcp_name}")

    # 3. Filesystem support tool paths
    info_path = os.path.join(BASELINE_DIR, "operation_space", "information")
    os.makedirs(info_path, exist_ok=True)
    output_path = os.path.join(BASELINE_DIR, "operation_space", "output")
    support_tool_path = os.path.join(
        BASELINE_DIR, "data", "tools", "support_tools", "Filesystem_MCP_Server.json"
    )
    if os.path.exists(support_tool_path):
        with open(support_tool_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if "mcpServers" in data and "filesystem" in data["mcpServers"]:
            data["mcpServers"]["filesystem"]["args"] = [
                "-y",
                "@modelcontextprotocol/server-filesystem",
                output_path,
                info_path,
            ]
        with open(support_tool_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print("Configured support tool: Filesystem_MCP_Server")

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
    if os.path.exists(agent_task_path):
        with open(agent_task_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        new_lines = []
        for line in lines:
            line = re.sub(
                r'([A-Za-z]:[\\/][^"\']*?operation_space[\\/]+information|/ABSOLUTE/PATH/TO/SPACE/INFORMATION)',
                lambda m: to_json_path(info_path),
                line,
            )
            new_lines.append(line)
        with open(agent_task_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
        print("Configured agent_task.jsonl")

    attack_task_path = os.path.join(BASELINE_DIR, "data", "attack_task.jsonl")
    if os.path.exists(attack_task_path):
        attack_output_path = to_json_path(os.path.join(output_path, "file_name.txt"))
        personal_info_path = to_json_path(os.path.join(info_path, "personal_information.json"))
        with open(attack_task_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        new_lines = []
        for line in lines:
            line = re.sub(
                r'([A-Za-z]:[\\/][^"\']*?operation_space[\\/]+output[\\/]+file_name\.txt|/ABSOLUTE/PATH/TO/SPACE/OUTPUT/FILENAME)',
                lambda m: attack_output_path,
                line,
            )
            line = re.sub(
                r'([A-Za-z]:[\\/][^"\']*?operation_space[\\/]+information[\\/]+personal_information\.json|/ABSOLUTE/PATH/TO/SPACE/INFORMATION/PERSONAL)',
                lambda m: personal_info_path,
                line,
            )
            new_lines.append(line)
        with open(attack_task_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
        print("Configured attack_task.jsonl")

    print("Windows setup completed successfully!")


if __name__ == "__main__":
    main()
