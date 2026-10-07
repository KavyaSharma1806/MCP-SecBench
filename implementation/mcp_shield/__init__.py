"""mcp_shield — hardened defensive middleware for MCP agents (MCP-SecBench v2)."""

from .audit import AuditLog, verify, verify_file
from .detectors import Finding, Label, classify_text
from .policy import Capability, Policy, capability_of, evaluate_call, find_secrets
from .semantic import Ensemble, HeuristicClassifier, OllamaJudge, default_classifier
from .shield import BLOCK_PREFIX, GuardEvent, Shield, apply_shield
from .tools import near_miss, review_tools

__all__ = [
    "AuditLog", "verify", "verify_file", "Finding", "Label", "classify_text", "Capability", "Policy",
    "capability_of", "evaluate_call", "find_secrets", "Ensemble", "HeuristicClassifier", "OllamaJudge",
    "default_classifier", "BLOCK_PREFIX", "GuardEvent", "Shield", "apply_shield", "near_miss", "review_tools",
]
__version__ = "2.0.0"
