from __future__ import annotations

from typing import List, Tuple

from .rules import Finding
from .rules import cloudformation, dockerfile, kubernetes, terraform


def detect_file_type(filename: str, content: str) -> str:
    lower_name = filename.lower()
    if lower_name.endswith(".tf"):
        return "terraform"
    if lower_name.endswith((".yml", ".yaml")):
        return "kubernetes"
    if "awstemplateformatversion" in content.lower():
        return "cloudformation"
    if lower_name.endswith(".json") and "cloudformation" in content.lower():
        return "cloudformation"
    if lower_name.endswith("dockerfile") or lower_name.endswith(".dockerfile"):
        return "dockerfile"
    return "unknown"


def _rules_for_type(file_type: str):
    if file_type == "terraform":
        return terraform.get_rules()
    if file_type == "kubernetes":
        return kubernetes.get_rules()
    if file_type == "cloudformation":
        return cloudformation.get_rules()
    if file_type == "dockerfile":
        return dockerfile.get_rules()
    return []


def scan_file(filename: str, content: str) -> Tuple[str, List[Finding]]:
    file_type = detect_file_type(filename, content)
    findings: List[Finding] = []
    for rule in _rules_for_type(file_type):
        findings.extend(rule.match(content, filename))
    return file_type, findings
