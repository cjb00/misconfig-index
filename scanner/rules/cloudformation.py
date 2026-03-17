from __future__ import annotations

import re
from typing import List

from .base import Finding, Rule, Severity


# ── Helpers ───────────────────────────────────────────────────────────────────

def _cfn_resource_blocks(content: str, resource_type: str) -> list[tuple[str, int]]:
    """
    Return (block_content, start_line_1indexed) for each CloudFormation resource
    of the given Type (e.g. 'AWS::S3::Bucket').

    Works with standard YAML indentation: the resource logical-name key sits at
    some indent level, and its children (Type, Properties, …) are indented further.
    """
    lines = content.splitlines()
    type_pattern = re.compile(
        rf"^\s+Type:\s+{re.escape(resource_type)}\s*$"
    )
    results: list[tuple[str, int]] = []

    for i, line in enumerate(lines):
        if not type_pattern.match(line):
            continue

        type_indent = len(line) - len(line.lstrip())

        # Walk backward to find the resource logical-name line (less indented)
        res_start = i
        for j in range(i - 1, -1, -1):
            stripped = lines[j].strip()
            if not stripped or stripped.startswith("#"):
                continue
            if (len(lines[j]) - len(lines[j].lstrip())) < type_indent:
                res_start = j
                break

        res_indent = len(lines[res_start]) - len(lines[res_start].lstrip())

        # Collect all lines that belong to this resource block
        block: list[str] = [lines[res_start]]
        j = res_start + 1
        while j < len(lines):
            l = lines[j]
            stripped = l.strip()
            if stripped and not stripped.startswith("#"):
                if (len(l) - len(l.lstrip())) <= res_indent:
                    break
            block.append(l)
            j += 1

        results.append(("\n".join(block), res_start + 1))

    return results


# ── Rules ─────────────────────────────────────────────────────────────────────

_PAB_KEYS = [
    "BlockPublicAcls",
    "BlockPublicPolicy",
    "IgnorePublicAcls",
    "RestrictPublicBuckets",
]


class CfnS3PublicAccess(Rule):
    id = "CFN_S3_PUBLIC_ACCESS"
    category = "storage"
    title = "S3 bucket public access not blocked"
    description = (
        "Detects AWS::S3::Bucket resources where PublicAccessBlockConfiguration "
        "is absent or any of its four settings is not true."
    )
    severity = Severity.high
    tags = ["cloudformation", "s3", "public-access"]
    remediation = (
        "Add PublicAccessBlockConfiguration with all four settings set to true."
    )

    _false_re = re.compile(r":\s*(false|False|no|No)\s*$")

    def match(self, content: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        for block, line_num in _cfn_resource_blocks(content, "AWS::S3::Bucket"):
            if "PublicAccessBlockConfiguration" not in block:
                findings.append(
                    Finding(
                        rule_id=self.id,
                        line_start=line_num,
                        line_end=line_num,
                        snippet=block.splitlines()[0].strip(),
                        extra={"filename": filename},
                    )
                )
                continue
            # Check for any key explicitly set to false
            for key in _PAB_KEYS:
                key_re = re.compile(rf"{key}:\s*(false|False|no|No)\s*$", re.MULTILINE)
                if key_re.search(block):
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            line_start=line_num,
                            line_end=line_num,
                            snippet=block.splitlines()[0].strip(),
                            extra={"filename": filename, "setting": key},
                        )
                    )
                    break
        return findings


class CfnSgOpen(Rule):
    id = "CFN_SG_OPEN"
    category = "networking"
    title = "Security group open to 0.0.0.0/0"
    description = (
        "Detects AWS::EC2::SecurityGroup resources with ingress rules that allow "
        "traffic from 0.0.0.0/0 (all IPv4) or ::/0 (all IPv6)."
    )
    severity = Severity.high
    tags = ["cloudformation", "security-group", "networking"]
    remediation = (
        "Restrict ingress rules to known IP ranges. Avoid 0.0.0.0/0 on any port."
    )

    _open_cidr_re = re.compile(
        r'CidrIp[v6]*:\s*["\']?(0\.0\.0\.0/0|::/0)["\']?'
    )

    def match(self, content: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        for block, block_start in _cfn_resource_blocks(content, "AWS::EC2::SecurityGroup"):
            block_lines = block.splitlines()
            for offset, line in enumerate(block_lines):
                if self._open_cidr_re.search(line):
                    abs_line = block_start + offset
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            line_start=abs_line,
                            line_end=abs_line,
                            snippet=line.strip(),
                            extra={"filename": filename},
                        )
                    )
        return findings


class CfnRdsPublic(Rule):
    id = "CFN_RDS_PUBLIC"
    category = "networking"
    title = "RDS instance publicly accessible"
    description = (
        "Detects AWS::RDS::DBInstance resources where PubliclyAccessible is set "
        "to true, exposing the database to the public internet."
    )
    severity = Severity.critical
    tags = ["cloudformation", "rds", "networking"]
    remediation = (
        "Set PubliclyAccessible: false and use a bastion host or VPN for "
        "database access."
    )

    _public_re = re.compile(r"PubliclyAccessible:\s*(true|True|yes|Yes)\s*$", re.MULTILINE)

    def match(self, content: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        for block, block_start in _cfn_resource_blocks(content, "AWS::RDS::DBInstance"):
            block_lines = block.splitlines()
            for offset, line in enumerate(block_lines):
                if self._public_re.search(line):
                    abs_line = block_start + offset
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            line_start=abs_line,
                            line_end=abs_line,
                            snippet=line.strip(),
                            extra={"filename": filename},
                        )
                    )
        return findings


_IAM_RESOURCE_TYPES = [
    "AWS::IAM::Policy",
    "AWS::IAM::ManagedPolicy",
    "AWS::IAM::Role",
    "AWS::IAM::User",
    "AWS::IAM::Group",
]

_RESOURCE_WILDCARD_RE = re.compile(r'Resource:\s*["\']?\*["\']?', re.MULTILINE)


class CfnIamWildcard(Rule):
    id = "CFN_IAM_WILDCARD"
    category = "identity"
    title = "IAM policy uses wildcard resource"
    description = (
        "Detects IAM policies in CloudFormation where a Statement grants "
        "Resource: '*', giving overly broad permissions."
    )
    severity = Severity.high
    tags = ["cloudformation", "iam", "least-privilege"]
    remediation = (
        "Scope IAM policy resources to specific ARNs instead of using wildcard *."
    )

    def match(self, content: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        seen_lines: set[int] = set()

        for resource_type in _IAM_RESOURCE_TYPES:
            for block, block_start in _cfn_resource_blocks(content, resource_type):
                block_lines = block.splitlines()
                for offset, line in enumerate(block_lines):
                    abs_line = block_start + offset
                    if abs_line in seen_lines:
                        continue
                    if _RESOURCE_WILDCARD_RE.search(line):
                        seen_lines.add(abs_line)
                        findings.append(
                            Finding(
                                rule_id=self.id,
                                line_start=abs_line,
                                line_end=abs_line,
                                snippet=line.strip(),
                                extra={"filename": filename},
                            )
                        )
        return findings


def get_rules() -> List[Rule]:
    return [
        CfnS3PublicAccess(),
        CfnSgOpen(),
        CfnRdsPublic(),
        CfnIamWildcard(),
    ]
