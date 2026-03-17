from __future__ import annotations

import re
from abc import ABC
from typing import List

from .base import Finding, Rule, Severity


def _find_line_numbers(content: str, match_start: int) -> tuple[int, int]:
    """Derive approximate line numbers for a match position."""
    prefix = content[:match_start]
    line_start = prefix.count("\n") + 1
    return line_start, line_start


_VAR_BLOCK_RE = re.compile(r'\bvariable\s+"[^"]*"\s*\{')
_RESOURCE_BLOCK_RE = re.compile(r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{')
_BUCKET_REF_RE = re.compile(r'aws_s3_bucket\.([a-zA-Z0-9_\-]+)\.')


def _variable_block_spans(content: str) -> list[tuple[int, int]]:
    """Return (start, end) byte offsets for every variable {} block.

    Matches that fall inside these spans are module input declarations
    (variable defaults / type constraints), not hardcoded infrastructure
    config.  Rules skip them to avoid false positives in module repos.
    """
    spans: list[tuple[int, int]] = []
    for m in _VAR_BLOCK_RE.finditer(content):
        depth = 0
        for i in range(m.start(), len(content)):
            if content[i] == "{":
                depth += 1
            elif content[i] == "}":
                depth -= 1
                if depth == 0:
                    spans.append((m.start(), i))
                    break
    return spans


def _resource_blocks(content: str, resource_type: str) -> list[tuple[str, str, int]]:
    """Return (logical_name, block_content, block_start) for each resource of given type.

    Uses brace-counting to find the full block extent, same approach as
    _variable_block_spans.
    """
    results: list[tuple[str, str, int]] = []
    for m in _RESOURCE_BLOCK_RE.finditer(content):
        if m.group(1) != resource_type:
            continue
        logical_name = m.group(2)
        depth = 0
        for i in range(m.start(), len(content)):
            if content[i] == "{":
                depth += 1
            elif content[i] == "}":
                depth -= 1
                if depth == 0:
                    results.append((logical_name, content[m.start() : i + 1], m.start()))
                    break
    return results


class _S(Rule, ABC):
    """
    SimplePatternRule mixin — fires one Finding per regex match.
    Subclasses only need to declare class-level attributes and `pattern`.
    """

    pattern: re.Pattern

    def match(self, content: str, filename: str) -> List[Finding]:
        var_spans = _variable_block_spans(content)
        findings: List[Finding] = []
        lines = content.splitlines()
        for m in self.pattern.finditer(content):
            # Skip matches inside variable {} blocks — those are module input
            # declarations (defaults / type constraints), not hardcoded config.
            if any(s <= m.start() <= e for s, e in var_spans):
                continue
            line_start, _ = _find_line_numbers(content, m.start())
            snippet = lines[line_start - 1].strip() if lines else ""
            findings.append(
                Finding(
                    rule_id=self.id,
                    line_start=line_start,
                    line_end=line_start,
                    snippet=snippet,
                    extra={"filename": filename},
                )
            )
        return findings


# ── Networking ────────────────────────────────────────────────────────────────


class TfOpenSecurityGroup(_S):
    id = "TF_OPEN_SG_0_0_0_0"
    category = "networking"
    title = "Security group allows 0.0.0.0/0"
    description = "Detects overly permissive security group rules that allow 0.0.0.0/0."
    severity = Severity.high
    tags = ["terraform", "network", "security-group"]
    remediation = "Restrict cidr_blocks to specific IP ranges. Use a VPN or bastion host for management access."
    pattern = re.compile(r"0\.0\.0\.0/0")


class TfSgSshOpen(_S):
    id = "TF_SG_SSH_OPEN_0_0_0_0"
    category = "networking"
    title = "Security group allows SSH (port 22) from 0.0.0.0/0"
    description = "Detects ingress rules that expose SSH to the internet."
    severity = Severity.critical
    tags = ["terraform", "network", "security-group", "ssh"]
    remediation = "Remove public SSH access. Use AWS Systems Manager Session Manager or restrict to known IPs via cidr_blocks."
    pattern = re.compile(
        r"ingress\s*{[^}]*from_port\s*=\s*22[^}]*to_port\s*=\s*22[^}]*0\.0\.0\.0/0[^}]*}",
        re.IGNORECASE | re.DOTALL,
    )


class TfSgRdpOpen(_S):
    id = "TF_SG_RDP_OPEN"
    category = "networking"
    title = "Security group allows RDP (port 3389) from 0.0.0.0/0"
    description = "Detects ingress rules that expose RDP to the internet."
    severity = Severity.critical
    tags = ["terraform", "network", "security-group", "rdp"]
    remediation = "Remove public RDP access. Use a VPN, bastion host, or AWS Systems Manager for remote access."
    pattern = re.compile(
        r"ingress\s*{[^}]*from_port\s*=\s*3389[^}]*0\.0\.0\.0/0[^}]*}",
        re.IGNORECASE | re.DOTALL,
    )


class TfSgAllTraffic(_S):
    id = "TF_SG_ALL_TRAFFIC"
    category = "networking"
    title = "Security group rule allows all traffic (protocol -1)"
    description = (
        'Detects security group rules with protocol = "-1" (all traffic), '
        "which bypasses port-level restrictions."
    )
    severity = Severity.high
    tags = ["terraform", "network", "security-group"]
    remediation = 'Replace protocol = "-1" with explicit protocol and port range rules.'
    pattern = re.compile(r'protocol\s*=\s*"-1"')


class TfEksPublicEndpoint(_S):
    id = "TF_EKS_PUBLIC_ENDPOINT"
    category = "networking"
    title = "EKS cluster API endpoint is publicly accessible"
    description = (
        "Detects aws_eks_cluster resources with endpoint_public_access = true. "
        "Consider restricting public access with public_access_cidrs."
    )
    severity = Severity.high
    tags = ["terraform", "eks", "network"]
    remediation = "Set endpoint_public_access = false and endpoint_private_access = true. Access the API via VPN or bastion."
    pattern = re.compile(r"endpoint_public_access\s*=\s*true", re.IGNORECASE)


class TfEc2PublicIp(_S):
    id = "TF_EC2_PUBLIC_IP"
    category = "networking"
    title = "EC2 instance or launch template assigns a public IP"
    description = (
        "Detects associate_public_ip_address = true. Instances in public subnets "
        "with public IPs are directly reachable from the internet."
    )
    severity = Severity.medium
    tags = ["terraform", "ec2", "network"]
    remediation = "Set associate_public_ip_address = false. Place instances in private subnets behind a load balancer."
    pattern = re.compile(r"associate_public_ip_address\s*=\s*true", re.IGNORECASE)


# ── Identity / IAM ────────────────────────────────────────────────────────────


class TfWildcardIamAction(_S):
    id = "TF_WILDCARD_IAM_ACTION"
    category = "identity"
    title = 'IAM policy allows Action "*" (JSON inline)'
    description = "Flags wildcard IAM actions in JSON-embedded policy documents."
    severity = Severity.critical
    tags = ["terraform", "iam", "wildcard"]
    remediation = 'Replace "*" with the minimum set of actions required. Use IAM Access Analyzer to identify least-privilege.'
    pattern = re.compile(r'"Action"\s*:\s*"\*"', re.IGNORECASE)


class TfWildcardIamResource(_S):
    id = "TF_WILDCARD_IAM_RESOURCE"
    category = "identity"
    title = 'IAM policy allows Resource "*" (JSON inline)'
    description = "Flags wildcard IAM resources in JSON-embedded policy documents."
    severity = Severity.high
    tags = ["terraform", "iam", "wildcard"]
    remediation = 'Replace "*" with specific resource ARNs scoped to the required resources.'
    pattern = re.compile(r'"Resource"\s*:\s*"\*"', re.IGNORECASE)


class TfIamWildcardActionsHcl(_S):
    id = "TF_IAM_WILDCARD_ACTIONS_HCL"
    category = "identity"
    title = 'IAM policy_document uses actions = ["*"]'
    description = (
        'Flags wildcard actions in HCL-native aws_iam_policy_document data sources. '
        'Grants every IAM action to the principal.'
    )
    severity = Severity.critical
    tags = ["terraform", "iam", "wildcard"]
    remediation = 'Replace ["*"] with only the actions the role requires. See AWS documentation for service-specific actions.'
    pattern = re.compile(r'actions\s*=\s*\["\*"\]', re.IGNORECASE)


class TfIamWildcardResourcesHcl(_S):
    id = "TF_IAM_WILDCARD_RESOURCES_HCL"
    category = "identity"
    title = 'IAM policy_document uses resources = ["*"]'
    description = (
        'Flags wildcard resources in HCL-native aws_iam_policy_document data sources. '
        'Applies the policy to every AWS resource.'
    )
    severity = Severity.high
    tags = ["terraform", "iam", "wildcard"]
    remediation = 'Scope resources to specific ARN patterns, e.g. "arn:aws:s3:::my-bucket/*" instead of ["*"].'
    pattern = re.compile(r'resources\s*=\s*\["\*"\]', re.IGNORECASE)


class TfIamAdminPolicy(_S):
    id = "TF_IAM_ADMIN_POLICY_ATTACHED"
    category = "identity"
    title = "AWS-managed AdministratorAccess policy attached"
    description = (
        "Detects the AdministratorAccess managed policy ARN. This grants full "
        "access to all AWS services and resources and should rarely be used."
    )
    severity = Severity.critical
    tags = ["terraform", "iam", "admin"]
    remediation = "Replace AdministratorAccess with a custom policy granting only the permissions the role actually needs."
    pattern = re.compile(
        r"arn:aws:iam::aws:policy/AdministratorAccess", re.IGNORECASE
    )


class TfKmsNoKeyRotation(_S):
    id = "TF_KMS_NO_KEY_ROTATION"
    category = "identity"
    title = "KMS key rotation disabled"
    description = (
        "Detects aws_kms_key resources with enable_key_rotation = false. "
        "Annual key rotation limits the blast radius of a compromised key."
    )
    severity = Severity.medium
    tags = ["terraform", "kms", "encryption"]
    remediation = "Set enable_key_rotation = true. AWS rotates the key material annually with no service interruption."
    pattern = re.compile(r"enable_key_rotation\s*=\s*false", re.IGNORECASE)


# ── Storage ───────────────────────────────────────────────────────────────────


class TfPublicS3Acl(_S):
    id = "TF_PUBLIC_S3_ACL"
    category = "storage"
    title = "S3 bucket ACL set to public"
    description = "Detects publicly readable or writable S3 ACLs."
    severity = Severity.high
    tags = ["terraform", "s3", "acl"]
    remediation = "Remove the public ACL. Use bucket policies with explicit principals if sharing is required."
    pattern = re.compile(r'acl\s*=\s*"(public-read|public-read-write)"', re.IGNORECASE)


class TfPublicS3PolicyPrincipal(_S):
    id = "TF_PUBLIC_S3_POLICY_PRINCIPAL"
    category = "storage"
    title = 'S3 bucket policy with Principal "*"'
    description = "Detects S3 bucket policies that allow all principals with Effect Allow."
    severity = Severity.critical
    tags = ["terraform", "s3", "policy", "wildcard"]
    remediation = 'Replace Principal: "*" with specific AWS account or role ARNs.'
    pattern = re.compile(
        r'"Effect"\s*:\s*"Allow"[^}]*"Principal"\s*:\s*"\*"',
        re.IGNORECASE | re.DOTALL,
    )


class TfS3PublicAccessBlockDisabled(_S):
    id = "TF_S3_PUBLIC_ACCESS_BLOCK_DISABLED"
    category = "storage"
    title = "S3 public access block explicitly disabled"
    description = (
        "Detects aws_s3_bucket_public_access_block resources where one or more "
        "public-access-block settings are set to false."
    )
    severity = Severity.medium
    tags = ["terraform", "s3", "public-access-block"]
    remediation = "Set block_public_acls, block_public_policy, ignore_public_acls, and restrict_public_buckets to true."
    pattern = re.compile(
        r'resource\s+"aws_s3_bucket_public_access_block"\s+".+?"\s*{[^}]*'
        r'(block_public_acls\s*=\s*false|block_public_policy\s*=\s*false|'
        r'ignore_public_acls\s*=\s*false|restrict_public_buckets\s*=\s*false)',
        re.IGNORECASE | re.DOTALL,
    )


class TfS3VersioningDisabled(Rule):
    id = "TF_S3_VERSIONING_DISABLED"
    category = "storage"
    title = "S3 bucket versioning disabled or not configured"
    description = (
        "Detects S3 buckets without versioning enabled. Covers both the legacy "
        "versioning { enabled = false } block and the modern aws_s3_bucket_versioning "
        "resource when status is not 'Enabled' or is absent."
    )
    severity = Severity.medium
    tags = ["terraform", "s3", "versioning"]
    remediation = (
        "Enable versioning on this S3 bucket to protect against accidental deletion "
        "and overwrites."
    )

    _old_style_re = re.compile(
        r"versioning\s*{\s*[^}]*enabled\s*=\s*false",
        re.IGNORECASE | re.DOTALL,
    )
    _status_enabled_re = re.compile(r'status\s*=\s*"Enabled"', re.IGNORECASE)

    def match(self, content: str, filename: str) -> List[Finding]:
        var_spans = _variable_block_spans(content)
        findings: List[Finding] = []
        lines = content.splitlines()

        # Old-style: versioning { enabled = false } inside any resource block
        for m in self._old_style_re.finditer(content):
            if any(s <= m.start() <= e for s, e in var_spans):
                continue
            line_start, _ = _find_line_numbers(content, m.start())
            snippet = lines[line_start - 1].strip() if lines else ""
            findings.append(
                Finding(
                    rule_id=self.id,
                    line_start=line_start,
                    line_end=line_start,
                    snippet=snippet,
                    extra={"filename": filename},
                )
            )

        # New-style: aws_s3_bucket_versioning resource without status = "Enabled"
        for _, block_content, start in _resource_blocks(content, "aws_s3_bucket_versioning"):
            if not self._status_enabled_re.search(block_content):
                line_start, _ = _find_line_numbers(content, start)
                snippet = lines[line_start - 1].strip() if lines else ""
                findings.append(
                    Finding(
                        rule_id=self.id,
                        line_start=line_start,
                        line_end=line_start,
                        snippet=snippet,
                        extra={"filename": filename},
                    )
                )

        return findings


class TfS3PublicAccessNotBlocked(Rule):
    id = "TF_S3_PUBLIC_ACCESS_NOT_BLOCKED"
    category = "storage"
    title = "S3 bucket has no public access block configured"
    description = (
        "Detects aws_s3_bucket resources with no associated "
        "aws_s3_bucket_public_access_block resource. Without this block, the bucket "
        "may be exposed to public ACLs or policies."
    )
    severity = Severity.high
    tags = ["terraform", "s3", "public-access-block"]
    remediation = (
        "Enable all four public access block settings on "
        "aws_s3_bucket_public_access_block to prevent public exposure."
    )

    def match(self, content: str, filename: str) -> List[Finding]:
        bucket_blocks = _resource_blocks(content, "aws_s3_bucket")
        block_blocks = _resource_blocks(content, "aws_s3_bucket_public_access_block")
        covered: set[str] = set()
        for _, block_content, _ in block_blocks:
            for ref in _BUCKET_REF_RE.finditer(block_content):
                covered.add(ref.group(1))
        findings: List[Finding] = []
        lines = content.splitlines()
        for name, _, start in bucket_blocks:
            if name not in covered:
                line_start, _ = _find_line_numbers(content, start)
                snippet = lines[line_start - 1].strip() if lines else ""
                findings.append(
                    Finding(
                        rule_id=self.id,
                        line_start=line_start,
                        line_end=line_start,
                        snippet=snippet,
                        extra={"filename": filename},
                    )
                )
        return findings


class TfS3EncryptionDisabled(Rule):
    id = "TF_S3_ENCRYPTION_DISABLED"
    category = "storage"
    title = "S3 bucket has no server-side encryption configured"
    description = (
        "Detects aws_s3_bucket resources with no associated "
        "aws_s3_bucket_server_side_encryption_configuration resource."
    )
    severity = Severity.high
    tags = ["terraform", "s3", "encryption"]
    remediation = (
        "Configure server-side encryption using "
        "aws_s3_bucket_server_side_encryption_configuration with AES256 or aws:kms."
    )

    def match(self, content: str, filename: str) -> List[Finding]:
        bucket_blocks = _resource_blocks(content, "aws_s3_bucket")
        sse_blocks = _resource_blocks(
            content, "aws_s3_bucket_server_side_encryption_configuration"
        )
        covered: set[str] = set()
        for _, block_content, _ in sse_blocks:
            for ref in _BUCKET_REF_RE.finditer(block_content):
                covered.add(ref.group(1))
        findings: List[Finding] = []
        lines = content.splitlines()
        for name, _, start in bucket_blocks:
            if name not in covered:
                line_start, _ = _find_line_numbers(content, start)
                snippet = lines[line_start - 1].strip() if lines else ""
                findings.append(
                    Finding(
                        rule_id=self.id,
                        line_start=line_start,
                        line_end=line_start,
                        snippet=snippet,
                        extra={"filename": filename},
                    )
                )
        return findings


class TfEbsNoEncryption(_S):
    id = "TF_EBS_NO_ENCRYPTION"
    category = "storage"
    title = "EBS volume without encryption"
    description = "Detects aws_ebs_volume resources with encrypted = false."
    severity = Severity.high
    tags = ["terraform", "ebs", "encryption"]
    remediation = "Set encrypted = true and specify a kms_key_id. Enable EBS default encryption in the AWS account."
    pattern = re.compile(
        r'resource\s+"aws_ebs_volume"\s+".+?"\s*{[^}]*encrypted\s*=\s*false',
        re.IGNORECASE | re.DOTALL,
    )


# ── Database ──────────────────────────────────────────────────────────────────


class TfRdsNoEncryption(_S):
    id = "TF_RDS_NO_ENCRYPTION"
    category = "database"
    title = "RDS instance without storage encryption"
    description = "Detects aws_db_instance resources with storage_encrypted = false."
    severity = Severity.high
    tags = ["terraform", "rds", "encryption"]
    remediation = "Set storage_encrypted = true and specify a kms_key_id. Note: requires a snapshot restore to enable on existing instances."
    pattern = re.compile(
        r'resource\s+"aws_db_instance"\s+".+?"\s*{[^}]*storage_encrypted\s*=\s*false',
        re.IGNORECASE | re.DOTALL,
    )


class TfRdsPubliclyAccessible(_S):
    id = "TF_RDS_PUBLICLY_ACCESSIBLE"
    category = "database"
    title = "RDS instance is publicly accessible"
    description = (
        "Detects publicly_accessible = true on RDS instances. Databases should "
        "never be directly reachable from the internet."
    )
    severity = Severity.critical
    tags = ["terraform", "rds", "network"]
    remediation = "Set publicly_accessible = false. Access the database through a private subnet and application layer."
    pattern = re.compile(r"publicly_accessible\s*=\s*true", re.IGNORECASE)


class TfRdsNoDeletionProtection(_S):
    id = "TF_RDS_NO_DELETION_PROTECTION"
    category = "database"
    title = "RDS instance deletion protection disabled"
    description = (
        "Detects deletion_protection = false on RDS instances. Enabling deletion "
        "protection prevents accidental or unauthorized database deletion."
    )
    severity = Severity.medium
    tags = ["terraform", "rds"]
    remediation = "Set deletion_protection = true. Deletion must then be explicitly disabled before the instance can be destroyed."
    pattern = re.compile(
        r'resource\s+"aws_db_instance"\s+".+?"\s*{[^}]*deletion_protection\s*=\s*false',
        re.IGNORECASE | re.DOTALL,
    )


class TfRdsNoBackup(_S):
    id = "TF_RDS_NO_BACKUP"
    category = "database"
    title = "RDS instance backup retention period set to 0"
    description = (
        "Detects backup_retention_period = 0, which disables automated backups. "
        "A minimum of 7 days is recommended."
    )
    severity = Severity.high
    tags = ["terraform", "rds", "backup"]
    remediation = "Set backup_retention_period to at least 7. AWS recommends 35 days for production databases."
    pattern = re.compile(r"backup_retention_period\s*=\s*0\b", re.IGNORECASE)


_DELETION_PROT_TRUE_RE = re.compile(r"deletion_protection\s*=\s*true", re.IGNORECASE)
_STORAGE_ENCRYPTED_TRUE_RE = re.compile(r"storage_encrypted\s*=\s*true", re.IGNORECASE)


class TfRdsDeletionProtectionDisabled(Rule):
    id = "TF_RDS_DELETION_PROTECTION_DISABLED"
    category = "storage"
    title = "RDS instance deletion protection disabled"
    description = (
        "Detects aws_db_instance resources where deletion_protection is false or "
        "not set. The default is false, leaving the database unprotected from "
        "accidental deletion."
    )
    severity = Severity.medium
    tags = ["terraform", "rds"]
    remediation = (
        "Set deletion_protection = true to prevent accidental database deletion."
    )

    def match(self, content: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()
        for _, block_content, start in _resource_blocks(content, "aws_db_instance"):
            if not _DELETION_PROT_TRUE_RE.search(block_content):
                line_start, _ = _find_line_numbers(content, start)
                snippet = lines[line_start - 1].strip() if lines else ""
                findings.append(
                    Finding(
                        rule_id=self.id,
                        line_start=line_start,
                        line_end=line_start,
                        snippet=snippet,
                        extra={"filename": filename},
                    )
                )
        return findings


class TfRdsStorageEncryptedDisabled(Rule):
    id = "TF_RDS_STORAGE_ENCRYPTED_DISABLED"
    category = "storage"
    title = "RDS instance storage encryption disabled"
    description = (
        "Detects aws_db_instance resources where storage_encrypted is false or "
        "not set. The default is false, leaving data at rest unencrypted."
    )
    severity = Severity.high
    tags = ["terraform", "rds", "encryption"]
    remediation = "Set storage_encrypted = true to encrypt data at rest."

    def match(self, content: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()
        for _, block_content, start in _resource_blocks(content, "aws_db_instance"):
            if not _STORAGE_ENCRYPTED_TRUE_RE.search(block_content):
                line_start, _ = _find_line_numbers(content, start)
                snippet = lines[line_start - 1].strip() if lines else ""
                findings.append(
                    Finding(
                        rule_id=self.id,
                        line_start=line_start,
                        line_end=line_start,
                        snippet=snippet,
                        extra={"filename": filename},
                    )
                )
        return findings


# ── Workload / Compute ────────────────────────────────────────────────────────


class TfEc2Imdsv1(_S):
    id = "TF_EC2_IMDSV1_ENABLED"
    category = "workload"
    title = "EC2 instance metadata service v1 allowed (http_tokens = optional)"
    description = (
        'Detects http_tokens = "optional" in metadata_options, which allows IMDSv1. '
        "IMDSv2 (required) mitigates SSRF-based credential theft attacks."
    )
    severity = Severity.high
    tags = ["terraform", "ec2", "imds", "ssrf"]
    remediation = 'Set http_tokens = "required" in metadata_options to enforce IMDSv2 and block SSRF-based credential theft.'
    pattern = re.compile(r'http_tokens\s*=\s*"optional"', re.IGNORECASE)


# ── Logging ───────────────────────────────────────────────────────────────────


class TfCloudtrailNoLogValidation(_S):
    id = "TF_CLOUDTRAIL_NO_LOG_VALIDATION"
    category = "logging"
    title = "CloudTrail log file validation disabled"
    description = (
        "Detects enable_log_file_validation = false in aws_cloudtrail resources. "
        "Log file validation detects tampering with trail logs after delivery."
    )
    severity = Severity.medium
    tags = ["terraform", "cloudtrail", "logging"]
    remediation = "Set enable_log_file_validation = true to generate digest files that detect log tampering."
    pattern = re.compile(r"enable_log_file_validation\s*=\s*false", re.IGNORECASE)


class TfAlbAccessLogsDisabled(_S):
    id = "TF_ALB_ACCESS_LOGS_DISABLED"
    category = "logging"
    title = "ALB/NLB access logging explicitly disabled"
    description = (
        "Detects access_logs blocks with enabled = false on aws_lb / aws_alb resources. "
        "Access logs are essential for security analysis and incident response."
    )
    severity = Severity.low
    tags = ["terraform", "alb", "logging"]
    remediation = "Set enabled = true in the access_logs block and specify an S3 bucket to receive the logs."
    pattern = re.compile(
        r"access_logs\s*{\s*[^}]*enabled\s*=\s*false",
        re.IGNORECASE | re.DOTALL,
    )


# ── Registry ──────────────────────────────────────────────────────────────────


def get_rules() -> List[Rule]:
    return [
        # Networking
        TfOpenSecurityGroup(),
        TfSgSshOpen(),
        TfSgRdpOpen(),
        TfSgAllTraffic(),
        TfEksPublicEndpoint(),
        TfEc2PublicIp(),
        # Identity
        TfWildcardIamAction(),
        TfWildcardIamResource(),
        TfIamWildcardActionsHcl(),
        TfIamWildcardResourcesHcl(),
        TfIamAdminPolicy(),
        TfKmsNoKeyRotation(),
        # Storage
        TfPublicS3Acl(),
        TfPublicS3PolicyPrincipal(),
        TfS3PublicAccessBlockDisabled(),
        TfS3VersioningDisabled(),
        TfS3PublicAccessNotBlocked(),
        TfS3EncryptionDisabled(),
        TfEbsNoEncryption(),
        # Database
        TfRdsNoEncryption(),
        TfRdsPubliclyAccessible(),
        TfRdsNoDeletionProtection(),
        TfRdsNoBackup(),
        TfRdsDeletionProtectionDisabled(),
        TfRdsStorageEncryptedDisabled(),
        # Workload
        TfEc2Imdsv1(),
        # Logging
        TfCloudtrailNoLogValidation(),
        TfAlbAccessLogsDisabled(),
    ]
