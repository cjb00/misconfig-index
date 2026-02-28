from __future__ import annotations

import re
from typing import List

from .base import Finding, Rule, Severity


class K8sRunAsRoot(Rule):
    id = "K8S_RUN_AS_ROOT"
    category = "workload"
    title = "Pod/container running as root"
    description = "Detects pods configured to run as root user (runAsUser: 0 or runAsNonRoot: false)."
    severity = Severity.high
    tags = ["kubernetes", "pod-security"]
    remediation = "Set runAsNonRoot: true and runAsUser to a non-zero UID in the container's securityContext."

    patterns = [
        re.compile(r"runAsUser:\s*0"),
        re.compile(r"runAsNonRoot:\s*false", re.IGNORECASE),
    ]

    def match(self, content: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            if any(p.search(line) for p in self.patterns):
                findings.append(
                    Finding(
                        rule_id=self.id,
                        line_start=idx,
                        line_end=idx,
                        snippet=line.strip(),
                        extra={"filename": filename},
                    )
                )
        return findings


class K8sPrivilegedContainer(Rule):
    id = "K8S_PRIVILEGED_CONTAINER"
    category = "workload"
    title = "Privileged container"
    description = "Detects containers running in privileged mode."
    severity = Severity.critical
    tags = ["kubernetes", "pod-security"]
    remediation = "Remove 'privileged: true' or set it to false in the container's securityContext."

    pattern = re.compile(r"privileged:\s*true", re.IGNORECASE)

    def match(self, content: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            if self.pattern.search(line):
                findings.append(
                    Finding(
                        rule_id=self.id,
                        line_start=idx,
                        line_end=idx,
                        snippet=line.strip(),
                        extra={"filename": filename},
                    )
                )
        return findings


class K8sHostPathVolume(Rule):
    id = "K8S_HOSTPATH_VOLUME"
    category = "storage"
    title = "HostPath volume used"
    description = "Detects usage of hostPath volumes, which can expose the node filesystem."
    severity = Severity.high
    tags = ["kubernetes", "volumes", "hostpath"]
    remediation = "Replace hostPath volumes with emptyDir, PersistentVolumeClaims, or other storage types that don't mount node paths."

    pattern = re.compile(r"\bhostPath:\b")

    def match(self, content: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            if self.pattern.search(line):
                findings.append(
                    Finding(
                        rule_id=self.id,
                        line_start=idx,
                        line_end=idx,
                        snippet=line.strip(),
                        extra={"filename": filename},
                    )
                )
        return findings


class K8sHostNetworkOrPid(Rule):
    id = "K8S_HOSTNETWORK_OR_HOSTPID"
    category = "workload"
    title = "Pod uses hostNetwork or hostPID"
    description = "Detects pods configured with hostNetwork: true or hostPID: true."
    severity = Severity.high
    tags = ["kubernetes", "pod-security", "isolation"]
    remediation = "Remove hostNetwork and hostPID from the pod spec; use ClusterIP services and separate namespaces for inter-pod communication."

    pattern = re.compile(r"\b(hostNetwork|hostPID):\s*true\b", re.IGNORECASE)

    def match(self, content: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            if self.pattern.search(line):
                findings.append(
                    Finding(
                        rule_id=self.id,
                        line_start=idx,
                        line_end=idx,
                        snippet=line.strip(),
                        extra={"filename": filename},
                    )
                )
        return findings


class K8sCapabilitiesAddDangerous(Rule):
    id = "K8S_CAPABILITIES_ADD_DANGEROUS"
    category = "workload"
    title = "Dangerous Linux capabilities added"
    description = (
        "Detects containers adding dangerous Linux capabilities such as NET_ADMIN, SYS_ADMIN, or ALL."
    )
    severity = Severity.high
    tags = ["kubernetes", "pod-security", "capabilities"]
    remediation = "Drop all capabilities with 'drop: [ALL]' and add back only the specific ones required; avoid NET_ADMIN, SYS_ADMIN, and ALL."

    # crude but effective: look for capabilities.add with specific caps
    pattern = re.compile(
        r"capabilities:\s*\n\s*add:\s*\n(?:\s*-\s*(?P<cap>NET_ADMIN|SYS_ADMIN|ALL)\b)+",
        re.IGNORECASE,
    )

    def match(self, content: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        for m in self.pattern.finditer(content):
            # approximate line number from match start
            prefix = content[: m.start()]
            line_start = prefix.count("\n") + 1
            cap = m.group("cap")
            snippet = content.splitlines()[line_start - 1].strip()
            findings.append(
                Finding(
                    rule_id=self.id,
                    line_start=line_start,
                    line_end=line_start,
                    snippet=snippet,
                    extra={"filename": filename, "capability": cap},
                )
            )
        return findings


class K8sImageLatestTag(Rule):
    id = "K8S_IMAGE_LATEST_TAG"
    category = "image"
    title = "Container image uses :latest tag"
    description = "Detects container images pinned to :latest, which is not reproducible and risky."
    severity = Severity.medium
    tags = ["kubernetes", "image", "supply-chain"]
    remediation = "Pin images to a specific version tag or SHA digest (e.g. nginx:1.25.3 or nginx@sha256:...) to ensure reproducible deployments."

    pattern = re.compile(r"\bimage:\s*\S+:latest\b", re.IGNORECASE)

    def match(self, content: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            if self.pattern.search(line):
                findings.append(
                    Finding(
                        rule_id=self.id,
                        line_start=idx,
                        line_end=idx,
                        snippet=line.strip(),
                        extra={"filename": filename},
                    )
                )
        return findings


class K8sNoResourceLimits(Rule):
    id = "K8S_NO_RESOURCE_LIMITS"
    category = "workload"
    title = "Containers without resource limits"
    description = (
        "Detects pod specs that define containers but no resource limits, which can cause noisy neighbor problems."
    )
    severity = Severity.medium
    tags = ["kubernetes", "resources", "best-practice"]
    remediation = "Add a resources.limits block to each container specifying cpu and memory caps, and set resources.requests to appropriate values."

    def match(self, content: str, filename: str) -> List[Finding]:
        """
        Very simple heuristic:
        - if a document contains 'containers:' but no 'resources:' or 'limits:' at all,
          flag the first 'containers:' line.
        """
        findings: List[Finding] = []
        lines = content.splitlines()
        doc = "\n".join(lines)

        if "containers:" in doc and "resources:" not in doc and "limits:" not in doc:
            for idx, line in enumerate(lines, start=1):
                if "containers:" in line:
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            line_start=idx,
                            line_end=idx,
                            snippet=line.strip(),
                            extra={"filename": filename},
                        )
                    )
                    break

        return findings


class K8sReadOnlyRootFsDisabled(Rule):
    id = "K8S_READONLY_ROOTFS_DISABLED"
    category = "workload"
    title = "readOnlyRootFilesystem disabled"
    description = (
        "Detects containers explicitly disabling readOnlyRootFilesystem, which weakens "
        "filesystem isolation."
    )
    severity = Severity.medium
    tags = ["kubernetes", "pod-security"]
    remediation = "Set readOnlyRootFilesystem: true in the container's securityContext; mount writable emptyDir volumes for paths that need write access."

    pattern = re.compile(r"\breadOnlyRootFilesystem:\s*false\b", re.IGNORECASE)

    def match(self, content: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            if self.pattern.search(line):
                findings.append(
                    Finding(
                        rule_id=self.id,
                        line_start=idx,
                        line_end=idx,
                        snippet=line.strip(),
                        extra={"filename": filename},
                    )
                )
        return findings


def get_rules() -> List[Rule]:
    return [
        K8sRunAsRoot(),
        K8sPrivilegedContainer(),
        K8sHostPathVolume(),
        K8sHostNetworkOrPid(),
        K8sCapabilitiesAddDangerous(),
        K8sImageLatestTag(),
        K8sNoResourceLimits(),
        K8sReadOnlyRootFsDisabled(),
    ]