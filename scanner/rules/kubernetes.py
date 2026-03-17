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


class K8sNoLivenessProbe(Rule):
    id = "K8S_NO_LIVENESS_PROBE"
    category = "reliability"
    title = "Container has no liveness probe"
    description = (
        "Detects pod specs that define containers but no livenessProbe. "
        "Without a liveness probe Kubernetes cannot detect and restart stuck containers."
    )
    severity = Severity.medium
    tags = ["kubernetes", "reliability", "probes"]
    remediation = (
        "Define a livenessProbe for each container so Kubernetes can restart "
        "unhealthy containers automatically."
    )

    def match(self, content: str, filename: str) -> List[Finding]:
        if "containers:" not in content or "livenessProbe:" in content:
            return []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            # Match `containers:` but not `initContainers:`
            if re.search(r"(?<!init)containers:", line):
                return [
                    Finding(
                        rule_id=self.id,
                        line_start=idx,
                        line_end=idx,
                        snippet=line.strip(),
                        extra={"filename": filename},
                    )
                ]
        return []


class K8sNoReadinessProbe(Rule):
    id = "K8S_NO_READINESS_PROBE"
    category = "reliability"
    title = "Container has no readiness probe"
    description = (
        "Detects pod specs that define containers but no readinessProbe. "
        "Without a readiness probe Kubernetes may route traffic to containers that "
        "are not yet ready."
    )
    severity = Severity.medium
    tags = ["kubernetes", "reliability", "probes"]
    remediation = (
        "Define a readinessProbe for each container so Kubernetes only routes "
        "traffic to containers that are ready to serve requests."
    )

    def match(self, content: str, filename: str) -> List[Finding]:
        if "containers:" not in content or "readinessProbe:" in content:
            return []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            if re.search(r"(?<!init)containers:", line):
                return [
                    Finding(
                        rule_id=self.id,
                        line_start=idx,
                        line_end=idx,
                        snippet=line.strip(),
                        extra={"filename": filename},
                    )
                ]
        return []


class K8sAutomountServiceAccountToken(Rule):
    id = "K8S_AUTOMOUNT_SERVICE_ACCOUNT_TOKEN"
    category = "identity"
    title = "Service account token auto-mounted"
    description = (
        "Detects pod specs that do not explicitly opt out of auto-mounting the "
        "service account token (automountServiceAccountToken defaults to true). "
        "Only flagged when no custom serviceAccountName is set."
    )
    severity = Severity.medium
    tags = ["kubernetes", "pod-security", "rbac"]
    remediation = (
        "Set automountServiceAccountToken: false if the pod does not need to "
        "communicate with the Kubernetes API."
    )

    _opt_out_re = re.compile(r"automountServiceAccountToken:\s*false", re.IGNORECASE)
    _custom_sa_re = re.compile(r"serviceAccountName:\s+(?!default\b)\S+")

    def match(self, content: str, filename: str) -> List[Finding]:
        if "containers:" not in content:
            return []
        if self._opt_out_re.search(content):
            return []
        if self._custom_sa_re.search(content):
            return []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            if re.search(r"(?<!init)containers:", line):
                return [
                    Finding(
                        rule_id=self.id,
                        line_start=idx,
                        line_end=idx,
                        snippet=line.strip(),
                        extra={"filename": filename},
                    )
                ]
        return []


class K8sPrivilegeEscalationAllowed(Rule):
    id = "K8S_PRIVILEGE_ESCALATION_ALLOWED"
    category = "workload"
    title = "Container allows privilege escalation"
    description = (
        "Detects container specs where allowPrivilegeEscalation is true or absent. "
        "The default is true, allowing processes inside the container to gain more "
        "privileges than the parent process."
    )
    severity = Severity.high
    tags = ["kubernetes", "pod-security"]
    remediation = (
        "Set allowPrivilegeEscalation: false in the container securityContext to "
        "prevent privilege escalation attacks."
    )

    _explicit_true_re = re.compile(r"allowPrivilegeEscalation:\s*true", re.IGNORECASE)
    _opt_out_re = re.compile(r"allowPrivilegeEscalation:\s*false", re.IGNORECASE)

    def match(self, content: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()

        # Explicit true → flag that line
        for idx, line in enumerate(lines, start=1):
            if self._explicit_true_re.search(line):
                findings.append(
                    Finding(
                        rule_id=self.id,
                        line_start=idx,
                        line_end=idx,
                        snippet=line.strip(),
                        extra={"filename": filename},
                    )
                )

        # Absent → flag at containers: line
        if not findings and "containers:" in content and not self._opt_out_re.search(content):
            for idx, line in enumerate(lines, start=1):
                if re.search(r"(?<!init)containers:", line):
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


class K8sSecretAsEnvVar(Rule):
    id = "K8S_SECRET_AS_ENV_VAR"
    category = "storage"
    title = "Secret referenced as environment variable"
    description = (
        "Detects containers referencing Kubernetes secrets as environment variables "
        "via valueFrom.secretKeyRef. Environment variables are visible in process "
        "listings and crash dumps."
    )
    severity = Severity.medium
    tags = ["kubernetes", "secrets", "best-practice"]
    remediation = (
        "Mount secrets as volumes instead of environment variables. Environment "
        "variables are visible in process listings and crash dumps."
    )

    pattern = re.compile(r"\bsecretKeyRef\b")

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


class K8sNoPodSecurityContext(Rule):
    id = "K8S_NO_POD_SECURITY_CONTEXT"
    category = "workload"
    title = "No pod-level security context defined"
    description = (
        "Detects pod specs that define containers but no top-level securityContext. "
        "A pod security context establishes a baseline for all containers."
    )
    severity = Severity.medium
    tags = ["kubernetes", "pod-security"]
    remediation = (
        "Define a pod-level securityContext with runAsNonRoot: true, runAsUser, "
        "and seccompProfile to establish a security baseline."
    )

    def match(self, content: str, filename: str) -> List[Finding]:
        if "containers:" not in content or "securityContext:" in content:
            return []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            if re.search(r"(?<!init)containers:", line):
                return [
                    Finding(
                        rule_id=self.id,
                        line_start=idx,
                        line_end=idx,
                        snippet=line.strip(),
                        extra={"filename": filename},
                    )
                ]
        return []


class K8sHostPathMount(Rule):
    id = "K8S_HOST_PATH_MOUNT"
    category = "workload"
    title = "Pod mounts host filesystem path"
    description = (
        "Detects pods with a hostPath volume, which allows containers to access "
        "and modify the host node filesystem."
    )
    severity = Severity.high
    tags = ["kubernetes", "volumes", "hostpath"]
    remediation = (
        "Avoid hostPath volumes — they allow containers to access and modify the "
        "host filesystem. Use PersistentVolumeClaims instead."
    )

    pattern = re.compile(r"\bhostPath\s*:")

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


class K8sIngressNoTls(Rule):
    id = "K8S_INGRESS_NO_TLS"
    category = "networking"
    title = "Ingress resource has no TLS configured"
    description = (
        "Detects Kubernetes Ingress resources without a tls field. "
        "Without TLS, traffic to the ingress is sent in plaintext."
    )
    severity = Severity.high
    tags = ["kubernetes", "ingress", "tls"]
    remediation = (
        "Configure TLS on all Ingress resources using a valid certificate. "
        "Use cert-manager for automated certificate management."
    )

    _kind_re = re.compile(r"^\s*kind:\s*Ingress\b", re.MULTILINE)
    _tls_re = re.compile(r"\btls\s*:")

    def match(self, content: str, filename: str) -> List[Finding]:
        if not self._kind_re.search(content) or self._tls_re.search(content):
            return []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            if self._kind_re.search(line):
                return [
                    Finding(
                        rule_id=self.id,
                        line_start=idx,
                        line_end=idx,
                        snippet=line.strip(),
                        extra={"filename": filename},
                    )
                ]
        return []


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
        K8sNoLivenessProbe(),
        K8sNoReadinessProbe(),
        K8sAutomountServiceAccountToken(),
        K8sPrivilegeEscalationAllowed(),
        K8sSecretAsEnvVar(),
        K8sNoPodSecurityContext(),
        K8sHostPathMount(),
        K8sIngressNoTls(),
    ]