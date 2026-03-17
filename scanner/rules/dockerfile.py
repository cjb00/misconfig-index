from __future__ import annotations

import re
from typing import List

from .base import Finding, Rule, Severity


class DockerSecretsInEnv(Rule):
    id = "DOCKER_SECRETS_IN_ENV"
    category = "storage"
    title = "Secret passed as ENV variable"
    description = (
        "Detects ENV instructions where the variable name suggests a secret "
        "(PASSWORD, SECRET, KEY, TOKEN, API_KEY, PRIVATE_KEY, CREDENTIAL, AUTH, "
        "ACCESS_KEY, SECRET_KEY). Secrets in ENV are visible in 'docker inspect' "
        "and inherited by child images."
    )
    severity = Severity.critical
    tags = ["dockerfile", "secrets"]
    remediation = (
        "Never pass secrets as ENV variables — they are visible in docker inspect "
        "and child images. Use Docker secrets or a secrets manager at runtime."
    )

    # Match: ENV SECRET_KEY=... or ENV SECRET_KEY value (both forms)
    _env_re = re.compile(
        r"^\s*ENV\s+([A-Za-z_][A-Za-z0-9_]*)",
        re.IGNORECASE | re.MULTILINE,
    )
    _secret_keywords = re.compile(
        r"PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|CREDENTIAL|AUTH|ACCESS_KEY",
        re.IGNORECASE,
    )

    def match(self, content: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            m = self._env_re.match(line)
            if m and self._secret_keywords.search(m.group(1)):
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


class DockerNoHealthcheck(Rule):
    id = "DOCKER_NO_HEALTHCHECK"
    category = "reliability"
    title = "No HEALTHCHECK instruction defined"
    description = (
        "Detects Dockerfiles that do not define a HEALTHCHECK instruction. "
        "Without a healthcheck, container orchestrators cannot detect unhealthy "
        "containers and restart them automatically."
    )
    severity = Severity.low
    tags = ["dockerfile", "reliability"]
    remediation = (
        "Add a HEALTHCHECK instruction so container orchestrators can detect "
        "and restart unhealthy containers."
    )

    _healthcheck_re = re.compile(r"^\s*HEALTHCHECK\b", re.IGNORECASE | re.MULTILINE)
    _from_re = re.compile(r"^\s*FROM\b", re.IGNORECASE | re.MULTILINE)

    def match(self, content: str, filename: str) -> List[Finding]:
        # Only flag files that look like Dockerfiles (have FROM)
        if not self._from_re.search(content):
            return []
        if self._healthcheck_re.search(content):
            return []
        # Flag at the first FROM line
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            if self._from_re.match(line):
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


class DockerRootUser(Rule):
    id = "DOCKER_ROOT_USER"
    category = "workload"
    title = "Dockerfile runs as root user"
    description = (
        "Detects Dockerfiles where the USER instruction is absent (default: root) "
        "or explicitly set to root or UID 0."
    )
    severity = Severity.high
    tags = ["dockerfile", "pod-security"]
    remediation = "Add a USER instruction to run the container as a non-root user."

    # Explicit root: USER root or USER 0 (optionally USER 0:0)
    _user_root_re = re.compile(r"^\s*USER\s+(root|0)(\s|:|$)", re.IGNORECASE | re.MULTILINE)
    # Any USER instruction
    _user_any_re = re.compile(r"^\s*USER\b", re.IGNORECASE | re.MULTILINE)
    _from_re = re.compile(r"^\s*FROM\b", re.IGNORECASE | re.MULTILINE)

    def match(self, content: str, filename: str) -> List[Finding]:
        if not self._from_re.search(content):
            return []

        lines = content.splitlines()

        # Explicit USER root / USER 0
        for idx, line in enumerate(lines, start=1):
            if self._user_root_re.match(line):
                return [
                    Finding(
                        rule_id=self.id,
                        line_start=idx,
                        line_end=idx,
                        snippet=line.strip(),
                        extra={"filename": filename},
                    )
                ]

        # No USER instruction at all → flag at first FROM
        if not self._user_any_re.search(content):
            for idx, line in enumerate(lines, start=1):
                if self._from_re.match(line):
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


class DockerShellFormEntrypoint(Rule):
    id = "DOCKER_SHELL_FORM_ENTRYPOINT"
    category = "reliability"
    title = "ENTRYPOINT uses shell form instead of exec form"
    description = (
        "Detects ENTRYPOINT instructions using shell form (plain string) rather "
        "than exec form (JSON array). Shell form runs as a subprocess and does not "
        "forward signals correctly, preventing graceful shutdown."
    )
    severity = Severity.low
    tags = ["dockerfile", "reliability"]
    remediation = (
        'Use exec form for ENTRYPOINT: ENTRYPOINT ["python", "app.py"]. '
        "Shell form runs as a shell subprocess and does not handle signals correctly."
    )

    # Shell form: ENTRYPOINT followed by anything that is NOT a JSON array (i.e. not '[')
    _shell_form_re = re.compile(
        r"^\s*ENTRYPOINT\s+(?!\[)",
        re.IGNORECASE | re.MULTILINE,
    )

    def match(self, content: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            if self._shell_form_re.match(line):
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


class DockerAptGetUpgrade(Rule):
    id = "DOCKER_APT_GET_UPGRADE"
    category = "workload"
    title = "apt-get upgrade used in Dockerfile"
    description = (
        "Detects RUN instructions that call 'apt-get upgrade' or 'apt upgrade'. "
        "Running a full upgrade in a Dockerfile produces non-deterministic builds "
        "because the set of upgraded packages changes with every build."
    )
    severity = Severity.low
    tags = ["dockerfile", "best-practice"]
    remediation = (
        "Avoid apt-get upgrade in Dockerfiles — it produces non-deterministic builds. "
        "Pin specific package versions instead."
    )

    _upgrade_re = re.compile(r"apt(?:-get)?\s+upgrade\b", re.IGNORECASE)
    _run_re = re.compile(r"^\s*RUN\b", re.IGNORECASE)

    def match(self, content: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            if self._run_re.match(line) and self._upgrade_re.search(line):
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
        DockerSecretsInEnv(),
        DockerNoHealthcheck(),
        DockerRootUser(),
        DockerShellFormEntrypoint(),
        DockerAptGetUpgrade(),
    ]
