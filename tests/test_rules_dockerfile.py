"""Tests for Dockerfile scanner rules."""
import pytest
from scanner.rules.dockerfile import (
    DockerSecretsInEnv,
    DockerNoHealthcheck,
    DockerRootUser,
    DockerShellFormEntrypoint,
    DockerAptGetUpgrade,
)

FILENAME = "Dockerfile"


# ── DOCKER_SECRETS_IN_ENV ─────────────────────────────────────────────────────


class TestDockerSecretsInEnv:
    rule = DockerSecretsInEnv()

    def test_positive_password(self):
        """ENV with PASSWORD in name → finding."""
        df = "FROM ubuntu:22.04\nENV DB_PASSWORD=secret123\n"
        findings = self.rule.match(df, FILENAME)
        assert len(findings) == 1
        assert findings[0].rule_id == "DOCKER_SECRETS_IN_ENV"

    def test_positive_secret(self):
        """ENV with SECRET in name → finding."""
        df = "FROM ubuntu:22.04\nENV APP_SECRET=abc\n"
        assert len(self.rule.match(df, FILENAME)) == 1

    def test_positive_token(self):
        """ENV with TOKEN in name → finding."""
        df = "FROM ubuntu:22.04\nENV AUTH_TOKEN=xyz\n"
        assert len(self.rule.match(df, FILENAME)) == 1

    def test_positive_api_key(self):
        """ENV with API_KEY in name → finding."""
        df = "FROM ubuntu:22.04\nENV API_KEY=mykey\n"
        assert len(self.rule.match(df, FILENAME)) == 1

    def test_positive_access_key(self):
        """ENV with ACCESS_KEY in name → finding."""
        df = "FROM ubuntu:22.04\nENV AWS_ACCESS_KEY=AKIA...\n"
        assert len(self.rule.match(df, FILENAME)) == 1

    def test_positive_multiple(self):
        """Multiple secret ENV vars → multiple findings."""
        df = "FROM ubuntu:22.04\nENV DB_PASSWORD=x\nENV API_TOKEN=y\n"
        assert len(self.rule.match(df, FILENAME)) == 2

    def test_negative_safe_env(self):
        """ENV with non-secret name → no finding."""
        df = "FROM ubuntu:22.04\nENV APP_PORT=8080\n"
        assert self.rule.match(df, FILENAME) == []

    def test_negative_safe_env_name(self):
        """ENV APP_ENV=production → no finding."""
        df = "FROM ubuntu:22.04\nENV APP_ENV=production\n"
        assert self.rule.match(df, FILENAME) == []

    def test_negative_credential_in_value_not_name(self):
        """Secret word only appears in value, not name → no finding."""
        df = "FROM ubuntu:22.04\nENV CONFIG_PATH=/etc/secret.conf\n"
        assert self.rule.match(df, FILENAME) == []


# ── DOCKER_NO_HEALTHCHECK ─────────────────────────────────────────────────────


class TestDockerNoHealthcheck:
    rule = DockerNoHealthcheck()

    def test_positive_no_healthcheck(self):
        """Dockerfile without HEALTHCHECK → finding."""
        df = "FROM ubuntu:22.04\nRUN apt-get update\n"
        findings = self.rule.match(df, FILENAME)
        assert len(findings) == 1
        assert findings[0].rule_id == "DOCKER_NO_HEALTHCHECK"

    def test_negative_healthcheck_present(self):
        """HEALTHCHECK defined → no finding."""
        df = (
            "FROM ubuntu:22.04\n"
            "RUN apt-get update\n"
            "HEALTHCHECK CMD curl -f http://localhost/ || exit 1\n"
        )
        assert self.rule.match(df, FILENAME) == []

    def test_negative_not_a_dockerfile(self):
        """File without FROM → no finding."""
        df = "# just a comment\nsome: yaml: content\n"
        assert self.rule.match(df, FILENAME) == []

    def test_negative_healthcheck_none(self):
        """HEALTHCHECK NONE disables check — still counts as defined → no finding."""
        df = "FROM ubuntu:22.04\nHEALTHCHECK NONE\n"
        assert self.rule.match(df, FILENAME) == []


# ── DOCKER_ROOT_USER ──────────────────────────────────────────────────────────


class TestDockerRootUser:
    rule = DockerRootUser()

    def test_positive_no_user(self):
        """No USER instruction → finding (default is root)."""
        df = "FROM ubuntu:22.04\nRUN apt-get update\n"
        findings = self.rule.match(df, FILENAME)
        assert len(findings) == 1
        assert findings[0].rule_id == "DOCKER_ROOT_USER"

    def test_positive_explicit_root(self):
        """USER root → finding."""
        df = "FROM ubuntu:22.04\nUSER root\n"
        assert len(self.rule.match(df, FILENAME)) == 1

    def test_positive_explicit_zero(self):
        """USER 0 → finding."""
        df = "FROM ubuntu:22.04\nUSER 0\n"
        assert len(self.rule.match(df, FILENAME)) == 1

    def test_negative_non_root_user(self):
        """USER appuser → no finding."""
        df = "FROM ubuntu:22.04\nRUN useradd -m appuser\nUSER appuser\n"
        assert self.rule.match(df, FILENAME) == []

    def test_negative_numeric_non_root(self):
        """USER 1000 → no finding."""
        df = "FROM ubuntu:22.04\nUSER 1000\n"
        assert self.rule.match(df, FILENAME) == []

    def test_negative_not_a_dockerfile(self):
        """No FROM → no finding."""
        df = "# just a comment\n"
        assert self.rule.match(df, FILENAME) == []


# ── DOCKER_SHELL_FORM_ENTRYPOINT ──────────────────────────────────────────────


class TestDockerShellFormEntrypoint:
    rule = DockerShellFormEntrypoint()

    def test_positive_shell_form(self):
        """ENTRYPOINT python app.py (shell form) → finding."""
        df = "FROM python:3.11\nENTRYPOINT python app.py\n"
        findings = self.rule.match(df, FILENAME)
        assert len(findings) == 1
        assert findings[0].rule_id == "DOCKER_SHELL_FORM_ENTRYPOINT"

    def test_positive_shell_form_with_slash(self):
        """ENTRYPOINT /entrypoint.sh (shell form) → finding."""
        df = "FROM ubuntu:22.04\nENTRYPOINT /entrypoint.sh\n"
        assert len(self.rule.match(df, FILENAME)) == 1

    def test_negative_exec_form(self):
        """ENTRYPOINT [\"python\", \"app.py\"] (exec form) → no finding."""
        df = 'FROM python:3.11\nENTRYPOINT ["python", "app.py"]\n'
        assert self.rule.match(df, FILENAME) == []

    def test_negative_no_entrypoint(self):
        """No ENTRYPOINT instruction → no finding."""
        df = "FROM ubuntu:22.04\nCMD [\"/bin/bash\"]\n"
        assert self.rule.match(df, FILENAME) == []


# ── DOCKER_APT_GET_UPGRADE ────────────────────────────────────────────────────


class TestDockerAptGetUpgrade:
    rule = DockerAptGetUpgrade()

    def test_positive_apt_get_upgrade(self):
        """RUN apt-get upgrade → finding."""
        df = "FROM ubuntu:22.04\nRUN apt-get upgrade -y\n"
        findings = self.rule.match(df, FILENAME)
        assert len(findings) == 1
        assert findings[0].rule_id == "DOCKER_APT_GET_UPGRADE"

    def test_positive_apt_upgrade(self):
        """RUN apt upgrade → finding."""
        df = "FROM ubuntu:22.04\nRUN apt upgrade\n"
        assert len(self.rule.match(df, FILENAME)) == 1

    def test_positive_combined_with_update(self):
        """RUN apt-get update && apt-get upgrade → finding."""
        df = "FROM ubuntu:22.04\nRUN apt-get update && apt-get upgrade -y\n"
        assert len(self.rule.match(df, FILENAME)) == 1

    def test_negative_apt_get_install(self):
        """RUN apt-get install → no finding."""
        df = "FROM ubuntu:22.04\nRUN apt-get install -y curl\n"
        assert self.rule.match(df, FILENAME) == []

    def test_negative_apt_get_update(self):
        """RUN apt-get update only → no finding."""
        df = "FROM ubuntu:22.04\nRUN apt-get update\n"
        assert self.rule.match(df, FILENAME) == []

    def test_negative_no_run(self):
        """upgrade mentioned in comment, not RUN → no finding."""
        df = "FROM ubuntu:22.04\n# don't run apt-get upgrade\n"
        assert self.rule.match(df, FILENAME) == []
