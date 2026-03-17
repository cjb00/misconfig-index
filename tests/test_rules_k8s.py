"""Tests for new Kubernetes scanner rules (batch 2)."""
import pytest
from scanner.rules.kubernetes import (
    K8sNoLivenessProbe,
    K8sNoReadinessProbe,
    K8sAutomountServiceAccountToken,
    K8sPrivilegeEscalationAllowed,
    K8sSecretAsEnvVar,
    K8sNoPodSecurityContext,
    K8sHostPathMount,
    K8sIngressNoTls,
)

FILENAME = "deployment.yaml"


# ── K8S_NO_LIVENESS_PROBE ─────────────────────────────────────────────────────


class TestK8sNoLivenessProbe:
    rule = K8sNoLivenessProbe()

    def test_positive_no_probe(self):
        """containers: present but livenessProbe: absent → finding."""
        yaml = """
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.25
"""
        findings = self.rule.match(yaml, FILENAME)
        assert len(findings) == 1
        assert findings[0].rule_id == "K8S_NO_LIVENESS_PROBE"

    def test_negative_probe_present(self):
        """livenessProbe: defined → no finding."""
        yaml = """
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.25
          livenessProbe:
            httpGet:
              path: /healthz
              port: 8080
"""
        assert self.rule.match(yaml, FILENAME) == []

    def test_negative_no_containers(self):
        """No containers: key → no finding."""
        yaml = """
apiVersion: v1
kind: ConfigMap
metadata:
  name: example
"""
        assert self.rule.match(yaml, FILENAME) == []

    def test_negative_init_containers_only(self):
        """initContainers: present but not containers: → no finding."""
        yaml = """
spec:
  template:
    spec:
      initContainers:
        - name: init
          image: busybox
"""
        assert self.rule.match(yaml, FILENAME) == []


# ── K8S_NO_READINESS_PROBE ────────────────────────────────────────────────────


class TestK8sNoReadinessProbe:
    rule = K8sNoReadinessProbe()

    def test_positive_no_probe(self):
        """containers: present but readinessProbe: absent → finding."""
        yaml = """
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.25
"""
        findings = self.rule.match(yaml, FILENAME)
        assert len(findings) == 1
        assert findings[0].rule_id == "K8S_NO_READINESS_PROBE"

    def test_negative_probe_present(self):
        """readinessProbe: defined → no finding."""
        yaml = """
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.25
          readinessProbe:
            tcpSocket:
              port: 8080
"""
        assert self.rule.match(yaml, FILENAME) == []

    def test_negative_no_containers(self):
        """No containers: → no finding."""
        yaml = """
apiVersion: v1
kind: Service
"""
        assert self.rule.match(yaml, FILENAME) == []


# ── K8S_AUTOMOUNT_SERVICE_ACCOUNT_TOKEN ──────────────────────────────────────


class TestK8sAutomountServiceAccountToken:
    rule = K8sAutomountServiceAccountToken()

    def test_positive_no_opt_out(self):
        """containers: present, no automountServiceAccountToken: false → finding."""
        yaml = """
spec:
  template:
    spec:
      containers:
        - name: app
          image: myapp:1.0
"""
        findings = self.rule.match(yaml, FILENAME)
        assert len(findings) == 1
        assert findings[0].rule_id == "K8S_AUTOMOUNT_SERVICE_ACCOUNT_TOKEN"

    def test_negative_opt_out(self):
        """automountServiceAccountToken: false → no finding."""
        yaml = """
spec:
  template:
    spec:
      automountServiceAccountToken: false
      containers:
        - name: app
          image: myapp:1.0
"""
        assert self.rule.match(yaml, FILENAME) == []

    def test_negative_custom_service_account(self):
        """Custom serviceAccountName → no finding (opt-out by convention)."""
        yaml = """
spec:
  template:
    spec:
      serviceAccountName: my-restricted-sa
      containers:
        - name: app
          image: myapp:1.0
"""
        assert self.rule.match(yaml, FILENAME) == []

    def test_negative_no_containers(self):
        """No containers: → no finding."""
        yaml = """
apiVersion: v1
kind: ServiceAccount
metadata:
  name: example
"""
        assert self.rule.match(yaml, FILENAME) == []


# ── K8S_PRIVILEGE_ESCALATION_ALLOWED ─────────────────────────────────────────


class TestK8sPrivilegeEscalationAllowed:
    rule = K8sPrivilegeEscalationAllowed()

    def test_positive_explicit_true(self):
        """allowPrivilegeEscalation: true → finding on that line."""
        yaml = """
spec:
  containers:
    - name: app
      securityContext:
        allowPrivilegeEscalation: true
"""
        findings = self.rule.match(yaml, FILENAME)
        assert len(findings) == 1
        assert findings[0].rule_id == "K8S_PRIVILEGE_ESCALATION_ALLOWED"

    def test_positive_absent(self):
        """allowPrivilegeEscalation absent (default true) → finding."""
        yaml = """
spec:
  template:
    spec:
      containers:
        - name: app
          image: myapp:1.0
"""
        findings = self.rule.match(yaml, FILENAME)
        assert len(findings) == 1
        assert findings[0].rule_id == "K8S_PRIVILEGE_ESCALATION_ALLOWED"

    def test_negative_explicit_false(self):
        """allowPrivilegeEscalation: false → no finding."""
        yaml = """
spec:
  containers:
    - name: app
      securityContext:
        allowPrivilegeEscalation: false
"""
        assert self.rule.match(yaml, FILENAME) == []

    def test_negative_no_containers(self):
        """No containers: → no finding."""
        yaml = """
apiVersion: v1
kind: ConfigMap
"""
        assert self.rule.match(yaml, FILENAME) == []


# ── K8S_SECRET_AS_ENV_VAR ────────────────────────────────────────────────────


class TestK8sSecretAsEnvVar:
    rule = K8sSecretAsEnvVar()

    def test_positive_secret_key_ref(self):
        """secretKeyRef in env → finding."""
        yaml = """
spec:
  containers:
    - name: app
      env:
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: password
"""
        findings = self.rule.match(yaml, FILENAME)
        assert len(findings) == 1
        assert findings[0].rule_id == "K8S_SECRET_AS_ENV_VAR"

    def test_positive_multiple_refs(self):
        """Two secretKeyRef entries → two findings."""
        yaml = """
spec:
  containers:
    - name: app
      env:
        - name: DB_PASS
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: password
        - name: API_KEY
          valueFrom:
            secretKeyRef:
              name: api-secret
              key: key
"""
        assert len(self.rule.match(yaml, FILENAME)) == 2

    def test_negative_config_map_ref(self):
        """configMapKeyRef only → no finding."""
        yaml = """
spec:
  containers:
    - name: app
      env:
        - name: APP_ENV
          valueFrom:
            configMapKeyRef:
              name: app-config
              key: environment
"""
        assert self.rule.match(yaml, FILENAME) == []

    def test_negative_literal_env(self):
        """Literal env value → no finding."""
        yaml = """
spec:
  containers:
    - name: app
      env:
        - name: APP_ENV
          value: "production"
"""
        assert self.rule.match(yaml, FILENAME) == []


# ── K8S_NO_POD_SECURITY_CONTEXT ──────────────────────────────────────────────


class TestK8sNoPodSecurityContext:
    rule = K8sNoPodSecurityContext()

    def test_positive_no_security_context(self):
        """containers: present but securityContext: absent → finding."""
        yaml = """
spec:
  template:
    spec:
      containers:
        - name: app
          image: myapp:1.0
"""
        findings = self.rule.match(yaml, FILENAME)
        assert len(findings) == 1
        assert findings[0].rule_id == "K8S_NO_POD_SECURITY_CONTEXT"

    def test_negative_security_context_present(self):
        """securityContext: defined → no finding."""
        yaml = """
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
      containers:
        - name: app
          image: myapp:1.0
"""
        assert self.rule.match(yaml, FILENAME) == []

    def test_negative_no_containers(self):
        """No containers: → no finding."""
        yaml = """
apiVersion: v1
kind: ServiceAccount
"""
        assert self.rule.match(yaml, FILENAME) == []


# ── K8S_HOST_PATH_MOUNT ───────────────────────────────────────────────────────


class TestK8sHostPathMount:
    rule = K8sHostPathMount()

    def test_positive_host_path(self):
        """hostPath: in volumes → finding."""
        yaml = """
spec:
  template:
    spec:
      volumes:
        - name: host-vol
          hostPath:
            path: /var/log
      containers:
        - name: app
          image: myapp:1.0
"""
        findings = self.rule.match(yaml, FILENAME)
        assert len(findings) == 1
        assert findings[0].rule_id == "K8S_HOST_PATH_MOUNT"

    def test_negative_pvc(self):
        """PersistentVolumeClaim instead of hostPath → no finding."""
        yaml = """
spec:
  template:
    spec:
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: my-pvc
      containers:
        - name: app
          image: myapp:1.0
"""
        assert self.rule.match(yaml, FILENAME) == []

    def test_negative_empty_dir(self):
        """emptyDir volume → no finding."""
        yaml = """
spec:
  volumes:
    - name: tmp
      emptyDir: {}
"""
        assert self.rule.match(yaml, FILENAME) == []


# ── K8S_INGRESS_NO_TLS ────────────────────────────────────────────────────────


class TestK8sIngressNoTls:
    rule = K8sIngressNoTls()

    def test_positive_ingress_no_tls(self):
        """kind: Ingress without tls: → finding."""
        yaml = """
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: example
spec:
  rules:
    - host: example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: my-service
                port:
                  number: 80
"""
        findings = self.rule.match(yaml, FILENAME)
        assert len(findings) == 1
        assert findings[0].rule_id == "K8S_INGRESS_NO_TLS"

    def test_negative_ingress_with_tls(self):
        """kind: Ingress with tls: → no finding."""
        yaml = """
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: example
spec:
  tls:
    - hosts:
        - example.com
      secretName: example-tls
  rules:
    - host: example.com
"""
        assert self.rule.match(yaml, FILENAME) == []

    def test_negative_not_ingress(self):
        """kind: Deployment (not Ingress) → no finding."""
        yaml = """
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.25
"""
        assert self.rule.match(yaml, FILENAME) == []
