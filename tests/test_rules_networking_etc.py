"""Tests for new networking, storage, workload, and logging Terraform scanner rules."""
import pytest
from scanner.rules.terraform import (
    TfSgSshOpenInternet,
    TfSgRdpOpen,
    TfEbsEncryptionDisabled,
    TfEcrImageScanDisabled,
    TfCloudtrailDisabled,
    TfKmsRotationDisabled,
)

FILENAME = "main.tf"


# ── TF_SG_SSH_OPEN ────────────────────────────────────────────────────────────


class TestTfSgSshOpenInternet:
    rule = TfSgSshOpenInternet()

    def test_positive_exact_port_cidr(self):
        """Inline ingress with exact port 22 and 0.0.0.0/0 → finding."""
        tf = """
resource "aws_security_group" "example" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""
        findings = self.rule.match(tf, FILENAME)
        assert len(findings) == 1
        assert findings[0].rule_id == "TF_SG_SSH_OPEN"

    def test_positive_port_range_covers_22(self):
        """Port range from=0 to=65535 covering port 22 → finding."""
        tf = """
resource "aws_security_group" "wide_open" {
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""
        assert len(self.rule.match(tf, FILENAME)) == 1

    def test_positive_ipv6(self):
        """Port 22 open to ::/0 (IPv6 all) → finding."""
        tf = """
resource "aws_security_group" "example" {
  ingress {
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }
}
"""
        assert len(self.rule.match(tf, FILENAME)) == 1

    def test_positive_sg_rule_resource(self):
        """aws_security_group_rule with ingress + port 22 + 0.0.0.0/0 → finding."""
        tf = """
resource "aws_security_group_rule" "ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
  security_group_id = aws_security_group.example.id
}
"""
        assert len(self.rule.match(tf, FILENAME)) == 1

    def test_negative_restricted_cidr(self):
        """Port 22 open only to specific CIDR → no finding."""
        tf = """
resource "aws_security_group" "example" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
"""
        assert self.rule.match(tf, FILENAME) == []

    def test_negative_different_port(self):
        """0.0.0.0/0 but only port 443 → no finding."""
        tf = """
resource "aws_security_group" "example" {
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""
        assert self.rule.match(tf, FILENAME) == []

    def test_negative_egress_not_ingress(self):
        """Egress rule with port 22 and 0.0.0.0/0 → no finding."""
        tf = """
resource "aws_security_group" "example" {
  egress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""
        assert self.rule.match(tf, FILENAME) == []


# ── TF_SG_RDP_OPEN ────────────────────────────────────────────────────────────


class TestTfSgRdpOpen:
    rule = TfSgRdpOpen()

    def test_positive_exact_port(self):
        """Port 3389 with 0.0.0.0/0 → finding."""
        tf = """
resource "aws_security_group" "example" {
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""
        findings = self.rule.match(tf, FILENAME)
        assert len(findings) == 1
        assert findings[0].rule_id == "TF_SG_RDP_OPEN"

    def test_positive_port_range(self):
        """Wide port range covering 3389 + 0.0.0.0/0 → finding."""
        tf = """
resource "aws_security_group" "example" {
  ingress {
    from_port   = 1024
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""
        assert len(self.rule.match(tf, FILENAME)) == 1

    def test_positive_ipv6(self):
        """Port 3389 open to ::/0 → finding."""
        tf = """
resource "aws_security_group" "example" {
  ingress {
    from_port        = 3389
    to_port          = 3389
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }
}
"""
        assert len(self.rule.match(tf, FILENAME)) == 1

    def test_negative_restricted_cidr(self):
        """Port 3389 to specific CIDR only → no finding."""
        tf = """
resource "aws_security_group" "example" {
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["192.168.1.0/24"]
  }
}
"""
        assert self.rule.match(tf, FILENAME) == []

    def test_negative_different_port(self):
        """0.0.0.0/0 but port 80 only → no finding."""
        tf = """
resource "aws_security_group" "example" {
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""
        assert self.rule.match(tf, FILENAME) == []


# ── TF_EBS_ENCRYPTION_DISABLED ────────────────────────────────────────────────


class TestTfEbsEncryptionDisabled:
    rule = TfEbsEncryptionDisabled()

    def test_positive_ebs_volume_absent(self):
        """aws_ebs_volume without encrypted attribute → finding."""
        tf = """
resource "aws_ebs_volume" "example" {
  availability_zone = "us-east-1a"
  size              = 20
}
"""
        findings = self.rule.match(tf, FILENAME)
        assert len(findings) == 1
        assert findings[0].rule_id == "TF_EBS_ENCRYPTION_DISABLED"

    def test_positive_ebs_volume_explicit_false(self):
        """aws_ebs_volume with encrypted = false → finding."""
        tf = """
resource "aws_ebs_volume" "example" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = false
}
"""
        assert len(self.rule.match(tf, FILENAME)) == 1

    def test_positive_instance_ebs_block_device(self):
        """aws_instance with unencrypted ebs_block_device → finding."""
        tf = """
resource "aws_instance" "example" {
  ami           = "ami-12345"
  instance_type = "t3.micro"
  ebs_block_device {
    device_name = "/dev/sdb"
    volume_size = 20
  }
}
"""
        assert len(self.rule.match(tf, FILENAME)) == 1

    def test_negative_ebs_volume_encrypted(self):
        """aws_ebs_volume with encrypted = true → no finding."""
        tf = """
resource "aws_ebs_volume" "example" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = true
}
"""
        assert self.rule.match(tf, FILENAME) == []

    def test_negative_instance_ebs_encrypted(self):
        """aws_instance ebs_block_device with encrypted = true → no finding."""
        tf = """
resource "aws_instance" "example" {
  ami           = "ami-12345"
  instance_type = "t3.micro"
  ebs_block_device {
    device_name = "/dev/sdb"
    volume_size = 20
    encrypted   = true
  }
}
"""
        assert self.rule.match(tf, FILENAME) == []


# ── TF_ECR_IMAGE_SCAN_DISABLED ────────────────────────────────────────────────


class TestTfEcrImageScanDisabled:
    rule = TfEcrImageScanDisabled()

    def test_positive_missing_scan_config(self):
        """aws_ecr_repository with no image_scanning_configuration → finding."""
        tf = """
resource "aws_ecr_repository" "example" {
  name = "my-repo"
}
"""
        findings = self.rule.match(tf, FILENAME)
        assert len(findings) == 1
        assert findings[0].rule_id == "TF_ECR_IMAGE_SCAN_DISABLED"

    def test_positive_scan_on_push_false(self):
        """scan_on_push = false → finding."""
        tf = """
resource "aws_ecr_repository" "example" {
  name = "my-repo"
  image_scanning_configuration {
    scan_on_push = false
  }
}
"""
        assert len(self.rule.match(tf, FILENAME)) == 1

    def test_negative_scan_on_push_true(self):
        """scan_on_push = true → no finding."""
        tf = """
resource "aws_ecr_repository" "example" {
  name = "my-repo"
  image_scanning_configuration {
    scan_on_push = true
  }
}
"""
        assert self.rule.match(tf, FILENAME) == []


# ── TF_CLOUDTRAIL_DISABLED ────────────────────────────────────────────────────


class TestTfCloudtrailDisabled:
    rule = TfCloudtrailDisabled()

    def test_positive_explicit_false(self):
        """enable_logging = false → finding."""
        tf = """
resource "aws_cloudtrail" "example" {
  name                  = "main"
  s3_bucket_name        = "my-bucket"
  enable_logging        = false
}
"""
        findings = self.rule.match(tf, FILENAME)
        assert len(findings) == 1
        assert findings[0].rule_id == "TF_CLOUDTRAIL_DISABLED"

    def test_negative_explicit_true(self):
        """enable_logging = true → no finding."""
        tf = """
resource "aws_cloudtrail" "example" {
  name           = "main"
  s3_bucket_name = "my-bucket"
  enable_logging = true
}
"""
        assert self.rule.match(tf, FILENAME) == []

    def test_negative_absent(self):
        """enable_logging absent (defaults to true) → no finding."""
        tf = """
resource "aws_cloudtrail" "example" {
  name           = "main"
  s3_bucket_name = "my-bucket"
}
"""
        assert self.rule.match(tf, FILENAME) == []


# ── TF_KMS_ROTATION_DISABLED ──────────────────────────────────────────────────


class TestTfKmsRotationDisabled:
    rule = TfKmsRotationDisabled()

    def test_positive_absent(self):
        """aws_kms_key without enable_key_rotation → finding (default false)."""
        tf = """
resource "aws_kms_key" "example" {
  description = "My KMS key"
}
"""
        findings = self.rule.match(tf, FILENAME)
        assert len(findings) == 1
        assert findings[0].rule_id == "TF_KMS_ROTATION_DISABLED"

    def test_positive_explicit_false(self):
        """enable_key_rotation = false → finding."""
        tf = """
resource "aws_kms_key" "example" {
  description        = "My KMS key"
  enable_key_rotation = false
}
"""
        assert len(self.rule.match(tf, FILENAME)) == 1

    def test_negative_rotation_enabled(self):
        """enable_key_rotation = true → no finding."""
        tf = """
resource "aws_kms_key" "example" {
  description         = "My KMS key"
  enable_key_rotation = true
}
"""
        assert self.rule.match(tf, FILENAME) == []

    def test_no_kms_resources(self):
        """File with no aws_kms_key → no findings."""
        tf = """
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
}
"""
        assert self.rule.match(tf, FILENAME) == []
