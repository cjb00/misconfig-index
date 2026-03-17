"""Tests for new S3 and RDS Terraform scanner rules."""
import pytest
from scanner.rules.terraform import (
    TfS3PublicAccessNotBlocked,
    TfS3VersioningDisabled,
    TfS3EncryptionDisabled,
    TfRdsDeletionProtectionDisabled,
    TfRdsStorageEncryptedDisabled,
)

FILENAME = "main.tf"


# ── TF_S3_PUBLIC_ACCESS_NOT_BLOCKED ──────────────────────────────────────────


class TestTfS3PublicAccessNotBlocked:
    rule = TfS3PublicAccessNotBlocked()

    def test_positive_no_block_resource(self):
        """Bucket with no aws_s3_bucket_public_access_block → finding."""
        tf = """
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
}
"""
        findings = self.rule.match(tf, FILENAME)
        assert len(findings) == 1
        assert findings[0].rule_id == "TF_S3_PUBLIC_ACCESS_NOT_BLOCKED"

    def test_negative_block_resource_present(self):
        """Bucket with associated public access block → no finding."""
        tf = """
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
}

resource "aws_s3_bucket_public_access_block" "example" {
  bucket              = aws_s3_bucket.example.id
  block_public_acls   = true
  block_public_policy = true
  ignore_public_acls  = true
  restrict_public_buckets = true
}
"""
        assert self.rule.match(tf, FILENAME) == []

    def test_multiple_buckets_partial_coverage(self):
        """Two buckets, only one covered → one finding."""
        tf = """
resource "aws_s3_bucket" "covered" {
  bucket = "bucket-a"
}

resource "aws_s3_bucket" "uncovered" {
  bucket = "bucket-b"
}

resource "aws_s3_bucket_public_access_block" "covered" {
  bucket = aws_s3_bucket.covered.id
  block_public_acls = true
}
"""
        findings = self.rule.match(tf, FILENAME)
        assert len(findings) == 1
        assert findings[0].rule_id == "TF_S3_PUBLIC_ACCESS_NOT_BLOCKED"


# ── TF_S3_VERSIONING_DISABLED ────────────────────────────────────────────────


class TestTfS3VersioningDisabled:
    rule = TfS3VersioningDisabled()

    def test_positive_old_style_disabled(self):
        """Old-style versioning { enabled = false } → finding."""
        tf = """
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  versioning {
    enabled = false
  }
}
"""
        findings = self.rule.match(tf, FILENAME)
        assert len(findings) == 1
        assert findings[0].rule_id == "TF_S3_VERSIONING_DISABLED"

    def test_positive_new_style_no_status(self):
        """New-style aws_s3_bucket_versioning without status = Enabled → finding."""
        tf = """
resource "aws_s3_bucket_versioning" "example" {
  bucket = aws_s3_bucket.example.id
  versioning_configuration {
    status = "Suspended"
  }
}
"""
        findings = self.rule.match(tf, FILENAME)
        assert len(findings) == 1
        assert findings[0].rule_id == "TF_S3_VERSIONING_DISABLED"

    def test_positive_new_style_absent_status(self):
        """New-style aws_s3_bucket_versioning with no status attribute → finding."""
        tf = """
resource "aws_s3_bucket_versioning" "example" {
  bucket = aws_s3_bucket.example.id
  versioning_configuration {}
}
"""
        assert len(self.rule.match(tf, FILENAME)) == 1

    def test_negative_new_style_enabled(self):
        """New-style with status = Enabled → no finding."""
        tf = """
resource "aws_s3_bucket_versioning" "example" {
  bucket = aws_s3_bucket.example.id
  versioning_configuration {
    status = "Enabled"
  }
}
"""
        assert self.rule.match(tf, FILENAME) == []

    def test_negative_old_style_enabled(self):
        """Old-style with enabled = true (implicit, no false present) → no finding."""
        tf = """
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  versioning {
    enabled = true
  }
}
"""
        assert self.rule.match(tf, FILENAME) == []


# ── TF_S3_ENCRYPTION_DISABLED ────────────────────────────────────────────────


class TestTfS3EncryptionDisabled:
    rule = TfS3EncryptionDisabled()

    def test_positive_no_sse_resource(self):
        """Bucket with no SSE configuration resource → finding."""
        tf = """
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
}
"""
        findings = self.rule.match(tf, FILENAME)
        assert len(findings) == 1
        assert findings[0].rule_id == "TF_S3_ENCRYPTION_DISABLED"

    def test_negative_sse_resource_present(self):
        """Bucket with associated SSE configuration → no finding."""
        tf = """
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  bucket = aws_s3_bucket.example.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
"""
        assert self.rule.match(tf, FILENAME) == []

    def test_no_buckets(self):
        """File with no S3 buckets → no findings."""
        tf = """
resource "aws_security_group" "example" {
  name = "example"
}
"""
        assert self.rule.match(tf, FILENAME) == []


# ── TF_RDS_DELETION_PROTECTION_DISABLED ──────────────────────────────────────


class TestTfRdsDeletionProtectionDisabled:
    rule = TfRdsDeletionProtectionDisabled()

    def test_positive_explicit_false(self):
        """deletion_protection = false → finding."""
        tf = """
resource "aws_db_instance" "example" {
  identifier        = "mydb"
  engine            = "mysql"
  instance_class    = "db.t3.micro"
  deletion_protection = false
}
"""
        findings = self.rule.match(tf, FILENAME)
        assert len(findings) == 1
        assert findings[0].rule_id == "TF_RDS_DELETION_PROTECTION_DISABLED"

    def test_positive_absent(self):
        """deletion_protection not set at all → finding (default is false)."""
        tf = """
resource "aws_db_instance" "example" {
  identifier     = "mydb"
  engine         = "mysql"
  instance_class = "db.t3.micro"
}
"""
        findings = self.rule.match(tf, FILENAME)
        assert len(findings) == 1

    def test_negative_enabled(self):
        """deletion_protection = true → no finding."""
        tf = """
resource "aws_db_instance" "example" {
  identifier          = "mydb"
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  deletion_protection = true
}
"""
        assert self.rule.match(tf, FILENAME) == []

    def test_no_rds_resources(self):
        """File with no aws_db_instance → no findings."""
        tf = """
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
}
"""
        assert self.rule.match(tf, FILENAME) == []


# ── TF_RDS_STORAGE_ENCRYPTED_DISABLED ────────────────────────────────────────


class TestTfRdsStorageEncryptedDisabled:
    rule = TfRdsStorageEncryptedDisabled()

    def test_positive_explicit_false(self):
        """storage_encrypted = false → finding."""
        tf = """
resource "aws_db_instance" "example" {
  identifier        = "mydb"
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  storage_encrypted = false
}
"""
        findings = self.rule.match(tf, FILENAME)
        assert len(findings) == 1
        assert findings[0].rule_id == "TF_RDS_STORAGE_ENCRYPTED_DISABLED"

    def test_positive_absent(self):
        """storage_encrypted not set → finding (default is false)."""
        tf = """
resource "aws_db_instance" "example" {
  identifier     = "mydb"
  engine         = "postgres"
  instance_class = "db.t3.micro"
}
"""
        assert len(self.rule.match(tf, FILENAME)) == 1

    def test_negative_enabled(self):
        """storage_encrypted = true → no finding."""
        tf = """
resource "aws_db_instance" "example" {
  identifier        = "mydb"
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  storage_encrypted = true
}
"""
        assert self.rule.match(tf, FILENAME) == []
