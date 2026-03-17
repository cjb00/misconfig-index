"""Tests for CloudFormation scanner rules."""
import pytest
from scanner.rules.cloudformation import (
    CfnS3PublicAccess,
    CfnSgOpen,
    CfnRdsPublic,
    CfnIamWildcard,
)

FILENAME = "template.yaml"


# ── CFN_S3_PUBLIC_ACCESS ──────────────────────────────────────────────────────


class TestCfnS3PublicAccess:
    rule = CfnS3PublicAccess()

    def test_positive_no_public_access_block(self):
        """S3 bucket with no PublicAccessBlockConfiguration → finding."""
        cfn = """
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-bucket
"""
        findings = self.rule.match(cfn, FILENAME)
        assert len(findings) == 1
        assert findings[0].rule_id == "CFN_S3_PUBLIC_ACCESS"

    def test_positive_block_public_acls_false(self):
        """BlockPublicAcls: false → finding."""
        cfn = """
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      PublicAccessBlockConfiguration:
        BlockPublicAcls: false
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
"""
        assert len(self.rule.match(cfn, FILENAME)) == 1

    def test_positive_restrict_public_buckets_false(self):
        """RestrictPublicBuckets: false → finding."""
        cfn = """
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: false
"""
        assert len(self.rule.match(cfn, FILENAME)) == 1

    def test_negative_all_true(self):
        """All four settings true → no finding."""
        cfn = """
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
"""
        assert self.rule.match(cfn, FILENAME) == []

    def test_negative_no_s3_resources(self):
        """Template with no S3 buckets → no finding."""
        cfn = """
Resources:
  MyQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: my-queue
"""
        assert self.rule.match(cfn, FILENAME) == []

    def test_positive_multiple_buckets_one_bad(self):
        """Two buckets, one without block config → one finding."""
        cfn = """
Resources:
  GoodBucket:
    Type: AWS::S3::Bucket
    Properties:
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
  BadBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: bad-bucket
"""
        findings = self.rule.match(cfn, FILENAME)
        assert len(findings) == 1


# ── CFN_SG_OPEN ───────────────────────────────────────────────────────────────


class TestCfnSgOpen:
    rule = CfnSgOpen()

    def test_positive_open_ipv4(self):
        """SecurityGroupIngress with CidrIp: 0.0.0.0/0 → finding."""
        cfn = """
Resources:
  MySecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Open SG
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
"""
        findings = self.rule.match(cfn, FILENAME)
        assert len(findings) == 1
        assert findings[0].rule_id == "CFN_SG_OPEN"

    def test_positive_open_ipv6(self):
        """CidrIpv6: ::/0 → finding."""
        cfn = """
Resources:
  MySecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Open SG
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIpv6: "::/0"
"""
        assert len(self.rule.match(cfn, FILENAME)) == 1

    def test_negative_restricted_cidr(self):
        """CidrIp restricted to internal range → no finding."""
        cfn = """
Resources:
  MySecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Internal SG
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 10.0.0.0/8
"""
        assert self.rule.match(cfn, FILENAME) == []

    def test_negative_no_security_groups(self):
        """Template with no security groups → no finding."""
        cfn = """
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
"""
        assert self.rule.match(cfn, FILENAME) == []


# ── CFN_RDS_PUBLIC ────────────────────────────────────────────────────────────


class TestCfnRdsPublic:
    rule = CfnRdsPublic()

    def test_positive_publicly_accessible_true(self):
        """PubliclyAccessible: true → finding."""
        cfn = """
Resources:
  MyDatabase:
    Type: AWS::RDS::DBInstance
    Properties:
      DBInstanceClass: db.t3.micro
      Engine: mysql
      PubliclyAccessible: true
"""
        findings = self.rule.match(cfn, FILENAME)
        assert len(findings) == 1
        assert findings[0].rule_id == "CFN_RDS_PUBLIC"

    def test_negative_publicly_accessible_false(self):
        """PubliclyAccessible: false → no finding."""
        cfn = """
Resources:
  MyDatabase:
    Type: AWS::RDS::DBInstance
    Properties:
      DBInstanceClass: db.t3.micro
      Engine: mysql
      PubliclyAccessible: false
"""
        assert self.rule.match(cfn, FILENAME) == []

    def test_negative_absent(self):
        """PubliclyAccessible absent (defaults to false in VPC) → no finding."""
        cfn = """
Resources:
  MyDatabase:
    Type: AWS::RDS::DBInstance
    Properties:
      DBInstanceClass: db.t3.micro
      Engine: mysql
"""
        assert self.rule.match(cfn, FILENAME) == []

    def test_negative_no_rds_resources(self):
        """No RDS resources → no finding."""
        cfn = """
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
"""
        assert self.rule.match(cfn, FILENAME) == []


# ── CFN_IAM_WILDCARD ──────────────────────────────────────────────────────────


class TestCfnIamWildcard:
    rule = CfnIamWildcard()

    def test_positive_iam_policy(self):
        """AWS::IAM::Policy with Resource: '*' → finding."""
        cfn = """
Resources:
  MyPolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: wildcard-policy
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Action: "s3:*"
            Resource: "*"
"""
        findings = self.rule.match(cfn, FILENAME)
        assert len(findings) == 1
        assert findings[0].rule_id == "CFN_IAM_WILDCARD"

    def test_positive_managed_policy(self):
        """AWS::IAM::ManagedPolicy with Resource: '*' → finding."""
        cfn = """
Resources:
  MyManagedPolicy:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Action: "ec2:*"
            Resource: "*"
"""
        assert len(self.rule.match(cfn, FILENAME)) == 1

    def test_positive_iam_role_inline(self):
        """AWS::IAM::Role with inline Resource: '*' → finding."""
        cfn = """
Resources:
  MyRole:
    Type: AWS::IAM::Role
    Properties:
      Policies:
        - PolicyName: inline
          PolicyDocument:
            Statement:
              - Effect: Allow
                Action: "logs:*"
                Resource: "*"
"""
        assert len(self.rule.match(cfn, FILENAME)) == 1

    def test_negative_scoped_resource(self):
        """Resource scoped to specific ARN → no finding."""
        cfn = """
Resources:
  MyPolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyDocument:
        Statement:
          - Effect: Allow
            Action: "s3:GetObject"
            Resource: "arn:aws:s3:::my-bucket/*"
"""
        assert self.rule.match(cfn, FILENAME) == []

    def test_negative_no_iam_resources(self):
        """No IAM resources → no finding."""
        cfn = """
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
"""
        assert self.rule.match(cfn, FILENAME) == []
