from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    JSON,
    func,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


# ---------------------------------------------------------------------------
# Phase 2: Multi-tenancy
# ---------------------------------------------------------------------------

class User(Base):
    """A GitHub-authenticated user account."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    github_id = Column(Integer, unique=True, nullable=False, index=True)
    github_login = Column(String, nullable=False)          # GitHub username
    github_email = Column(String, nullable=True)
    avatar_url = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Billing — Stripe integration
    plan = Column(String, nullable=False, default="free", server_default="free")
    plan_status = Column(String, nullable=True)             # "active" | "past_due" | "canceled"
    stripe_customer_id = Column(String, nullable=True, index=True)
    stripe_subscription_id = Column(String, nullable=True)

    user_orgs = relationship("UserOrg", back_populates="user")


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    slug = Column(String, nullable=False, unique=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    api_keys = relationship("ApiKey", back_populates="org")
    sources = relationship("Source", back_populates="org")
    user_orgs = relationship("UserOrg", back_populates="org")


class UserOrg(Base):
    """Links a User to an Organization with a role."""
    __tablename__ = "user_orgs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    role = Column(String, nullable=False, default="owner")  # owner | member
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="user_orgs")
    org = relationship("Organization", back_populates="user_orgs")


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    name = Column(String, nullable=False)
    key_prefix = Column(String, nullable=False)         # first 10 chars, for display
    key_hash = Column(String, nullable=False, unique=True, index=True)  # sha256 of full key
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)

    org = relationship("Organization", back_populates="api_keys")


# ---------------------------------------------------------------------------
# Core scanning models
# ---------------------------------------------------------------------------

class MisconfigRule(Base):
    __tablename__ = "misconfig_rules"

    id = Column(String, primary_key=True, index=True)
    category = Column(String, nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String, nullable=False)
    tags = Column(JSON, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )

    findings = relationship("Finding", back_populates="rule")


class Source(Base):
    __tablename__ = "sources"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True)  # null = local scan
    source_type = Column(String, nullable=False)
    # e.g. "github.com/user/repo" or "local:/path/to/dir"
    identifier = Column(String, nullable=False)
    meta = Column(JSON, nullable=True)
    first_seen_at = Column(DateTime, server_default=func.now())
    last_seen_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )

    org = relationship("Organization", back_populates="sources")
    scans = relationship("Scan", back_populates="source")
    files = relationship("File", back_populates="source")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    source_id = Column(Integer, ForeignKey("sources.id"), nullable=False)
    started_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    status = Column(String, nullable=False, default="success")
    notes = Column(Text, nullable=True)
    # Phase 2: ingest metadata
    commit_sha = Column(String, nullable=True)
    branch = Column(String, nullable=True)
    scanner_version = Column(String, nullable=True)
    # Phase 1: scoring
    score = Column(Integer, nullable=True)
    score_breakdown = Column(JSON, nullable=True)       # {"grade": "B", "networking": 85, ...}
    total_files_scanned = Column(Integer, nullable=True)

    source = relationship("Source", back_populates="scans")
    findings = relationship("Finding", back_populates="scan")


class File(Base):
    __tablename__ = "files"

    id = Column(Integer, primary_key=True, index=True)
    source_id = Column(Integer, ForeignKey("sources.id"), nullable=False)
    path = Column(String, nullable=False)
    file_type = Column(String, nullable=False)
    hash = Column(String, nullable=True)
    last_seen_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )

    source = relationship("Source", back_populates="files")
    findings = relationship("Finding", back_populates="file")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    file_id = Column(Integer, ForeignKey("files.id"), nullable=False)
    rule_id = Column(String, ForeignKey("misconfig_rules.id"), nullable=False)
    line_start = Column(Integer, nullable=True)
    line_end = Column(Integer, nullable=True)
    snippet = Column(String, nullable=False)
    extra = Column(JSON, nullable=True)
    detected_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="findings")
    file = relationship("File", back_populates="findings")
    rule = relationship("MisconfigRule", back_populates="findings")


class WaitlistEntry(Base):
    """Pro plan waitlist — collected before LLC / billing is fully set up."""
    __tablename__ = "waitlist"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, nullable=False, unique=True, index=True)
    created_at = Column(DateTime, server_default=func.now())
