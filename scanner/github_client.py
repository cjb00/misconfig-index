"""
Lightweight GitHub client stub. Extend with authenticated requests to fetch IaC files.
"""
from __future__ import annotations

import logging
from typing import List

import requests

logger = logging.getLogger(__name__)


class GitHubClient:
    def __init__(self, token: str | None = None):
        self.session = requests.Session()
        if token:
            self.session.headers.update({"Authorization": f"token {token}"})

    def fetch_repo_files(self, repo: str, path: str = "") -> List[str]:
        """
        Placeholder for GitHub API integration. Return a list of file paths.
        """
        logger.info("fetch_repo_files called for repo=%s path=%s (stub)", repo, path)
        return []

    def fetch_file_content(self, repo: str, file_path: str) -> str:
        logger.info("fetch_file_content called for repo=%s file_path=%s (stub)", repo, file_path)
        return ""
