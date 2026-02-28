import os
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()


@dataclass
class ScannerConfig:
    github_token: str | None = None
    database_url: str | None = None

    @classmethod
    def from_env(cls) -> "ScannerConfig":
        return cls(
            github_token=os.getenv("GITHUB_TOKEN"),
            database_url=os.getenv("DATABASE_URL"),
        )
