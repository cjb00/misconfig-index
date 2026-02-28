"""
Allows running the scanner as a module:

    python -m scanner scan --path ./infra
    python -m scanner ingest --repo github.com/org/repo --path ./infra
    python -m scanner serve
"""
from scanner.cmd import cli

if __name__ == "__main__":
    cli()
