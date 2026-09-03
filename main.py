#!/usr/bin/env python3
"""CLI entry point: `webforg` or `webforg web`"""

import sys
import argparse

from webforg.core.config import get_settings
from webforg.core.logging import configure_logging, log_event
from webforg.cli import WebForgeREPL


def cli_entry():
    """Main entry point (registered in pyproject.toml as 'webforg')."""
    configure_logging()
    _S = get_settings()
    log_event("cli", "startup", app=_S.app_name, version=_S.version)

    parser = argparse.ArgumentParser(
        prog="webforg",
        description="WebForge — Web Exploitation Framework",
    )
    subparsers = parser.add_subparsers(dest="subcommand")

    # webforg (no args) — interactive CLI
    # webforg web — start web UI
    web_parser = subparsers.add_parser("web", help="Start web UI dashboard")
    web_parser.add_argument("--port", type=int, default=8443, help="Web UI port (default: 8443)")
    web_parser.add_argument("--host", type=str, default="0.0.0.0", help="Web UI bind host")
    web_parser.add_argument("--auth", action="store_true", help="Enable JWT auth for web UI")

    # webforg update — update CVE database
    subparsers.add_parser("update", help="Update CVE database from NVD + CISA KEV + Sploitus")

    args = parser.parse_args()

    if args.subcommand == "web":
        try:
            from webforg.core.rpc_server import start_web
            start_web(host=args.host, port=args.port, auth=args.auth)
        except ImportError as e:
            print(f"[!] Web UI dependencies not installed: {e}")
            sys.exit(1)

    elif args.subcommand == "update":
        from webforg.core.cve_db import update_cve_database
        update_cve_database()

    else:
        # Interactive CLI REPL
        repl = WebForgeREPL()
        repl.run()


if __name__ == "__main__":
    cli_entry()
