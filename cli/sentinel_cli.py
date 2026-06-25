#!/usr/bin/env python3
"""
sentinel_cli.py
-----------------
Packages Sentinel as an installable "skill" invokable from the command
line, the way the course's Agents CLI material expects a reusable skill
to be exposed. This is intentionally thin -- the real logic lives in
sentinel_policy.py / worker_agent.py -- the CLI's job is just to make
that logic runnable as a standalone command.

Examples:
    python cli/sentinel_cli.py list-scenarios
    python cli/sentinel_cli.py run injection
    python cli/sentinel_cli.py run all
    python cli/sentinel_cli.py run financial_fraud --llm-judge
"""

import argparse
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scenarios"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agents"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools_server"))

from run_scenarios import SCENARIOS, run_scenario  # noqa: E402


def cmd_list(_args) -> None:
    print("Available scenarios:")
    for name, cfg in SCENARIOS.items():
        print(f"  - {name}: {cfg['description']}")


def cmd_run(args) -> None:
    targets = list(SCENARIOS.keys()) if args.scenario == "all" else [args.scenario]
    for name in targets:
        asyncio.run(run_scenario(name))


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel: a runtime security-guardian skill for tool-using AI agents.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser(
        "list-scenarios",
        help="List all available demo attack scenarios.",
    ).set_defaults(func=cmd_list)

    run_parser = sub.add_parser("run", help="Run one (or all) demo scenarios.")
    run_parser.add_argument(
        "scenario",
        choices=list(SCENARIOS.keys()) + ["all"],
        help="Scenario name, or 'all' to run every scenario in sequence.",
    )
    run_parser.add_argument(
        "--llm-judge",
        action="store_true",
        default=False,
        help=(
            "Enable the Gemini LLM-as-judge rule for semantic injection detection. "
            "Adds latency and API cost; off by default for free-tier demos."
        ),
    )
    run_parser.set_defaults(func=cmd_run)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
