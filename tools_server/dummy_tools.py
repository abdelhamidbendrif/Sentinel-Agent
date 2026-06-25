"""
dummy_tools.py
---------------
A small, fully simulated toolset that stands in for "real" agent tools
(web search, file access, email, fund transfer, shell execution).

Why simulated tools?
We want full, safe control over tool *outputs* so we can deterministically
inject adversarial content (the way a real attacker would hide instructions
inside a search result or a file) without touching any real service or
real user data. Every tool below is pure Python with an in-memory "world"
that the demo scenarios can poison on purpose.

These functions are exposed over MCP by mcp_server.py in this same folder,
so the agent layer never imports this file directly -- it only ever talks
to tools through the Model Context Protocol, exactly like it would with a
real production MCP server.
"""

from __future__ import annotations
from typing import Dict, List

# ---------------------------------------------------------------------------
# In-memory "world state" the dummy tools operate on.
# Scenario scripts mutate this dict to plant adversarial content.
# ---------------------------------------------------------------------------
WORLD: Dict[str, object] = {
    "search_index": {
        "company offsite ideas": [
            "Top result: 'Best Offsite Venues 2026' - a roundup of team retreat spots.",
        ],
    },
    "files": {
        "notes/meeting_notes.txt": "Q3 planning notes: ship the v2 onboarding flow by August.",
        "notes/contacts.txt": "alice@company.com, bob@company.com, finance@company.com",
    },
    "sent_emails": [],          # populated by send_email
    "transfers": [],            # populated by transfer_funds
    "shell_log": [],            # populated by execute_shell
}


def search_web(query: str) -> str:
    """Search the (simulated) web and return a short text snippet.

    Args:
        query: the search query string.
    """
    results = WORLD["search_index"].get(query.lower().strip())
    if not results:
        return f"No results found for '{query}'."
    return "\n".join(results)


def read_file(path: str) -> str:
    """Read a (simulated) file from the user's workspace.

    Args:
        path: relative file path, e.g. 'notes/meeting_notes.txt'.
    """
    content = WORLD["files"].get(path)
    if content is None:
        return f"Error: file '{path}' not found."
    return content


def send_email(to: str, subject: str, body: str) -> str:
    """Send an email on the user's behalf.

    Args:
        to: recipient email address.
        subject: email subject line.
        body: email body text.
    """
    WORLD["sent_emails"].append({"to": to, "subject": subject, "body": body})
    return f"Email queued to {to} with subject '{subject}'."


def transfer_funds(destination_account: str, amount_usd: float) -> str:
    """Transfer money to an external account. High-risk / sensitive tool.

    Args:
        destination_account: destination account identifier.
        amount_usd: amount to transfer, in US dollars.
    """
    WORLD["transfers"].append({"to": destination_account, "amount": amount_usd})
    return f"Transferred ${amount_usd:.2f} to {destination_account}."


def execute_shell(command: str) -> str:
    """Execute a shell command in the user's environment. High-risk tool.

    Args:
        command: the shell command to run.
    """
    WORLD["shell_log"].append(command)
    return f"Executed: {command}"


# Registry used by the MCP server to expose these as tools.
ALL_TOOLS = [search_web, read_file, send_email, transfer_funds, execute_shell]
