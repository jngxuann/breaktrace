"""Daytona sandbox runner for BreakTrace.

All Daytona SDK logic lives here, separate from FastAPI routing.

Security note: the command executed inside the sandbox is HARDCODED below.
The frontend can never influence what runs in the sandbox — there is no
code path that accepts commands from users.
"""

import os

from dotenv import load_dotenv

from daytona import Daytona, DaytonaConfig

# Load credentials from backend/.env (DAYTONA_API_KEY, DAYTONA_API_URL, DAYTONA_TARGET).
load_dotenv()

# Hardcoded, harmless command for this milestone.
SANDBOX_TEST_COMMAND = "python -c \"print('BreakTrace sandbox working')\""

DEFAULT_API_URL = "https://app.daytona.io/api"


def get_daytona_client() -> Daytona:
    """Build the Daytona client from environment variables.

    Raises:
        RuntimeError: If DAYTONA_API_KEY is missing.
    """
    api_key = os.getenv("DAYTONA_API_KEY")
    if not api_key:
        raise RuntimeError(
            "DAYTONA_API_KEY is not set. Add it to backend/.env "
            "(see backend/.env.example)."
        )

    config = DaytonaConfig(
        api_key=api_key,
        api_url=os.getenv("DAYTONA_API_URL") or DEFAULT_API_URL,
        target=os.getenv("DAYTONA_TARGET"),
    )
    return Daytona(config)


def run_sandbox_test() -> dict:
    """Create a disposable sandbox, run the test command, clean up, return output.

    Returns:
        A dict like {"success": True, "output": "BreakTrace sandbox working"}.

    Raises:
        RuntimeError: If the sandbox cannot be created, the command fails,
            or execution fails.
    """
    client = get_daytona_client()
    sandbox = None
    try:
        sandbox = client.create()
        result = sandbox.process.exec(SANDBOX_TEST_COMMAND)
        output = (result.result or "").strip()

        if result.exit_code != 0:
            raise RuntimeError(
                f"Command failed with exit code {result.exit_code}: {output or '(no output)'}"
            )

        return {"success": True, "output": output}
    finally:
        if sandbox is not None:
            try:
                client.delete(sandbox)
            except Exception:
                # Cleanup is best-effort: a deletion failure must not mask
                # the sandbox's actual result or error.
                pass
