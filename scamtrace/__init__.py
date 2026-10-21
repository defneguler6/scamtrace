"""ScamTrace: links payees to live advert-originated scam campaigns."""

import os
from pathlib import Path

__version__ = "0.2.0"


def _load_dotenv(path: Path = Path(".env")) -> None:
    """Read KEY=value lines from ./.env into the environment (if not already set).

    Keeps secrets such as ANTHROPIC_API_KEY out of the code and shell history.
    """
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_dotenv()
