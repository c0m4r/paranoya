#!venv/bin/python
"""Check for outdated packages and show how long ago each new version was released."""
from __future__ import annotations

import json
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone


def get_latest_release_date(package: str) -> str | None:
    """Fetch the release date of the latest version from PyPI."""
    url = f"https://pypi.org/pypi/{package}/json"
    try:
        with urllib.request.urlopen(url) as response:
            data = json.loads(response.read().decode("utf-8"))
            if data.get("urls"):
                return data["urls"][0]["upload_time_iso_8601"]
    except (urllib.error.HTTPError, urllib.error.URLError):
        pass
    return None


def parse_iso_date(iso_str: str) -> datetime:
    """Parse an ISO-8601 timestamp into a timezone-aware datetime."""
    # Handle formats like 2024-01-15T12:34:56 or 2024-01-15T12:34:56Z
    iso_str = iso_str.replace("Z", "+00:00")
    if "+" not in iso_str and iso_str.count("-") == 2:
        iso_str += "+00:00"
    return datetime.fromisoformat(iso_str)


def days_ago(iso_str: str) -> int:
    """Calculate how many days ago a release was published."""
    dt = parse_iso_date(iso_str)
    now = datetime.now(timezone.utc)
    return (now - dt).days


def check_outdated() -> list[dict]:
    """Run `pip list --outdated` and return structured results."""
    result = subprocess.run(
        [sys.executable, "-m", "pip", "list", "--outdated", "--format=json"],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)


def main():
    outdated = check_outdated()

    if not outdated:
        print("All packages are up to date.")
        return

    # Header
    print(f"{'Package':<25} {'Installed':<15} {'Latest':<15} {'Released':<12} {'Days Ago'}")
    print("-" * 82)

    for pkg in outdated:
        name = pkg["name"]
        installed = pkg["version"]
        latest = pkg["latest_version"]

        release_date = get_latest_release_date(name)
        if release_date:
            days = days_ago(release_date)
            date_str = parse_iso_date(release_date).strftime("%Y-%m-%d")
            days_str = f"{days}d" if days > 0 else "today"
        else:
            date_str = "unknown"
            days_str = "— "

        print(f"{name:<25} {installed:<15} {latest:<15} {date_str:<12} {days_str}")


if __name__ == "__main__":
    main()
