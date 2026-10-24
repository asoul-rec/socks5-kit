"""Allocate the next UTC date-based package version from existing release tags."""

import re
import subprocess
from collections.abc import Iterable
from datetime import UTC, date, datetime

_TAG = re.compile(r"v?(\d{4})\.(\d{1,2})\.(\d{1,2})\.(\d+)")


def next_version(tags: Iterable[str], day: date) -> str:
    revision = 0
    for tag in tags:
        match = _TAG.fullmatch(tag)
        if match is None:
            continue
        year, month, day_of_month, sequence = map(int, match.groups())
        if (year, month, day_of_month) == (day.year, day.month, day.day):
            revision = max(revision, sequence)
    return f"{day.year}.{day.month}.{day.day}.{revision + 1}"


def main() -> None:
    tags = subprocess.check_output(["git", "tag", "--list"], text=True).splitlines()
    print(next_version(tags, datetime.now(UTC).date()))


if __name__ == "__main__":
    main()
