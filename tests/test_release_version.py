"""Date release versions reserve existing tags and increment numerically."""

import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest

from tools.release_version import next_version


@pytest.mark.parametrize(
    ("tags", "day", "expected"),
    [
        ([], date(2026, 10, 24), "2026.10.24.1"),
        (["v2026.10.24.1"], date(2026, 10, 24), "2026.10.24.2"),
        (
            ["v2026.10.24.9", "v2026.10.24.2", "v2026.10.24.10"],
            date(2026, 10, 24),
            "2026.10.24.11",
        ),
        (
            ["v2026.10.24.99", "v2026.10.26.7"],
            date(2026, 10, 25),
            "2026.10.25.1",
        ),
        (["v2026.12.31.12"], date(2027, 1, 1), "2027.1.1.1"),
        (
            ["v2026.01.02.3", "2026.1.2.8"],
            date(2026, 1, 2),
            "2026.1.2.9",
        ),
        (
            ["v0.1.0", "v2026.10.24", "v2026.10.24.9rc1", "v2026.10.24.1-extra"],
            date(2026, 10, 24),
            "2026.10.24.1",
        ),
    ],
)
def test_next_version(tags, day, expected):
    assert next_version(iter(tags), day) == expected


def test_cli_reads_all_tags_without_modifying_repository(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    script = Path(__file__).resolve().parents[1] / "tools" / "release_version.py"
    result = subprocess.run(
        [sys.executable, str(script)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )
    year, month, day, revision = map(int, result.stdout.strip().split("."))
    date(year, month, day)
    assert revision == 1
    assert (
        subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=tmp_path, text=True
        )
        == ""
    )
