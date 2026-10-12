"""Verify modules are available through the installed package."""

from importlib import import_module

import pytest


@pytest.mark.parametrize(
    "module", ["", ".client", ".server", ".protocol", ".dns", ".reverse"]
)
def test_package_import(module: str) -> None:
    imported = import_module(f"socks5_kit{module}")
    assert imported.__name__ == f"socks5_kit{module}"
