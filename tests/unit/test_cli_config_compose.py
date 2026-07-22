#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Regression tests (R2): CLI flags must compose with a ``-c`` config file.

When a configuration file is supplied via ``-c/--config``, the CLI override
flags (``-s``, ``--cve``, ``--deep``, ``--debug``, ``--no-cache``) must still be
layered on top of the file so that explicit flags win. Previously the file was
returned as-is and all CLI flags were dropped.
"""

import argparse
import json

import pytest

from src.dexray_insight.asam import _load_or_create_configuration


def _write_config(tmp_path, security_enabled: bool):
    """Write a minimal JSON config toggling OWASP security assessment."""
    cfg = {"security": {"enable_owasp_assessment": security_enabled}}
    path = tmp_path / "config.json"
    path.write_text(json.dumps(cfg))
    return str(path)


def _args(**overrides):
    """Build a parsed-args namespace with only the given attributes set."""
    return argparse.Namespace(**overrides)


def test_cli_sec_flag_overrides_disabled_file(tmp_path):
    """(a) File disables security; CLI ``-s`` must re-enable it in the effective config."""
    config_path = _write_config(tmp_path, security_enabled=False)

    args = _args(config=config_path, sec=True, cve=False)
    config, err = _load_or_create_configuration(args)

    assert err == 0
    assert config is not None
    assert config.enable_security_assessment is True


def test_cve_flag_with_file_enabled_security_does_not_exit(tmp_path):
    """(b) File enables security; CLI ``--cve`` (without ``-s``) must NOT sys.exit."""
    config_path = _write_config(tmp_path, security_enabled=True)

    args = _args(config=config_path, sec=False, cve=True)

    try:
        config, err = _load_or_create_configuration(args)
    except SystemExit as exc:  # pragma: no cover - failure path
        pytest.fail(f"--cve with file-enabled security wrongly triggered sys.exit({exc.code})")

    assert err == 0
    assert config is not None
    assert config.enable_security_assessment is True
    # CVE scanning should have been enabled since security is on.
    assert config.get_security_config().get("cve_scanning", {}).get("enabled") is True


def test_cve_flag_without_any_security_still_exits(tmp_path):
    """Guard: ``--cve`` with security disabled everywhere must still exit(1)."""
    config_path = _write_config(tmp_path, security_enabled=False)

    args = _args(config=config_path, sec=False, cve=True)

    with pytest.raises(SystemExit):
        _load_or_create_configuration(args)
