#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for the BaseExternalTool availability-probe helpers.

Covers the recently implemented helpers:
- _binary_runs_cleanly(command): True iff subprocess exits 0, False on exception.
- _python_module_importable(module_name): True iff importlib can locate the module.
"""

from types import SimpleNamespace

import pytest

from src.dexray_insight.core import base_classes
from src.dexray_insight.core.base_classes import BaseExternalTool


class _ConcreteExternalTool(BaseExternalTool):
    """Minimal concrete subclass so the abstract base can be instantiated."""

    def execute(self, apk_path, output_dir=None):
        return {"status": "success"}

    def is_available(self):
        return True


def _fake_completed(returncode: int):
    return SimpleNamespace(returncode=returncode, stdout="", stderr="")


@pytest.fixture
def tool():
    return _ConcreteExternalTool({})


class TestBinaryRunsCleanly:
    """Tests for BaseExternalTool._binary_runs_cleanly()."""

    @pytest.mark.unit
    def test_returns_true_on_zero_returncode(self, tool, monkeypatch):
        monkeypatch.setattr(base_classes.subprocess, "run", lambda *a, **k: _fake_completed(0))
        assert tool._binary_runs_cleanly(["some-binary", "--version"]) is True

    @pytest.mark.unit
    def test_returns_false_on_nonzero_returncode(self, tool, monkeypatch):
        monkeypatch.setattr(base_classes.subprocess, "run", lambda *a, **k: _fake_completed(3))
        assert tool._binary_runs_cleanly(["some-binary", "--version"]) is False

    @pytest.mark.unit
    def test_returns_false_when_subprocess_raises(self, tool, monkeypatch):
        def _boom(*a, **k):
            raise OSError("binary not found")

        monkeypatch.setattr(base_classes.subprocess, "run", _boom)
        assert tool._binary_runs_cleanly(["missing-binary", "--version"]) is False


class TestPythonModuleImportable:
    """Tests for BaseExternalTool._python_module_importable()."""

    @pytest.mark.unit
    def test_returns_true_for_stdlib_module(self, tool):
        assert tool._python_module_importable("json") is True

    @pytest.mark.unit
    def test_returns_false_for_nonexistent_module(self, tool):
        assert tool._python_module_importable("definitely_not_a_real_module_xyz") is False
