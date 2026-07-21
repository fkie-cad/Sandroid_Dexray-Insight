#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for the APKIDTool availability probing and graceful-skip behaviour.

Covers the recently implemented fixes:
- is_available() gates on shutil.which() and a functional --version probe.
- _is_environment_failure() classifies YARA/rule stderr as an environment issue.
- execute() returns a "skipped" status (no error-level log) on an environment
  failure, and a "failure" status on a genuine analysis error.
"""

import logging
from types import SimpleNamespace

import pytest

from src.dexray_insight.core import base_classes
from src.dexray_insight.tools import apkid_tool
from src.dexray_insight.tools.apkid_tool import APKIDTool


def _fake_completed(returncode: int, stdout: str = "", stderr: str = ""):
    """Build a stand-in for subprocess.CompletedProcess."""
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


class TestAPKIDToolIsAvailable:
    """Tests for APKIDTool.is_available()."""

    @pytest.mark.unit
    def test_is_available_false_when_which_returns_none(self, monkeypatch):
        """If the apkid binary is not on PATH, availability is False."""
        monkeypatch.setattr(apkid_tool.shutil, "which", lambda name: None)

        tool = APKIDTool({})
        assert tool.is_available() is False

    @pytest.mark.unit
    def test_is_available_false_when_version_probe_fails(self, monkeypatch):
        """Binary present but --version probe exits non-zero -> not available."""
        monkeypatch.setattr(apkid_tool.shutil, "which", lambda name: "/usr/bin/apkid")
        # _binary_runs_cleanly lives on the base class and calls base_classes.subprocess.
        monkeypatch.setattr(
            base_classes.subprocess, "run", lambda *a, **k: _fake_completed(returncode=1, stderr="boom")
        )

        tool = APKIDTool({})
        assert tool.is_available() is False

    @pytest.mark.unit
    def test_is_available_true_when_which_and_probe_succeed(self, monkeypatch):
        """Binary on PATH and a clean --version probe -> available."""
        monkeypatch.setattr(apkid_tool.shutil, "which", lambda name: "/usr/bin/apkid")
        monkeypatch.setattr(
            base_classes.subprocess, "run", lambda *a, **k: _fake_completed(returncode=0, stdout="apkid 2.1.5")
        )

        tool = APKIDTool({})
        assert tool.is_available() is True


class TestAPKIDToolEnvironmentFailureClassifier:
    """Tests for APKIDTool._is_environment_failure()."""

    @pytest.mark.unit
    def test_yara_stderr_is_environment_failure(self):
        stderr = "yara.SyntaxError: could not compile rules (libyara version mismatch)"
        assert APKIDTool._is_environment_failure(stderr) is True

    @pytest.mark.unit
    def test_unrelated_stderr_is_not_environment_failure(self):
        stderr = "Traceback: FileNotFoundError: no such file /path/to/app.apk"
        assert APKIDTool._is_environment_failure(stderr) is False

    @pytest.mark.unit
    def test_empty_stderr_is_not_environment_failure(self):
        assert APKIDTool._is_environment_failure("") is False
        assert APKIDTool._is_environment_failure(None) is False


class TestAPKIDToolExecute:
    """Tests for APKIDTool.execute() status + logging behaviour."""

    @pytest.mark.unit
    def test_execute_skips_on_environment_failure_without_error_log(self, monkeypatch, caplog):
        """rc=1 with YARA stderr -> skipped status, results None, no error log."""
        yara_stderr = "yara.SyntaxError: unable to compile rules due to libyara incompatible version"
        monkeypatch.setattr(
            apkid_tool.subprocess, "run", lambda *a, **k: _fake_completed(returncode=1, stderr=yara_stderr)
        )

        tool = APKIDTool({})
        with caplog.at_level(logging.INFO, logger=apkid_tool.__name__):
            result = tool.execute("/path/to/app.apk")

        assert result["status"] == "skipped"
        assert result["results"] is None
        assert "reason" in result

        # Environment issues must NOT be logged at error level.
        error_records = [r for r in caplog.records if r.levelno >= logging.ERROR]
        assert error_records == [], f"Unexpected error-level logs: {[r.getMessage() for r in error_records]}"

    @pytest.mark.unit
    def test_execute_reports_failure_on_genuine_error(self, monkeypatch):
        """rc=1 with unrelated stderr -> genuine failure status."""
        monkeypatch.setattr(
            apkid_tool.subprocess,
            "run",
            lambda *a, **k: _fake_completed(returncode=1, stderr="FileNotFoundError: app.apk missing"),
        )

        tool = APKIDTool({})
        result = tool.execute("/path/to/app.apk")

        assert result["status"] == "failure"
        assert result["results"] is None
        assert "error" in result
