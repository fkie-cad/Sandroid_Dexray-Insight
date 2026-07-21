#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for KavanozTool.is_available().

Covers the recently implemented fix: availability is now derived from whether
the ``kavanoz`` Python module can be located for import, via
BaseExternalTool._python_module_importable (importlib.util.find_spec).
"""

from types import SimpleNamespace

import pytest

from src.dexray_insight.core import base_classes
from src.dexray_insight.tools.kavanoz_tool import KavanozTool


class TestKavanozToolIsAvailable:
    """Tests for KavanozTool.is_available()."""

    @pytest.mark.unit
    def test_is_available_false_when_module_not_found(self, monkeypatch):
        """find_spec returning None means the module is not importable."""
        monkeypatch.setattr(base_classes.importlib.util, "find_spec", lambda name: None)

        tool = KavanozTool({})
        assert tool.is_available() is False

    @pytest.mark.unit
    def test_is_available_true_when_module_present(self, monkeypatch):
        """A non-None spec means the module can be imported -> available."""
        fake_spec = SimpleNamespace(name="kavanoz")
        monkeypatch.setattr(base_classes.importlib.util, "find_spec", lambda name: fake_spec)

        tool = KavanozTool({})
        assert tool.is_available() is True
