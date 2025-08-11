#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tracker Analysis Detectors Package

Contains specialized detection engines for different tracker detection methods.
Each detector follows Single Responsibility Principle and handles timing,
error management, and result processing for its detection method.

Phase 7 TDD Refactoring: Extracted from monolithic tracker_analysis.py
"""

from .pattern_detector import PatternDetector
from .version_extractor import VersionExtractor
from .tracker_deduplicator import TrackerDeduplicator

__all__ = [
    'PatternDetector',
    'VersionExtractor',
    'TrackerDeduplicator'
]