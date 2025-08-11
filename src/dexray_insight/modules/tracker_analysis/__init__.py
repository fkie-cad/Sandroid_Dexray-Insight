#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tracker Analysis Module Package

Advertising and analytics tracker detection module using multi-stage analysis with specialized detectors.
Refactored into submodules following Single Responsibility Principle.

Phase 7 TDD Refactoring: Split from monolithic tracker_analysis.py into:
- databases/: Tracker pattern databases and Exodus Privacy API integration
- detectors/: Specialized detection engines for pattern matching, version extraction, and deduplication
- models/: Data models and result structures

Main Components:
- TrackerAnalysisModule: Main analysis module
- TrackerAnalysisResult: Result data structure
- DetectedTracker: Individual tracker representation
"""

from .tracker_analysis_module import TrackerAnalysisModule, TrackerAnalysisResult
from .models import DetectedTracker
from .databases import TrackerDatabase, ExodusAPIClient
from .detectors import (
    PatternDetector,
    VersionExtractor, 
    TrackerDeduplicator
)

__all__ = [
    'TrackerAnalysisModule',
    'TrackerAnalysisResult',
    'DetectedTracker',
    'TrackerDatabase',
    'ExodusAPIClient',
    'PatternDetector',
    'VersionExtractor',
    'TrackerDeduplicator'
]