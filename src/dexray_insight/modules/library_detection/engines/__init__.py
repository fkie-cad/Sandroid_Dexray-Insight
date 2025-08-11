#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Library Detection Engines Package

Contains specialized detection engines for different library detection methods.
Each engine follows Single Responsibility Principle and handles timing,
error management, and result processing for its detection method.

Phase 6.5 TDD Refactoring: Extracted from monolithic library_detection.py
"""

from .heuristic_engine import HeuristicDetectionEngine
from .similarity_engine import SimilarityDetectionEngine  
from .native_engine import NativeLibraryDetectionEngine
from .androidx_engine import AndroidXDetectionEngine
from .apktool_detection_engine import ApktoolDetectionEngine
from .coordinator import LibraryDetectionCoordinator

__all__ = [
    'HeuristicDetectionEngine',
    'SimilarityDetectionEngine', 
    'NativeLibraryDetectionEngine',
    'AndroidXDetectionEngine',
    'ApktoolDetectionEngine',
    'LibraryDetectionCoordinator'
]