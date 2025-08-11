#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Library Detection Module Package

Third-party library detection module using multi-stage analysis with specialized engines.
Refactored into submodules following Single Responsibility Principle.

Phase 6.5 TDD Refactoring: Split from monolithic library_detection.py into:
- patterns/: Library pattern definitions for heuristic detection  
- signatures/: Signature extraction and matching for similarity detection
- engines/: Specialized detection engines with timing and error management

Main Components:
- LibraryDetectionModule: Main analysis module
- LibraryDetectionResult: Result data structure
"""

from .library_detection_module import LibraryDetectionModule, LibraryDetectionResult
from .patterns import LIBRARY_PATTERNS
from .signatures import ClassSignatureExtractor, SignatureMatcher, get_known_library_signatures
from .engines import (
    HeuristicDetectionEngine, 
    SimilarityDetectionEngine,
    NativeLibraryDetectionEngine, 
    AndroidXDetectionEngine,
    LibraryDetectionCoordinator
)

__all__ = [
    'LibraryDetectionModule',
    'LibraryDetectionResult', 
    'LIBRARY_PATTERNS',
    'ClassSignatureExtractor',
    'SignatureMatcher', 
    'get_known_library_signatures',
    'HeuristicDetectionEngine',
    'SimilarityDetectionEngine',
    'NativeLibraryDetectionEngine',
    'AndroidXDetectionEngine', 
    'LibraryDetectionCoordinator'
]