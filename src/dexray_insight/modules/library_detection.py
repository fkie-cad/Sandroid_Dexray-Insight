#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Library Detection Module - Backward Compatibility Layer

This file maintains backward compatibility for existing imports while
delegating to the new submodule structure.

Phase 6.5 TDD Refactoring: Maintains API compatibility while using
refactored submodule architecture internally.
"""

# Import everything from the new submodule structure
from .library_detection.library_detection_module import LibraryDetectionModule, LibraryDetectionResult
from .library_detection.patterns import LIBRARY_PATTERNS

# Re-export the main classes and functions to maintain compatibility
__all__ = [
    'LibraryDetectionModule',
    'LibraryDetectionResult',
    'LIBRARY_PATTERNS'
]