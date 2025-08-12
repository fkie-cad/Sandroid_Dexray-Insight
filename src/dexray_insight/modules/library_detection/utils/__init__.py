#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Library Detection Utilities Package

Utilities for version analysis, library matching, and other detection support functionality.
"""

from .version_analyzer import VersionAnalyzer, VersionAnalysisResult, get_version_analyzer

__all__ = [
    'VersionAnalyzer',
    'VersionAnalysisResult', 
    'get_version_analyzer'
]