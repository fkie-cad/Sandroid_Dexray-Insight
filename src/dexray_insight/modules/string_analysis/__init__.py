#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
String Analysis Module Package

String extraction and analysis module using specialized filters and extractors.
Refactored into submodules following Single Responsibility Principle.

Phase 8 TDD Refactoring: Split from monolithic string_analysis.py into:
- extractors/: String extraction engines for different APK components
- filters/: Specialized filters for different string types (email, IP, URL, domain, android properties)
- validators/: Common validation utilities for string pattern validation

Main Components:
- StringAnalysisModule: Main analysis module
- StringAnalysisResult: Result data structure
"""

from .string_analysis_module import StringAnalysisModule, StringAnalysisResult
from .extractors import StringExtractor
from .filters import (
    EmailFilter,
    NetworkFilter, 
    DomainFilter,
    AndroidPropertiesFilter
)
from .validators import StringValidators

__all__ = [
    'StringAnalysisModule',
    'StringAnalysisResult',
    'StringExtractor',
    'EmailFilter',
    'NetworkFilter',
    'DomainFilter', 
    'AndroidPropertiesFilter',
    'StringValidators'
]