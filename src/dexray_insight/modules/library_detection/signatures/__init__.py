#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Library Detection Signatures Package

Contains signature extraction and matching functionality for similarity-based detection.
Separated from main module for better maintainability and to support advanced
LibScan-style similarity analysis.
"""

from .class_signatures import ClassSignatureExtractor
from .signature_database import get_known_library_signatures
from .signature_matcher import SignatureMatcher

__all__ = ['ClassSignatureExtractor', 'get_known_library_signatures', 'SignatureMatcher']