#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tracker Analysis Models Package

Data models and result structures for tracker analysis.
Extracted from monolithic tracker_analysis.py for better maintainability.
"""

from .tracker_models import DetectedTracker

__all__ = ['DetectedTracker']