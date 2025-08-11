#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Behaviour Analysis Module

This package provides comprehensive behavioral analysis for Android applications,
supporting both fast mode (APK-only) and deep mode (full DEX analysis).

Components:
- analyzers: Privacy-sensitive behavior detection modules
- engines: Pattern search and analysis coordination
- modes: Mode-specific analysis logic (fast/deep)  
- models: Data structures and behavior models
"""

from .behaviour_analysis_module import BehaviourAnalysisModule

__all__ = ['BehaviourAnalysisModule']