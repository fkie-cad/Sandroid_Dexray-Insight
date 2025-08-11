#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Behaviour Analysis Module - Compatibility Layer

This module provides backward compatibility by importing and delegating
to the refactored BehaviourAnalysisModule.
"""

from .behaviour_analysis.behaviour_analysis_module import BehaviourAnalysisModule

# Re-export for backward compatibility
__all__ = ['BehaviourAnalysisModule']