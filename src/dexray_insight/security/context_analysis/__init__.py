#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Context-Aware Security Analysis Module

This module provides context-aware security analysis capabilities that enhance
traditional pattern-based secret detection with intelligent context analysis,
false positive reduction, and risk correlation.

Key Components:
- ContextualSecretAnalyzer: Main orchestrator for context-aware analysis
- CodeContextAnalyzer: Analyzes code context around detected secrets
- FalsePositiveFilter: Enhanced filtering with context-aware rules
- RiskCorrelationEngine: Correlates findings across analysis modules
- UsagePatternAnalyzer: Determines how secrets are used in practice

Design Principles:
- Incremental enhancement of existing detection capabilities
- SOLID principles with single-responsibility components
- Strategy pattern integration with existing security framework
- Backwards compatibility with current analysis pipeline
"""

from .contextual_secret_analyzer import ContextualSecretAnalyzer
from .code_context_analyzer import CodeContextAnalyzer
from .false_positive_filter import FalsePositiveFilter
from .risk_correlation_engine import RiskCorrelationEngine
from .usage_pattern_analyzer import UsagePatternAnalyzer

__all__ = [
    'ContextualSecretAnalyzer',
    'CodeContextAnalyzer', 
    'FalsePositiveFilter',
    'RiskCorrelationEngine',
    'UsagePatternAnalyzer'
]