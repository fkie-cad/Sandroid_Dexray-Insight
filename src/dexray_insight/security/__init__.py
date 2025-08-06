#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""OWASP Top 10 security assessment modules for Dexray Insight"""

# Import all security assessments to register them
from . import injection_assessment
from . import broken_access_control_assessment
from . import sensitive_data_assessment

__all__ = [
    'injection_assessment',
    'broken_access_control_assessment',
    'sensitive_data_assessment'
]