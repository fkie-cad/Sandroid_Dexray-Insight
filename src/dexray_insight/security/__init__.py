#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""OWASP Top 10 security assessment modules for Dexray Insight"""

# Import all security assessments to register them
from . import injection_assessment
from . import broken_access_control_assessment
from . import sensitive_data_assessment
from . import insecure_design_assessment
from . import security_misconfiguration_assessment
from . import vulnerable_components_assessment
from . import authentication_failures_assessment
from . import integrity_failures_assessment
from . import logging_monitoring_failures_assessment
from . import ssrf_assessment
from . import mobile_specific_assessment
from . import cve_assessment

__all__ = [
    'injection_assessment',
    'broken_access_control_assessment',
    'sensitive_data_assessment',
    'insecure_design_assessment',
    'security_misconfiguration_assessment',
    'vulnerable_components_assessment',
    'authentication_failures_assessment',
    'integrity_failures_assessment',
    'logging_monitoring_failures_assessment',
    'ssrf_assessment',
    'mobile_specific_assessment',
    'cve_assessment'
]