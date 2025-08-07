#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Analysis modules for Dexray Insight using the new OOP framework"""

# Import all refactored modules to register them
from . import apk_overview_analysis
from . import signature_analysis
from . import permission_analysis
from . import string_analysis
from . import manifest_analysis
from . import api_invocation_analysis
from . import tracker_analysis
from . import behaviour_analysis
from . import dotnet_analysis
from . import library_detection
from . import native  # Native binary analysis modules

__all__ = [
    'apk_overview_analysis',
    'signature_analysis', 
    'permission_analysis',
    'string_analysis',
    'manifest_analysis',
    'api_invocation_analysis',
    'tracker_analysis',
    'behaviour_analysis',
    'dotnet_analysis',
    'library_detection',
    'native'
]