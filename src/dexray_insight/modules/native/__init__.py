#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Native Analysis Modules

This package contains modules for analyzing native binaries (.so files) 
found in Android APKs using radare2/r2pipe.

Modules:
- native_loader: Main orchestrator for native binary analysis
- string_extraction: Extract strings from native binaries
- base_native_module: Base class for native analysis modules
"""

# Import modules to register them (needed for module discovery)
from . import native_loader  # noqa: F401