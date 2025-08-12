Dexray Insight Documentation
============================

**Dexray Insight** is a comprehensive Python-based Android APK static analysis tool that performs security analysis using a modern object-oriented architecture. It's part of the Sandroid dynamic sandbox project and provides multiple analysis modules for examining Android applications.

.. image:: https://img.shields.io/badge/Python-3.8%2B-blue.svg
   :target: https://www.python.org/downloads/
   :alt: Python Version

.. image:: https://img.shields.io/badge/License-MIT-green.svg
   :target: https://opensource.org/licenses/MIT
   :alt: License

Features
--------

* **Comprehensive APK Analysis**: Deep static analysis of Android applications
* **Security Assessment**: OWASP Top 10 security checks with enhanced secret detection
* **Native Binary Analysis**: Radare2-powered analysis of .so files
* **Third-party Library Detection**: Identify and analyze embedded libraries
* **Signature Detection**: VirusTotal, Koodous, and Triage API integration
* **Parallel Execution**: Multi-threaded analysis for improved performance
* **Configurable Modules**: Enable/disable analysis components via YAML configuration
* **Docker Support**: Containerized analysis environment

Quick Start
-----------

**Installation**::

   # Development installation
   python3 -m pip install -e .

   # Standard installation
   python3 -m pip install dexray-insight

**Basic Usage**::

   # Basic APK analysis
   dexray-insight path/to/app.apk

   # Enable security assessment
   dexray-insight path/to/app.apk -s

   # Enable signature checking with API keys
   dexray-insight path/to/app.apk -sig

   # Deep behavioral analysis
   dexray-insight path/to/app.apk --deep

   # With custom configuration (the configuration file dexray.yaml will be used by default)
   dexray-insight path/to/app.apk -c mydexray.yaml

Documentation Contents
----------------------

.. toctree::
   :maxdepth: 2
   :caption: User Guide

   installation
   cli_usage
   configuration
   output_format

.. toctree::
   :maxdepth: 2
   :caption: Testing

   testing/overview
   testing/writing_tests
   testing/fixtures

.. toctree::
   :maxdepth: 2
   :caption: API Reference

   api/core
   api/modules
   api/results
   api/utilities

.. toctree::
   :maxdepth: 2
   :caption: Advanced Topics

   advanced/security_assessment
   version_analysis
   advanced/native_analysis
   advanced/custom_modules
   advanced/docker_usage

.. toctree::
   :maxdepth: 1
   :caption: Development

   contributing
   changelog

Indices and Tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`