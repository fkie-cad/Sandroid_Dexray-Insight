#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-
#
# # Copyright (C) {{ year }} Dexray Insight Contributors
# #
# # This file is part of Dexray Insight - Android APK Security Analysis Tool
# #
# # Licensed under the Apache License, Version 2.0 (the "License");
# # you may not use this file except in compliance with the License.
# # You may obtain a copy of the License at
# #
# #     http://www.apache.org/licenses/LICENSE-2.0
# #
# # Unless required by applicable law or agreed to in writing, software
# # distributed under the License is distributed on an "AS IS" BASIS,
# # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# # See the License for the specific language governing permissions and
# # limitations under the License.

"""Android Security Analysis Module (ASAM) - Main CLI interface for Dexray Insight."""

# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-
#
# # Copyright (C) {{ year }} Dexray Insight Contributors
# #
# # This file is part of Dexray Insight - Android APK Security Analysis Tool
# #
# # Licensed under the Apache License, Version 2.0 (the "License");
# # you may not use this file except in compliance with the License.
# # You may obtain a copy of the License at
# #
# #     http://www.apache.org/licenses/LICENSE-2.0
# #
# # Unless required by applicable law or agreed to in writing, software
# # distributed under the License is distributed on an "AS IS" BASIS,
# # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# # See the License for the specific language governing permissions and
# # limitations under the License.

import argparse
import contextlib
import logging
import sys
import time
from datetime import datetime
from pathlib import Path

# Import modules to register them (imports are needed for registration)
from . import modules  # This will register all analysis modules  # noqa: F401
from . import security  # This will register all security assessments  # noqa: F401
from . import tools  # This will register all external tools  # noqa: F401
from .about import __author__
from .about import __version__

# Import the new OOP framework
from .core import AnalysisEngine
from .core import Configuration
from .Utils import androguardObjClass
from .Utils.file_utils import dump_json
from .Utils.file_utils import dump_text
from .Utils.file_utils import split_path_file_extension
from .Utils.log import set_logger


def print_logo():
    """Print the Dexray Insight ASCII logo."""
    print(
        """        Dexray Insight
⠀⠀⠀⠀⢀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠙⢷⣤⣤⣴⣶⣶⣦⣤⣤⡾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠾⠛⢉⣉⣉⣉⡉⠛⠷⣦⣄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠋⣠⣴⣿⣿⣿⣿⣿⡿⣿⣶⣌⠹⣷⡀⠀⠀
⠀⠀⠀⠀⣼⣿⣿⣉⣹⣿⣿⣿⣿⣏⣉⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠁⣴⣿⣿⣿⣿⣿⣿⣿⣿⣆⠉⠻⣧⠘⣷⠀⠀
⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡇⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠈⠀⢹⡇⠀
⣠⣄⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⣠⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⢸⣿⠛⣿⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⢸⡇⠀
⣿⣿⡇⢸⣿⣿⣿Sandroid⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣷⠀⢿⡆⠈⠛⠻⠟⠛⠉⠀⠀⠀⠀⠀⠀⣾⠃⠀
⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣧⡀⠻⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⠃⠀⠀
⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢼⠿⣦⣄⠀⠀⠀⠀⠀⠀⠀⣀⣴⠟⠁⠀⠀⠀
⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣦⠀⠀⠈⠉⠛⠓⠲⠶⠖⠚⠋⠉⠀⠀⠀⠀⠀⠀
⠻⠟⠁⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠈⠻⠟⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠉⠉⣿⣿⣿⡏⠉⠉⢹⣿⣿⣿⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⣿⡇⠀⠀⢸⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⣿⡇⠀⠀⢸⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⢀⣄⠈⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⠉⠉⠀⠀⠀⠀⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀"""
    )
    print(f"        version: {__version__}\n")


def create_configuration_from_args(args) -> Configuration:
    """Create configuration object from command line arguments.

    Refactored to use single-responsibility functions following SOLID principles.
    Maintains exact same behavior as original while improving maintainability.

    Args:
        args: Command line arguments namespace

    Returns:
        Configuration object with applied command line overrides
    """
    # Create base configuration
    config = Configuration()

    # Build configuration updates using refactored single-purpose functions
    config_updates = _build_configuration_updates(args)

    # Apply configuration updates if any were generated
    if config_updates:
        config._merge_config(config_updates)

    return config


def _process_signature_flags(args, config_updates: dict) -> None:
    """Process signature detection related command line flags.

    Single Responsibility: Handle only signature detection flag processing.

    Args:
        args: Command line arguments namespace
        config_updates: Dictionary to update with configuration changes
    """
    if hasattr(args, "signaturecheck") and args.signaturecheck:
        config_updates.setdefault("modules", {})["signature_detection"] = {"enabled": True}


def _process_security_flags(args, config_updates: dict) -> None:
    """Process security analysis related command line flags.

    Single Responsibility: Handle only security analysis flag processing.

    Args:
        args: Command line arguments namespace
        config_updates: Dictionary to update with configuration changes
    """
    if hasattr(args, "sec") and args.sec:
        config_updates.setdefault("security", {})["enable_owasp_assessment"] = True

    # Markdown security report is a pure output preference; enable it independently.
    if hasattr(args, "security_report_md") and args.security_report_md:
        output_updates = config_updates.setdefault("output", {})
        security_report = output_updates.setdefault("security_report", {})
        security_report.setdefault("markdown", {})["enabled"] = True


def _process_cve_flags(args, config_updates: dict, existing_config=None) -> None:
    """Process CVE vulnerability scanning related command line flags.

    Single Responsibility: Handle only CVE scanning flag processing.
    CVE scanning requires security analysis to be enabled.

    Args:
        args: Command line arguments namespace
        config_updates: Dictionary to update with configuration changes
        existing_config: Optional already-loaded Configuration (e.g. from a
            ``-c`` config file). When security is enabled there, ``--cve`` is
            valid even without the ``-s`` CLI flag.
    """
    if hasattr(args, "cve") and args.cve:
        # Security may be enabled via the CLI (-s), via updates already staged in
        # this batch, or via a loaded config file. Any of these makes --cve valid.
        config_file_sec_enabled = existing_config is not None and existing_config.enable_security_assessment
        sec_enabled = (
            (hasattr(args, "sec") and args.sec)
            or config_updates.get("security", {}).get("enable_owasp_assessment", False)
            or config_file_sec_enabled
        )

        if sec_enabled:
            # Enable CVE scanning. OSV is the key-less default source; NVD/GitHub
            # stay off unless the config file turns them on (NVD needs an API key
            # and rate-limit-stalls without one). Java/Android libraries are scanned
            # too — native-only scanning was the historical bug that found nothing on
            # an obviously-outdated Java SDK stack.
            config_updates.setdefault("security", {})["cve_scanning"] = {
                "enabled": True,
                "sources": {"osv": {"enabled": True}, "nvd": {"enabled": False}, "github": {"enabled": False}},
                "max_workers": 3,
                "timeout_seconds": 30,
                "min_confidence": 0.7,
                "cache_duration_hours": 24,
                "max_libraries_per_source": 50,
                # Scan Java/Android libraries in addition to native libraries.
                "scan_native_only": False,
                "include_java_libraries": True,
                "native_library_patterns": [
                    "*.so",
                    "*ffmpeg*",
                    "*openssl*",
                    "*curl*",
                    "*sqlite*",
                    "*crypto*",
                    "*ssl*",
                    "*zlib*",
                    "*png*",
                    "*jpeg*",
                    "*webp*",
                ],
            }
        else:
            # Print warning and exit if CVE flag is used without security flag
            print("Error: --cve flag requires --sec flag to be enabled")
            print("CVE vulnerability scanning is only available during security assessment")
            print("Usage: dexray-insight <apk> --sec --cve")
            import sys

            sys.exit(1)


def _process_logging_flags(args, config_updates: dict) -> None:
    """Process logging related command line flags.

    Single Responsibility: Handle only logging configuration flag processing.

    Args:
        args: Command line arguments namespace
        config_updates: Dictionary to update with configuration changes
    """
    if hasattr(args, "debug") and args.debug:
        config_updates.setdefault("logging", {})["level"] = args.debug.upper()
    elif hasattr(args, "verbose") and args.verbose:
        config_updates.setdefault("logging", {})["level"] = "DEBUG"


def _process_analysis_flags(args, config_updates: dict) -> None:
    """Process analysis module related command line flags.

    Single Responsibility: Handle only analysis module flag processing.

    Args:
        args: Command line arguments namespace
        config_updates: Dictionary to update with configuration changes
    """
    # APK diffing
    if hasattr(args, "diffing_apk") and args.diffing_apk:
        config_updates.setdefault("modules", {})["apk_diffing"] = {"enabled": True}

    # Tracker analysis
    if hasattr(args, "tracker") and args.tracker:
        config_updates.setdefault("modules", {})["tracker_analysis"] = {"enabled": True}
    elif hasattr(args, "no_tracker") and args.no_tracker:
        config_updates.setdefault("modules", {})["tracker_analysis"] = {"enabled": False}

    # API invocation analysis
    if hasattr(args, "api_invocation") and args.api_invocation:
        config_updates.setdefault("modules", {})["api_invocation"] = {"enabled": True}

    # Deep behavior analysis
    if hasattr(args, "deep") and args.deep:
        config_updates.setdefault("modules", {})["behaviour_analysis"] = {"enabled": True, "deep_mode": True}
        # Deep mode also needs per-method string attribution so the deep PII-flow
        # detectors can tie a PII source string to the code location that uses it.
        # Enable the opt-in tracker-analysis pass that populates string_locations
        # with "class->method" attributions (default is off for cost reasons).
        tracker = config_updates.setdefault("modules", {}).setdefault("tracker_analysis", {})
        tracker["deep_string_location_analysis"] = True

    # Analysis result cache
    if hasattr(args, "no_cache") and args.no_cache:
        config_updates.setdefault("caching", {})["enabled"] = False


def _build_configuration_updates(args, existing_config=None) -> dict:
    """Build configuration updates from command line arguments.

    Single Responsibility: Coordinate all flag processing to build complete config updates.
    Following Open/Closed Principle: Easy to extend with new flag processors.

    Args:
        args: Command line arguments namespace
        existing_config: Optional already-loaded Configuration (e.g. from a
            ``-c`` config file) used so CLI flags can compose with file settings.

    Returns:
        Dictionary containing all configuration updates
    """
    config_updates = {}

    # Process different categories of flags using single-responsibility functions
    _process_signature_flags(args, config_updates)
    _process_security_flags(args, config_updates)
    _process_cve_flags(args, config_updates, existing_config)  # CVE processing after security flags
    _process_logging_flags(args, config_updates)
    _process_analysis_flags(args, config_updates)

    return config_updates


def _print_analysis_results_to_terminal(results, verbose: bool, config=None):
    """Print analysis results to the terminal using the appropriate format.

    Args:
        results: The analysis results object (or dict).
        verbose: When True, show full JSON output; otherwise the analyst summary.
        config: Optional Configuration, threaded into the analyst summary so the
            ranked TOP-RISKS / tier thresholds and ``top_n`` come from config.
    """
    # Use analyst-friendly summary by default, full JSON if verbose is enabled
    if verbose:
        # Verbose mode: show full JSON output
        if hasattr(results, "print_results"):
            results.print_results()
        else:
            print(results.to_json() if hasattr(results, "to_json") else str(results))
    else:
        # Default mode: show analyst-friendly summary (ranked TOP RISKS + tiers)
        if hasattr(results, "print_analyst_summary"):
            results.print_analyst_summary(verbose=verbose, config=config)
        elif hasattr(results, "print_results"):
            results.print_results()
        else:
            print(results.to_json() if hasattr(results, "to_json") else str(results))


def start_apk_static_analysis_new(
    apk_file_path: str, config: Configuration, print_results_to_terminal: bool = False, verbose: bool = False
):
    """Perform APK static analysis with new engine architecture.

    Args:
        apk_file_path: Path to the APK file
        config: Configuration object
        print_results_to_terminal: Whether to print results to terminal
        verbose: Whether to use verbose output (full JSON) or analyst summary

    Returns:
        Tuple of (results, result_file_name, security_result_file_name)
    """
    try:
        # Create analysis engine first (needed for the full-hit cache gate)
        engine = AnalysisEngine(config)

        # Generate timestamp for consistent naming across temporal directory and output files
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

        base_dir, name, file_ext = split_path_file_extension(apk_file_path)

        # Full-hit cache gate: satisfy an identical re-run entirely from cache
        # BEFORE building the (expensive) Androguard object. External tools are
        # re-run live inside try_full_hit so their results stay fresh.
        cached_payload = None
        try:
            cached_payload = engine.try_full_hit(apk_file_path)
        except Exception as e:
            logging.debug(f"Full-hit cache check failed, running full analysis: {e}")

        if cached_payload is not None:
            print("[*] Full-hit cache: reusing prior analysis (use --no-cache to force re-analysis)")
            main_dict = cached_payload.get("main", {})
            security_dict = cached_payload.get("security")

            result_file_name = dump_results_as_json_file(main_dict, name, timestamp)
            security_result_file_name = ""
            if security_dict:
                security_result_file_name = dump_security_results_as_json_file(security_dict, name, timestamp)

                # Re-emit the optional Markdown security report so a cached re-run
                # produces the same artifacts as a fresh run. Reconstruct a minimal
                # results object carrying the cached security dict for the reporter.
                from .results.FullAnalysisResults import FullAnalysisResults

                recon_for_md = FullAnalysisResults()
                recon_for_md.security_assessment = security_dict
                with contextlib.suppress(Exception):
                    recon_for_md.apk_overview.update_from_dict(main_dict.get("apk_overview", {}) or {})
                _maybe_dump_security_markdown(recon_for_md, config, name, timestamp)

            if print_results_to_terminal:
                _print_cached_summary(main_dict, security_dict, verbose=verbose, config=config)

            return cached_payload, result_file_name, security_result_file_name

        # Create androguard object first
        print("[*] Initializing Androguard analysis...")
        androguard_obj = None
        try:
            androguard_obj = androguardObjClass.AndroguardObj(apk_file_path)
        except Exception as e:
            print(f"\033[93m[W] Androguard initialization failed: {str(e)}\033[0m")
            print("\033[93m[W] Analysis will continue with limited functionality\033[0m")
            logging.warning(f"Androguard initialization failed: {str(e)}")

        print("[*] Starting comprehensive APK analysis...")

        # Run analysis with androguard object (may be None if initialization failed)
        results = engine.analyze_apk(apk_file_path, androguard_obj=androguard_obj, timestamp=timestamp)

        if print_results_to_terminal:
            _print_analysis_results_to_terminal(results, verbose, config)

        # Save results to file
        result_file_name = dump_results_as_json_file(results, name, timestamp)

        security_result_file_name = ""
        # Save separate security results file if security assessment was performed
        if hasattr(results, "security_assessment") and results.security_assessment:
            security_result_file_name = dump_security_results_as_json_file(results, name, timestamp)

            # Optional human-readable Markdown security report (config-gated).
            _maybe_dump_security_markdown(results, config, name, timestamp)

        return results, result_file_name, security_result_file_name

    except Exception as e:
        import traceback

        error_details = traceback.format_exc()

        print(f"\n\033[91m[-] Analysis failed: {str(e)}\033[0m")
        print("\033[93m[W] For detailed error information, run with -d DEBUG\033[0m")

        # Log detailed error information
        logging.error(f"Analysis failed: {str(e)}")
        logging.debug(f"Detailed error traceback:\n{error_details}")

        return None, "", ""


def dump_results_as_json_file(results, filename: str, timestamp: str = None) -> str:
    """Save analysis results to JSON file."""
    if timestamp is None:
        current_time = datetime.now()
        timestamp = current_time.strftime("%Y-%m-%d_%H-%M-%S")

    # Ensure filename is safe
    base_filename = filename.replace(" ", "_")
    safe_filename = f"dexray_{base_filename}_{timestamp}.json"

    # Convert results to dict. A plain dict (e.g. a full-hit cache re-emit) is
    # written as-is; a result object is serialized via to_dict.
    if isinstance(results, dict):
        results_dict = results
    elif hasattr(results, "to_dict"):
        results_dict = results.to_dict(include_security=False)
    else:
        results_dict = {"results": str(results)}

    dump_json(safe_filename, results_dict)
    return safe_filename


def dump_security_results_as_json_file(results, filename: str, timestamp: str = None) -> str:
    """Save security assessment results to separate JSON file."""
    if timestamp is None:
        current_time = datetime.now()
        timestamp = current_time.strftime("%Y-%m-%d_%H-%M-%S")

    # Ensure filename is safe
    base_filename = filename.replace(" ", "_")
    safe_filename = f"dexray_{base_filename}_security_{timestamp}.json"

    # Get security results dict from FullAnalysisResults object
    if hasattr(results, "get_security_results_dict"):
        security_dict = results.get_security_results_dict()
    elif isinstance(results, dict):
        security_dict = results
    elif hasattr(results, "to_dict"):
        security_dict = results.to_dict()
    else:
        security_dict = {"security_results": str(results)}

    # Only save if there are actual security results
    if security_dict:
        dump_json(safe_filename, security_dict)
        return safe_filename
    return ""


def dump_security_report_as_markdown(results, filename: str, timestamp: str = None, config=None) -> str:
    """Save a human-readable Markdown security report beside the JSON writers.

    Uses :class:`MarkdownSecurityReporter` to render a ranked / tiered report from
    the analysis results. Returns the written filename, or "" when there is nothing
    to write.

    Args:
        results: FullAnalysisResults object or a dict with apk_overview/security_assessment.
        filename: Base APK name used to build the output filename.
        timestamp: Shared run timestamp; generated when omitted.
        config: Optional Configuration controlling report thresholds and top_n.
    """
    from .results.reporting.markdown_report import MarkdownSecurityReporter

    if timestamp is None:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    # Nothing to report without a security assessment.
    has_security = (isinstance(results, dict) and results.get("security_assessment")) or getattr(
        results, "security_assessment", None
    )
    if not has_security:
        return ""

    top_n = 5
    if config is not None:
        try:
            security_report_cfg = config.get_output_config().get("security_report", {}) or {}
            top_n = int(security_report_cfg.get("top_n", 5))
        except Exception:
            top_n = 5

    reporter = MarkdownSecurityReporter(top_n=top_n, config=config)
    markdown = reporter.generate(results)

    base_filename = filename.replace(" ", "_")
    safe_filename = f"dexray_{base_filename}_security_{timestamp}.md"
    dump_text(safe_filename, markdown)
    return safe_filename


def _maybe_dump_security_markdown(results, config, name: str, timestamp: str) -> str:
    """Write the Markdown security report if output.security_report.markdown.enabled.

    Returns the written filename (or "") and never raises: a report-rendering
    failure must not abort the analysis run.
    """
    try:
        if config is None:
            return ""
        output_cfg = config.get_output_config() if hasattr(config, "get_output_config") else {}
        markdown_cfg = (output_cfg.get("security_report", {}) or {}).get("markdown", {}) or {}
        if not markdown_cfg.get("enabled", False):
            return ""
        report_file = dump_security_report_as_markdown(results, name, timestamp, config)
        if report_file:
            print(f"[*] Markdown security report saved to: {report_file}")
        return report_file
    except Exception as e:
        logging.debug(f"Markdown security report generation failed: {e}")
        return ""


def _print_cached_summary(main_dict: dict, security_dict: dict | None, verbose: bool = False, config=None):
    """Print the analyst summary for a full-hit cache re-emit.

    Reconstructs a lightweight :class:`FullAnalysisResults` from the cached dicts —
    the security assessment dict (rendered verbatim) plus the APK overview — and
    delegates to ``print_cached_summary`` so the security block (risk scores, TOP
    RISKS, CONFIRMED tiers) matches a fresh run. On any reconstruction failure this
    falls back to a concise stub so a cache hit never regresses to zero output.
    """
    try:
        from .results.FullAnalysisResults import FullAnalysisResults

        recon = FullAnalysisResults()
        if security_dict:
            recon.security_assessment = security_dict
        # Best-effort restore of the APK-info header. Only apk_overview supports
        # dict rehydration (Results/in_depth has no update_from_dict); a malformed
        # overview must not sink the whole summary.
        with contextlib.suppress(Exception):
            recon.apk_overview.update_from_dict(main_dict.get("apk_overview", {}) or {})
        recon.print_cached_summary(verbose=verbose, config=config)
    except Exception as e:
        logging.debug(f"Rich cached summary failed, printing concise stub: {e}")
        _print_cached_summary_stub(main_dict, security_dict)


def _print_cached_summary_stub(main_dict: dict, security_dict: dict | None):
    """Concise fallback summary printed only if the rich cached summary fails."""
    try:
        overview = main_dict.get("apk_overview", {}) or {}
        general = overview.get("general_info", {}) or {}
        print(f"{'='*60}")
        print("📱 DEXRAY INSIGHT ANALYSIS SUMMARY (from cache)")
        print(f"{'='*60}")
        app_name = general.get("app_name") or general.get("package_name")
        if app_name:
            print(f"App: {app_name}")
        if general.get("package_name"):
            print(f"Package: {general.get('package_name')}")
        if security_dict:
            findings = security_dict.get("findings", security_dict.get("security_findings", []))
            if isinstance(findings, list):
                print(f"Security Findings: {len(findings)}")
        print("💡 Full details saved to the JSON output file(s).")
    except Exception as e:
        logging.debug(f"Could not print cached summary stub: {e}")


class ArgParser(argparse.ArgumentParser):
    """Custom argument parser for Dexray Insight CLI."""

    def error(self, message):
        """Handle argument parsing errors with custom formatting."""
        print("Dexray Insight v" + __version__ + " ")
        print("by " + __author__)
        print()
        print("Error: " + message)
        print()
        print(self.format_help().replace("usage:", "Usage:"))
        self.exit(0)


def _create_argument_parser():
    """Create and configure the main argument parser."""
    return ArgParser(
        add_help=False,
        description="Dexray Insight is part of the dynamic Sandbox Sandroid. Its purpose is to do static analysis in order to get a basic understanding of an Android application.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False,
        epilog=r"""
Examples:
  %(prog)s <path to APK>
  %(prog)s <path to APK> -s  # Enable OWASP Top 10 security assessment
  %(prog)s <path to APK> -s --cve  # Enable security assessment with CVE scanning
  %(prog)s <path to APK> -sig  # Enable signature checking
  %(prog)s <path to APK> --no-tracker  # Disable tracker analysis
  %(prog)s <path to APK> -a  # Enable API invocation analysis
  %(prog)s <path to APK> --deep  # Enable deep behavioral analysis
""",
    )


def _add_basic_arguments(args_group):
    """Add basic arguments like target APK and version."""
    args_group.add_argument("exec", metavar="<executable/apk>", help="Path to the target APK file for static analysis.")
    args_group.add_argument(
        "--version",
        action="version",
        version=f"Dexray Insight v{__version__}",
        help="Display the current version of Dexray Insight.",
    )


def _add_logging_arguments(args_group):
    """Add logging and output control arguments."""
    args_group.add_argument(
        "-d",
        "--debug",
        nargs="?",
        const="INFO",
        default="ERROR",
        help=(
            "Set the logging level for debugging. Options: DEBUG, INFO, WARNING, ERROR. "
            "If not specified, defaults to ERROR."
        ),
    )
    args_group.add_argument(
        "-f",
        "--filter",
        nargs="+",
        help="Filter log messages by file. Specify one or more files to include in the logs.",
    )
    args_group.add_argument(
        "-v",
        "--verbose",
        required=False,
        action="store_const",
        const=True,
        default=False,
        help="Enable verbose output. Shows complete JSON results instead of the analyst-friendly summary.",
    )


def _add_analysis_arguments(args_group):
    """Add analysis control arguments."""
    args_group.add_argument(
        "-sig", "--signaturecheck", action="store_true", help="Perform signature analysis during static analysis."
    )
    args_group.add_argument(
        "--diffing_apk",
        metavar="<path_to_diff_apk>",
        help=(
            "Specify an additional APK to perform diffing analysis. Provide two APK paths "
            "for comparison, or use this parameter to specify the APK for diffing."
        ),
    )


def _add_security_arguments(args_group):
    """Add security analysis arguments."""
    args_group.add_argument(
        "-s",
        "--sec",
        required=False,
        action="store_const",
        const=True,
        default=False,
        help="Enable OWASP Top 10 security analysis. This comprehensive assessment will be done after the standard analysis.",
    )
    args_group.add_argument(
        "--cve",
        required=False,
        action="store_true",
        help=(
            "Enable CVE vulnerability scanning for detected libraries. "
            "Queries online CVE databases (OSV, NVD, GitHub Advisory) to identify known vulnerabilities. "
            "Requires --sec flag to be enabled. Rate-limited and cached for performance."
        ),
    )
    args_group.add_argument(
        "--clear-cve-cache",
        required=False,
        action="store_true",
        help=(
            "Clear the CVE vulnerability scanning cache before analysis. "
            "Forces fresh queries to CVE databases instead of using cached results. "
            "Useful when you want the latest vulnerability information."
        ),
    )
    args_group.add_argument(
        "--no-cache",
        required=False,
        action="store_true",
        help=(
            "Disable the analysis result cache for this run (both reads and writes). "
            "Forces every prerequisite (e.g. DEX string extraction) to be recomputed."
        ),
    )
    args_group.add_argument(
        "--clear-analysis-cache",
        required=False,
        action="store_true",
        help=(
            "Clear the analysis result cache (~/.dexray_insight/analysis_cache) before "
            "analysis. Does not affect the CVE cache (see --clear-cve-cache)."
        ),
    )
    args_group.add_argument(
        "--security-report-md",
        required=False,
        action="store_true",
        help=(
            "Write a human-readable Markdown security report (ranked TOP RISKS + "
            "Confirmed / Needs-review / Informational tiers) alongside the JSON output. "
            "Equivalent to setting output.security_report.markdown.enabled in config."
        ),
    )


def _add_module_control_arguments(args_group):
    """Add module control arguments for trackers, API analysis, etc."""
    args_group.add_argument(
        "-t",
        "--tracker",
        required=False,
        action="store_true",
        help="Enable tracker analysis. This is enabled by default but can be disabled in config.",
    )
    args_group.add_argument(
        "--no-tracker",
        required=False,
        action="store_true",
        help="Disable tracker analysis even if enabled in configuration.",
    )
    args_group.add_argument(
        "-a",
        "--api-invocation",
        required=False,
        action="store_true",
        help="Enable API invocation analysis. This is disabled by default.",
    )
    args_group.add_argument(
        "--deep",
        required=False,
        action="store_true",
        help="Enable deep behavioral analysis. Detects privacy-sensitive behaviors and advanced techniques. This is disabled by default.",
    )
    args_group.add_argument(
        "--exclude_net_libs",
        required=False,
        default=None,
        metavar="<path_to_file_with_lib_name>",
        help="Specify which .NET libs/assemblies should be ignored. "
        "Provide a path either to a comma separated or '\\n'-separated file."
        "E.g. if the string 'System.Security' is in that file, every assembly starting with 'System.Security' will be ignored",
    )


def _add_config_arguments(args_group):
    """Add configuration file arguments."""
    args_group.add_argument(
        "-c",
        "--config",
        metavar="<config_file>",
        help="Path to configuration file (JSON or YAML) for advanced settings.",
    )


def parse_arguments():
    """Parse command line arguments with organized argument groups."""
    parser = _create_argument_parser()

    args = parser.add_argument_group("Arguments")

    _add_basic_arguments(args)
    _add_logging_arguments(args)
    _add_analysis_arguments(args)
    _add_security_arguments(args)
    _add_module_control_arguments(args)
    _add_config_arguments(args)

    return parser.parse_args()


def _load_or_create_configuration(parsed_args):
    """Load configuration from file if provided, otherwise create it from CLI args.

    Returns:
        Tuple of (configuration, error_code). error_code is non-zero on failure.
    """
    config = None
    if hasattr(parsed_args, "config") and parsed_args.config:
        try:
            config = Configuration(config_path=parsed_args.config)
            print(f"[*] Loaded configuration from: {parsed_args.config}")
        except Exception as e:
            print(f"[-] Failed to load configuration file: {str(e)}", file=sys.stderr)
            return None, 1

    if config is None:
        config = create_configuration_from_args(parsed_args)
    else:
        # A config file was loaded. Layer CLI flag overrides on top so that
        # explicit flags (-s, --cve, --deep, --debug, --no-cache, ...) win over
        # the file, matching the DEFAULT -> dexray.yaml -> file -> dict layering.
        # Pass the loaded config so --cve can see file-enabled security.
        config._merge_config(_build_configuration_updates(parsed_args, existing_config=config))

    return config, 0


def _print_analysis_completion(results, total_time, result_file_name, security_result_file_name):
    """Print the analysis completion summary and return the process exit code."""
    if results:
        print(f"\n{'='*60}")
        print("ANALYSIS COMPLETE")
        print(f"{'='*60}")
        print(f"Analysis completed in {total_time:.2f} seconds")
        print(f"Results saved to: {result_file_name}")

        if security_result_file_name:
            print(f"Security analysis results saved to: {security_result_file_name}")

        print("\nThank you for using Dexray Insight!")
        print("Visit https://github.com/fkie-cad/Sandroid_Dexray-Insight for more information.")

        return 0
    else:
        print("[-] Analysis failed", file=sys.stderr)
        return 1


def main():
    """Execute the main entry point for the application."""
    try:
        parsed_args = parse_arguments()
        script_name = sys.argv[0]

        print_logo()

        # Create configuration first so we can pass it to set_logger
        config, config_error = _load_or_create_configuration(parsed_args)
        if config_error:
            return config_error

        # Set up logging with configuration
        set_logger(parsed_args, config)

        if not parsed_args.exec:
            print("\n[-] Missing argument.", file=sys.stderr)
            print(
                f"[-] Invoke it with the target process to hook:\n    {script_name} <executable/apk>", file=sys.stderr
            )
            return 2

        target_apk = parsed_args.exec

        # Check if APK file exists
        if not Path(target_apk).exists():
            print(f"[-] APK file not found: {target_apk}", file=sys.stderr)
            return 1

        # Configuration was already created earlier

        # Validate configuration
        if not config.validate():
            print("[-] Configuration validation failed", file=sys.stderr)
            return 1

        # Clear CVE cache if requested
        if hasattr(parsed_args, "clear_cve_cache") and parsed_args.clear_cve_cache:
            try:
                from .security.cve.utils.cache_manager import CVECacheManager

                cache_manager = CVECacheManager()
                cache_manager.clear_cache()
                print("[*] CVE cache cleared successfully")
            except Exception as e:
                print(f"[!] Warning: Failed to clear CVE cache: {e}")

        # Clear analysis cache if requested
        if hasattr(parsed_args, "clear_analysis_cache") and parsed_args.clear_analysis_cache:
            try:
                from .core.cache_manager import AnalysisCacheManager

                caching_cfg = config.get_caching_config()
                AnalysisCacheManager(cache_dir=caching_cfg.get("cache_dir")).clear_cache()
                print("[*] Analysis cache cleared successfully")
            except Exception as e:
                print(f"[!] Warning: Failed to clear analysis cache: {e}")

        print(f"[*] Analyzing APK: {target_apk}")
        print(f"[*] OWASP Top 10 Security Assessment: {'Enabled' if config.enable_security_assessment else 'Disabled'}")
        print(f"[*] Parallel Execution: {'Enabled' if config.parallel_execution_enabled else 'Disabled'}")

        # Run analysis
        start_time = time.time()
        is_verbose = hasattr(parsed_args, "verbose") and parsed_args.verbose
        results, result_file_name, security_result_file_name = start_apk_static_analysis_new(
            target_apk, config, print_results_to_terminal=True, verbose=is_verbose
        )

        total_time = time.time() - start_time

        return _print_analysis_completion(results, total_time, result_file_name, security_result_file_name)

    except KeyboardInterrupt:
        print("\n[-] Analysis interrupted by user", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"[-] Unexpected error: {str(e)}", file=sys.stderr)
        logging.error(f"Unexpected error in main: {str(e)}", exc_info=True)
        return 1


# Backward compatibility: keep the old function signature
def start_apk_static_analysis(
    apk_file_path,
    do_signature_check=False,
    apk_to_diff=None,
    print_results_to_terminal=False,
    is_verbose=False,
    do_sec_analysis=False,
    exclude_net_libs=None,
):
    """Backward compatibility wrapper for the old function signature."""
    # Create configuration from old parameters
    config_dict = {
        "modules": {
            "signature_detection": {"enabled": do_signature_check},
            "apk_diffing": {"enabled": apk_to_diff is not None},
        },
        "security": {"enable_owasp_assessment": do_sec_analysis},
        "logging": {"level": "DEBUG" if is_verbose else "INFO"},
    }

    config = Configuration(config_dict=config_dict)

    return start_apk_static_analysis_new(apk_file_path, config, print_results_to_terminal, verbose=is_verbose)


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
