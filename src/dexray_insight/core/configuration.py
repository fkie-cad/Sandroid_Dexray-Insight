#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Configuration management system for Dexray Insight analysis framework."""

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

import copy
import json
import logging
import os
from pathlib import Path
from typing import Any


def _leaves(tree: dict[str, Any], prefix: tuple[str, ...] = ()):
    """Yield ``(path, value)`` for every non-dict value of a nested dict."""
    for key, value in tree.items():
        path = (*prefix, key)
        if isinstance(value, dict) and value:
            yield from _leaves(value, path)
        else:
            yield path, value


_MISSING = object()


def _default_at(tree: dict[str, Any], path: tuple[str, ...]) -> Any:
    """The value at ``path`` in ``tree``, or a sentinel when absent."""
    node: Any = tree
    for key in path:
        if not isinstance(node, dict) or key not in node:
            return _MISSING
        node = node[key]
    return node


class Configuration:
    """Centralized configuration management for Dexray Insight."""

    DEFAULT_CONFIG = {
        "analysis": {
            "parallel_execution": {"enabled": True, "max_workers": 4},
            "timeout": {"module_timeout": 300, "tool_timeout": 600},  # 5 minutes per module  # 10 minutes per tool
        },
        "caching": {
            # MD5-keyed reuse of expensive, deterministic analysis prerequisites.
            # Invalidation is fingerprint-based (tool + androguard version +
            # schema), not time-based. Skipped/failed results are never cached.
            "enabled": True,
            "cache_dir": None,  # None -> ~/.dexray_insight/analysis_cache
            "tiers": {
                "dex_strings": True,  # shared per-DEX string lists (biggest low-risk win)
                "library_signatures": True,  # library similarity signatures
                "module_results": True,  # per-module result dicts
                "full_result": True,  # assembled full-run report (full-hit gate)
            },
            "full_hit_gate": True,  # short-circuit an identical re-run from cache
        },
        "modules": {
            "signature_detection": {
                "enabled": True,
                "priority": 10,
                "providers": {
                    "virustotal": {"enabled": False, "api_key": None, "rate_limit": 4},  # requests per minute
                    "koodous": {"enabled": False, "api_key": None},
                    "triage": {"enabled": True, "api_key": None},
                },
            },
            "permission_analysis": {
                "enabled": True,
                "priority": 20,
                "critical_permissions_file": None,  # Path to custom permissions file
                "use_default_critical_list": True,
            },
            "string_analysis": {
                "enabled": True,
                "priority": 30,
                "patterns": {
                    "ip_addresses": True,
                    "urls": True,
                    "email_addresses": True,
                    "domains": True,
                    "base64_strings": True,
                },
                "filters": {"min_string_length": 2, "exclude_patterns": []},
                # Cap on materialized samples surfaced per category (emails, IPs,
                # URLs, domains, android_properties). True totals are preserved.
                "max_samples_per_category": 1000,
            },
            "api_invocation": {"enabled": False, "priority": 40, "reflection_analysis": True},
            "manifest_analysis": {
                "enabled": True,
                "priority": 15,
                "extract_intent_filters": True,
                "analyze_exported_components": True,
            },
            "apk_diffing": {"enabled": False, "priority": 100},
            "tracker_analysis": {
                "enabled": True,
                "priority": 35,
                "fetch_exodus_trackers": True,
                "exodus_api_url": "https://reports.exodus-privacy.eu.org/api/trackers",
                "api_timeout": 10,
                # On-disk copy of the Exodus list (None -> ~/.dexray_insight/exodus_cache/trackers.json),
                # used when the API is unreachable; exodus_offline=True never touches the network.
                "exodus_cache_path": None,
                "exodus_offline": False,
                # Optional JSON file extending/overriding the built-in signature database by id.
                "tracker_db_path": None,
                # Expensive deep option: full second pass over all DEX bytecode to
                # attribute each string to its method location(s). Not required for
                # tracker detection; disabled by default.
                "deep_string_location_analysis": False,
            },
            "privacy_analysis": {
                # Off in the generic profile: it forces the androguard xref build (+20-30 % wall
                # time when nothing else needs it). The privacy profile switches it on.
                "enabled": False,
                "priority": 45,  # unused by the engine (ordering is by dependencies); parity only
                # Call sites emitted per catalogued API; the rest are counted in coverage.limits_hit.
                "max_call_sites_per_api": 1000,
                # Later sites of an API keep reachability "not_checked".
                "reachability_max_sites_per_api": 200,
                "reachability_max_depth": 6,
                "reachability_max_nodes": 200,
                # Attribute obfuscated code to an SDK by its cited strings/hosts.
                "string_anchor_attribution": True,
            },
            "behaviour_analysis": {
                "enabled": True,
                "priority": 1000,  # Lowest priority to run last
                "deep_mode": False,  # Fast mode by default, deep mode via --deep flag
            },
            "library_detection": {
                "enabled": True,
                "priority": 25,
                "enable_heuristic": True,
                "enable_similarity": True,
                "confidence_threshold": 0.7,
                "similarity_threshold": 0.85,
                "class_similarity_threshold": 0.7,
                "version_analysis": {
                    "enabled": True,
                    "security_analysis_only": True,  # Only run during security analysis
                    "api_timeout": 5,
                    "cache_duration_hours": 24,
                    "sources": {"maven_central": True, "npm_registry": True, "pypi": True, "custom_database": False},
                    "console_output": {
                        "enabled": True,
                        "show_recommendations": True,
                        "group_by_risk": True,
                        "show_summary": True,
                    },
                },
            },
            "native_analysis": {
                "enabled": True,
                "priority": 50,  # Run after library_detection and string_analysis
                "requires_temporal_analysis": True,  # Only run when APK is unzipped
                "architectures": ["arm64-v8a"],  # Primary 64-bit ARM
                "file_patterns": ["*.so"],  # Native shared libraries
                "modules": {
                    "string_extraction": {
                        "enabled": True,
                        "min_string_length": 4,
                        "max_string_length": 1024,
                        "encoding": "utf-8",
                        "fallback_encodings": ["latin1", "ascii"],
                    }
                },
            },
        },
        "tools": {
            # apkid is optional: even when enabled here, it is only run if the
            # `apkid` CLI is installed (detected via the tool's is_available()).
            "apkid": {"enabled": True, "timeout": 300, "options": []},
            "kavanoz": {"enabled": True, "timeout": 600, "output_dir": None},  # If None, uses temp directory
            "androguard": {"enabled": True, "logging_level": "WARNING"},
            # Decompilation and Analysis Tools
            "jadx": {
                "enabled": True,
                "path": None,  # Set to JADX executable path
                "timeout": 900,  # 15 minutes
                "options": ["--no-debug-info", "--no-inline-anonymous", "--show-bad-code"],
            },
            "apktool": {
                "enabled": True,
                "path": None,  # Set to apktool JAR path
                "timeout": 600,  # 10 minutes
                "java_options": ["-Xmx2g"],  # Java heap options
                "options": ["--no-debug-info"],
            },
            # Native Binary Analysis Tools
            "radare2": {
                "enabled": True,
                "path": None,  # Set to radare2 binary path (uses system PATH if None)
                "timeout": 120,  # 2 minutes per binary analysis
                "options": ["-2"],  # Radare2 options: -2 for no stderr output
            },
        },
        "temporal_analysis": {
            "enabled": True,
            "base_directory": "./temp_analysis",  # Base directory for temporal analysis
            "cleanup_after_analysis": False,  # Set to True to cleanup directories after analysis
            "directory_structure": {
                "unzipped_folder": "unzipped",  # Folder name for unzipped APK contents
                "jadx_folder": "jadxResults",  # Folder name for JADX decompiled results
                "apktool_folder": "apktoolResults",  # Folder name for apktool results
                "logs_folder": "logs",  # Folder name for tool execution logs
            },
            "preserve_on_error": True,  # Keep directories if analysis fails
        },
        "security": {
            "enable_owasp_assessment": False,
            "assessments": {
                "injection": {
                    "enabled": True,
                    "sql_patterns": ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP"],
                    "command_patterns": ["exec", "system", "runtime"],
                },
                "broken_authentication": {"enabled": True, "check_weak_crypto": True, "check_hardcoded_secrets": True},
                "sensitive_data": {
                    "enabled": True,
                    "pii_patterns": ["email", "phone", "ssn", "credit_card"],
                    "crypto_keys_check": True,
                    # Legacy string-corpus PII scanner; off by default, superseded by the
                    # dedicated `pii` assessment (validated taxonomy).
                    "pii_exposure_enabled": False,
                },
                # Privacy / PII taxonomy assessment (Phase B1).
                "pii": {"enabled": True},
                # FileProvider path-scope + exported-provider analyzer (Phase B2).
                "provider_paths": {"enabled": True},
                # Ad-SDK RCE-surface knowledge base (Phase B4).
                "sdk_risk_surface": {"enabled": True},
                # Deep xref detectors (Phase C1/C2) — no-op unless --deep.
                "deep_dataflow": {"enabled": True},
                # Deep PII-flow correlation (Phase C3) — no-op unless --deep.
                "pii_flow": {"enabled": True},
                "broken_access_control": {
                    "enabled": True,
                    "check_exported_components": True,
                    "check_permissions": True,
                },
                "security_misconfiguration": {
                    "enabled": True,
                    "check_debug_flags": True,
                    "check_network_security": True,
                },
                "vulnerable_components": {"enabled": True, "check_known_libraries": True},
                "insufficient_logging": {"enabled": True, "check_logging_practices": True},
            },
            # PR-7: context analysis / false-positive post-processing pass. Default ON
            # (per rollout decision); the pass is a safety no-op for non-secret findings.
            "context_analysis": {
                "enabled": True,
                "allow_severity_downgrade": True,
                "max_context_strings": 5000,
                "false_positive": {
                    "downgrade_high_threshold": 0.8,
                    "downgrade_medium_threshold": 0.5,
                },
                "dedup": {
                    "enabled": True,
                    "merge_across_categories": True,
                },
            },
            # Evidence-weighted risk scoring (Phase A). Headline = confirmed-subset score.
            "risk_scoring": {
                "version": 2,
                "headline_mode": "confirmed",
                "confirmed_threshold": 0.7,
                # Retained for backward-compat / rollback; no longer a hard clamp.
                "critical_floor": 75.0,
                # Soft additive bump per confirmed high-confidence CRITICAL (capped at 100):
                # score = min(100, base_normalized + critical_bump * n_critical).
                "critical_bump": 18.0,
                # Diminishing-returns decay per severity tier (k-th finding in a tier
                # contributes weight*confidence*decay**k). CRITICAL undecayed; volume damped.
                "severity_decay": {
                    "critical": 1.0,
                    "high": 0.8,
                    "medium": 0.5,
                    "low": 0.4,
                },
            },
        },
        "output": {
            "format": "json",
            "pretty_print": True,
            "include_timestamps": True,
            "output_directory": "./results",
            "filename_template": "asam_{apk_name}_{timestamp}.json",
            # Ranked / tiered security report (PR-9). Controls the terminal analyst
            # summary's TOP-RISKS count and tier thresholds, and the optional
            # Markdown security report writer.
            "security_report": {
                "top_n": 5,  # findings surfaced in the TOP RISKS section
                "tiers": {
                    "high_confidence_min": 0.75,  # confirmed tier: confidence >= this AND crit/high
                    "review_min": 0.40,  # needs-review floor; below -> informational
                },
                "show_informational": False,  # print the informational tier in the terminal
                "markdown": {"enabled": False},  # write a Markdown security report file
            },
        },
        "logging": {
            "level": "INFO",
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            "file": None,  # If None, logs to console only
        },
    }

    def __init__(
        self,
        config_path: str | None = None,
        config_dict: dict[str, Any] | None = None,
        profile: str | None = None,
    ):
        """
        Initialize configuration.

        Layering, lowest to highest: built-in defaults, ``dexray.yaml``,
        ``config_path``, ``config_dict``, environment, then CLI flags merged with
        :meth:`merge_explicit`. The ``profile`` overrides apply to every key that
        nothing set explicitly. Explicit keys are those of ``config_path`` whose
        value differs from the built-in defaults (a full copy of the shipped
        ``dexray.yaml`` changes nothing), every key of ``config_dict`` and every CLI
        flag. A profile's requirements apply when the caller or a CLI flag switches
        the feature on, are re-applied after every later merge, and only touch keys
        that were not set explicitly.

        Args:
            config_path: Path to configuration file (JSON or YAML)
            config_dict: Configuration dictionary (overrides file and profile)
            profile: Name of an analysis profile (see
                :mod:`dexray_insight.core.profiles`), e.g. ``"privacy"``.

        Raises:
            ValueError: For an unknown profile name.
        """
        # Deep copy so that per-instance mutations (env overrides, merged file
        # or dict config) never leak into the shared class-level DEFAULT_CONFIG.
        self.config = copy.deepcopy(self.DEFAULT_CONFIG)
        self.profile: str | None = None
        #: Leaf key paths a user set explicitly; a profile never overrides them.
        self._explicit: set[tuple[str, ...]] = set()
        #: The subset set by the caller (``config_dict``) or CLI flags.
        self._explicit_by_caller: set[tuple[str, ...]] = set()
        self._warned_requirements: set[str] = set()

        # Try to load default config file first
        self._load_default_config()

        if config_path:
            self._load_from_file(config_path, explicit="changed")

        if config_dict:
            self._merge_config(config_dict, explicit="all")

        if profile:
            self.apply_profile(profile)

        # Load environment variables (highest priority)
        self._load_from_environment()

    def _load_default_config(self):
        """Try to load default config file from project root."""
        # Look for dexray.yaml in project root (relative to this file)
        current_dir = Path(__file__).parent
        project_root = current_dir.parent.parent.parent  # Go up to project root
        default_config_path = project_root / "dexray.yaml"

        if default_config_path.exists():
            try:
                self._load_from_file(str(default_config_path))
            except Exception as e:
                # Don't fail if default config can't be loaded, just warn
                print(f"Warning: Could not load default config from {default_config_path}: {e}")
        else:
            # Also check current working directory
            cwd_config = Path.cwd() / "dexray.yaml"
            if cwd_config.exists():
                try:
                    self._load_from_file(str(cwd_config))
                except Exception as e:
                    print(f"Warning: Could not load config from {cwd_config}: {e}")

    def _load_from_file(self, config_path: str, explicit: str | None = None):
        """Load configuration from file."""
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        try:
            with open(path) as f:
                if path.suffix.lower() in [".yml", ".yaml"]:
                    # Try to import yaml, fallback to JSON if not available
                    try:
                        import yaml

                        file_config = yaml.safe_load(f)
                    except ImportError:
                        raise ValueError("YAML files require PyYAML to be installed") from None
                else:
                    file_config = json.load(f)

            self._merge_config(file_config, explicit=explicit)
        except Exception as e:
            raise ValueError(f"Failed to load configuration from {config_path}: {str(e)}") from e

    def _load_from_environment(self):
        """Load configuration from environment variables."""
        # API Keys
        vt_key = os.getenv("VIRUSTOTAL_API_KEY")
        if vt_key:
            self.config["modules"]["signature_detection"]["providers"]["virustotal"]["api_key"] = vt_key
            self.config["modules"]["signature_detection"]["providers"]["virustotal"]["enabled"] = True

        koodous_key = os.getenv("KOODOUS_API_KEY")
        if koodous_key:
            self.config["modules"]["signature_detection"]["providers"]["koodous"]["api_key"] = koodous_key
            self.config["modules"]["signature_detection"]["providers"]["koodous"]["enabled"] = True

        triage_key = os.getenv("TRIAGE_API_KEY")
        if triage_key:
            self.config["modules"]["signature_detection"]["providers"]["triage"]["api_key"] = triage_key

        # Other environment overrides
        log_level = os.getenv("DEXRAY_LOG_LEVEL")
        if log_level:
            self.config["logging"]["level"] = log_level.upper()

        output_dir = os.getenv("DEXRAY_OUTPUT_DIR")
        if output_dir:
            self.config["output"]["output_directory"] = output_dir

    def _merge_config(self, new_config: dict[str, Any], explicit: str | None = None):
        """Recursively merge new configuration with existing.

        Args:
            new_config: Partial configuration.
            explicit: ``"all"`` marks every leaf key as set explicitly,
                ``"changed"`` only those whose value differs from the built-in
                defaults, ``None`` none (defaults, ``dexray.yaml``).
        """

        def merge_dict(base: dict[str, Any], update: dict[str, Any]):
            for key, value in update.items():
                if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                    merge_dict(base[key], value)
                else:
                    base[key] = value

        if explicit and isinstance(new_config, dict):
            for path, value in _leaves(new_config):
                if explicit == "all" or _default_at(self.DEFAULT_CONFIG, path) != value:
                    self._explicit.add(path)
                if explicit == "all":
                    self._explicit_by_caller.add(path)
        merge_dict(self.config, new_config)
        if getattr(self, "profile", None):
            self._apply_profile_requirements()

    def merge_explicit(self, updates: dict[str, Any]) -> None:
        """Merge settings the user stated explicitly (CLI flags); a profile never overrides them."""
        self._merge_config(updates, explicit="all")

    def _apply_profile_requirements(self) -> None:
        """Switch on what an enabled feature needs (see ``AnalysisProfile.requirements``).

        Keys set explicitly are left alone; one warning then says the feature is limited.
        """
        from .profiles import get_profile

        for feature, switch, triggers, required in get_profile(self.profile).requirements:
            if switch not in self._explicit_by_caller:
                continue  # switched on only by a -c file (or not at all)
            if any(self._get_nested(path) != value for path, value in triggers.items()):
                continue
            kept_off = []
            for path, value in required.items():
                if self._get_nested(path) == value:
                    continue
                if path in self._explicit:
                    kept_off.append(".".join(path))
                else:
                    self._set_nested_value(list(path), value)
            if kept_off and feature not in self._warned_requirements:
                self._warned_requirements.add(feature)
                logging.getLogger(__name__).warning(f"{feature} is limited: {', '.join(kept_off)} stay as configured")

    def _get_nested(self, path) -> Any:
        node: Any = self.config
        for key in path:
            if not isinstance(node, dict) or key not in node:
                return None
            node = node[key]
        return node

    def apply_profile(self, name: str) -> None:
        """Merge the overrides of analysis profile ``name`` into this configuration.

        Raises:
            ValueError: For an unknown profile name.
        """
        from .profiles import get_profile

        profile = get_profile(name)
        self.profile = profile.name
        for path, value in _leaves(profile.overrides):
            if path not in self._explicit:
                self._set_nested_value(list(path), copy.deepcopy(value))
        self._apply_profile_requirements()

    def get_module_config(self, module_name: str) -> dict[str, Any]:
        """Get configuration for a specific module."""
        return self.config.get("modules", {}).get(module_name, {})

    def get_tool_config(self, tool_name: str) -> dict[str, Any]:
        """Get configuration for a specific external tool."""
        return self.config.get("tools", {}).get(tool_name, {})

    def get_temporal_analysis_config(self) -> dict[str, Any]:
        """Get temporal analysis configuration."""
        return self.config.get("temporal_analysis", {})

    def get_security_config(self) -> dict[str, Any]:
        """Get security assessment configuration."""
        return self.config.get("security", {})

    def get_context_analysis_config(self) -> dict[str, Any]:
        """Get the security context-analysis / false-positive post-processing config.

        Returns the ``security.context_analysis`` block (PR-7). Returns an empty dict
        when absent, which the post-processor treats as disabled (no-op) for safety.
        """
        return self.config.get("security", {}).get("context_analysis", {})

    def get_output_config(self) -> dict[str, Any]:
        """Get output configuration."""
        return self.config.get("output", {})

    @property
    def enable_security_assessment(self) -> bool:
        """Check if OWASP security assessment is enabled."""
        return self.config.get("security", {}).get("enable_owasp_assessment", False)

    @property
    def parallel_execution_enabled(self) -> bool:
        """Check if parallel execution is enabled."""
        return self.config.get("analysis", {}).get("parallel_execution", {}).get("enabled", True)

    @property
    def max_workers(self) -> int:
        """Get maximum number of parallel workers."""
        return self.config.get("analysis", {}).get("parallel_execution", {}).get("max_workers", 4)

    @property
    def caching_enabled(self) -> bool:
        """Check if analysis result caching is enabled."""
        return self.config.get("caching", {}).get("enabled", True)

    def get_caching_config(self) -> dict[str, Any]:
        """Get the caching configuration section."""
        return self.config.get("caching", {})

    def to_dict(self) -> dict[str, Any]:
        """Get complete configuration as dictionary."""
        return self.config.copy()

    def save_to_file(self, file_path: str, format: str = "json"):
        """
        Save configuration to file.

        Args:
            file_path: Path to save configuration
            format: File format ('json' or 'yaml')
        """
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w") as f:
            if format.lower() == "yaml":
                try:
                    import yaml

                    yaml.dump(self.config, f, default_flow_style=False, indent=2)
                except ImportError:
                    raise ValueError("YAML output requires PyYAML to be installed") from None
            else:
                json.dump(self.config, f, indent=2)

    def update_from_kwargs(self, **kwargs):
        """Update configuration from keyword arguments (for backward compatibility)."""
        # Map common CLI arguments to configuration
        mapping = {
            "do_signature_check": ["modules", "signature_detection", "enabled"],
            "is_verbose": ["logging", "level"],  # Would map 'DEBUG' if True
            "do_sec_analysis": ["security", "enable_owasp_assessment"],
        }

        for arg_name, arg_value in kwargs.items():
            if arg_name in mapping:
                config_path = mapping[arg_name]
                self._set_nested_value(config_path, arg_value)

    def _set_nested_value(self, path: list, value: Any):
        """Set a nested configuration value."""
        current = self.config
        for key in path[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]

        # Special handling for verbose flag
        if path[-1] == "level" and isinstance(value, bool):
            current[path[-1]] = "DEBUG" if value else "INFO"
        else:
            current[path[-1]] = value

    def validate(self) -> bool:
        """Validate configuration."""
        # Check required API keys if services are enabled
        sig_config = self.get_module_config("signature_detection")
        for provider, config in sig_config.get("providers", {}).items():
            if config.get("enabled", False) and not config.get("api_key"):
                print(f"Warning: {provider} is enabled but no API key provided")

        # Check output directory
        output_dir = self.get_output_config().get("output_directory")
        if output_dir:
            path = Path(output_dir)
            if not path.exists():
                try:
                    path.mkdir(parents=True, exist_ok=True)
                except Exception as e:
                    print(f"Warning: Cannot create output directory {output_dir}: {e}")
                    return False

        return True
