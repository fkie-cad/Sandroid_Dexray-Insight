#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""PR-9 config-parity guard: DEFAULT_CONFIG vs the shipped dexray.yaml.

``Configuration`` merges ``dexray.yaml`` on top of ``DEFAULT_CONFIG`` at runtime,
so structural drift between the two silently changes behaviour depending on whether
the yaml is present. These tests pin the *structure* (nested key sets); values may
differ freely.

Two guards:

* ``output.security_report`` (the PR-9 addition) must have EXACT structural parity
  in both places — the new surface must never drift.
* The whole-tree drift is pinned to a small, explicitly documented allowlist so any
  NEW drift fails the build and must be either aligned (preferred, additive) or
  added here with a reason.
"""

import os

import pytest
import yaml

from src.dexray_insight.core.configuration import Configuration

_YAML_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", "dexray.yaml")


def _key_paths(obj, prefix=""):
    """Return the set of dotted key paths in a nested dict (structure only)."""
    paths = set()
    if isinstance(obj, dict):
        for key, value in obj.items():
            path = f"{prefix}.{key}" if prefix else key
            paths.add(path)
            paths |= _key_paths(value, path)
    return paths


@pytest.fixture(scope="module")
def yaml_config():
    with open(_YAML_PATH) as handle:
        return yaml.safe_load(handle)


# --------------------------------------------------------------------------- #
# Documented, intentional drift. Keep this list SMALL and justified.
# --------------------------------------------------------------------------- #

# Keys present in DEFAULT_CONFIG but intentionally NOT in dexray.yaml.
_DEFAULT_ONLY_ALLOWLIST = {
    # dexray.yaml deliberately comments this out so the -s CLI flag controls it
    # (see the "Security Assessment Configuration" block in dexray.yaml).
    "security.enable_owasp_assessment",
}

# dexray.yaml is a richer, user-facing superset: many keys are read in code via
# .get(...) with inline defaults and need no DEFAULT_CONFIG fallback. Pinning the
# exact set makes any NEW yaml-only key surface here for a conscious decision.
_YAML_ONLY_ALLOWLIST = {
    # behaviour_analysis feature toggles (read with per-feature .get defaults)
    "modules.behaviour_analysis.features",
    "modules.behaviour_analysis.features.android_version_access",
    "modules.behaviour_analysis.features.camera_access",
    "modules.behaviour_analysis.features.clipboard_usage",
    "modules.behaviour_analysis.features.device_model_access",
    "modules.behaviour_analysis.features.dynamic_receivers",
    "modules.behaviour_analysis.features.imei_access",
    "modules.behaviour_analysis.features.installed_applications_access",
    "modules.behaviour_analysis.features.installed_packages_access",
    "modules.behaviour_analysis.features.phone_number_access",
    "modules.behaviour_analysis.features.reflection_usage",
    "modules.behaviour_analysis.features.running_services_access",
    # library_detection apktool detection + feature toggles + custom patterns
    "modules.library_detection.apktool_detection",
    "modules.library_detection.apktool_detection.auto_update_definitions",
    "modules.library_detection.apktool_detection.enable_buildconfig_detection",
    "modules.library_detection.apktool_detection.enable_pattern_detection",
    "modules.library_detection.apktool_detection.enable_properties_detection",
    "modules.library_detection.apktool_detection.libinfo_path",
    "modules.library_detection.apktool_detection.libinfo_url",
    "modules.library_detection.apktool_detection.libsmali_path",
    "modules.library_detection.apktool_detection.libsmali_url",
    "modules.library_detection.custom_patterns",
    "modules.library_detection.features",
    "modules.library_detection.features.call_chain_analysis",
    "modules.library_detection.features.class_analysis",
    "modules.library_detection.features.manifest_analysis",
    "modules.library_detection.features.method_analysis",
    "modules.library_detection.features.package_analysis",
    "modules.library_detection.features.structural_analysis",
    # native_analysis library version detection sub-module
    "modules.native_analysis.modules.library_version_detection",
    "modules.native_analysis.modules.library_version_detection.enabled",
    "modules.native_analysis.modules.library_version_detection.max_libraries_per_binary",
    "modules.native_analysis.modules.library_version_detection.min_confidence",
    "modules.native_analysis.modules.library_version_detection.strings_timeout",
    # security assessment knobs (evidence gating + detailed secret detection)
    "security.assessments.injection.require_sink",
    "security.assessments.sensitive_data.key_detection",
    "security.assessments.sensitive_data.key_detection.allowlist",
    "security.assessments.sensitive_data.key_detection.allowlist.enabled",
    "security.assessments.sensitive_data.key_detection.binary_filter",
    "security.assessments.sensitive_data.key_detection.binary_filter.enabled",
    "security.assessments.sensitive_data.key_detection.confidence",
    "security.assessments.sensitive_data.key_detection.confidence.enabled",
    "security.assessments.sensitive_data.key_detection.confidence.min_confidence",
    "security.assessments.sensitive_data.key_detection.context_detection",
    "security.assessments.sensitive_data.key_detection.context_detection.enabled",
    "security.assessments.sensitive_data.key_detection.context_detection.strict_mode",
    "security.assessments.sensitive_data.key_detection.deduplication",
    "security.assessments.sensitive_data.key_detection.deduplication.enabled",
    "security.assessments.sensitive_data.key_detection.deduplication.similarity_threshold",
    "security.assessments.sensitive_data.key_detection.enabled",
    "security.assessments.sensitive_data.key_detection.entropy_thresholds",
    "security.assessments.sensitive_data.key_detection.entropy_thresholds.min_base64_entropy",
    "security.assessments.sensitive_data.key_detection.entropy_thresholds.min_generic_entropy",
    "security.assessments.sensitive_data.key_detection.entropy_thresholds.min_hex_entropy",
    "security.assessments.sensitive_data.key_detection.jwt",
    "security.assessments.sensitive_data.key_detection.jwt.require_decodable_header",
    "security.assessments.sensitive_data.key_detection.length_filters",
    "security.assessments.sensitive_data.key_detection.length_filters.max_key_length",
    "security.assessments.sensitive_data.key_detection.length_filters.min_key_length",
    "security.assessments.sensitive_data.key_detection.patterns",
    "security.assessments.sensitive_data.key_detection.patterns.android_specific",
    "security.assessments.sensitive_data.key_detection.patterns.api_keys",
    "security.assessments.sensitive_data.key_detection.patterns.base64_keys",
    "security.assessments.sensitive_data.key_detection.patterns.database_connections",
    "security.assessments.sensitive_data.key_detection.patterns.hex_keys",
    "security.assessments.sensitive_data.key_detection.patterns.high_entropy_strings",
    "security.assessments.sensitive_data.key_detection.patterns.jwt_tokens",
    "security.assessments.sensitive_data.key_detection.patterns.mobile_specific",
    "security.assessments.sensitive_data.key_detection.patterns.pem_keys",
    "security.assessments.sensitive_data.key_detection.patterns.ssh_keys",
    "security.assessments.sensitive_data.key_detection.performance",
    "security.assessments.sensitive_data.key_detection.performance.max_pattern_length",
    "security.assessments.sensitive_data.key_detection.performance.max_strings_ci",
    "security.assessments.sensitive_data.key_detection.performance.max_text_length",
    # radare2 fallback paths (probed at runtime, not part of the minimal default)
    "tools.radare2.fallback_paths",
}

# CVE scanning is a large, entirely yaml-driven subtree (read via the security
# config with inline defaults). Pinned by prefix to keep the allowlist readable.
_YAML_ONLY_PREFIXES = ("security.cve_scanning",)


@pytest.mark.unit
class TestSecurityReportParity:
    """The PR-9 output.security_report surface must be identical in both configs."""

    def test_output_security_report_structure_matches(self, yaml_config):
        default_output = Configuration.DEFAULT_CONFIG["output"]
        yaml_output = yaml_config["output"]

        default_paths = _key_paths(default_output.get("security_report", {}))
        yaml_paths = _key_paths(yaml_output.get("security_report", {}))

        assert default_paths == yaml_paths, (
            "output.security_report drifted between DEFAULT_CONFIG and dexray.yaml.\n"
            f"  default-only: {sorted(default_paths - yaml_paths)}\n"
            f"  yaml-only:    {sorted(yaml_paths - default_paths)}"
        )

    def test_output_top_level_structure_matches(self, yaml_config):
        default_paths = _key_paths(Configuration.DEFAULT_CONFIG["output"])
        yaml_paths = _key_paths(yaml_config["output"])
        assert default_paths == yaml_paths, (
            "output section drifted.\n"
            f"  default-only: {sorted(default_paths - yaml_paths)}\n"
            f"  yaml-only:    {sorted(yaml_paths - default_paths)}"
        )


@pytest.mark.unit
class TestWholeTreeParity:
    """Pin whole-tree structural drift to the documented allowlist."""

    def test_no_undocumented_drift(self, yaml_config):
        default_paths = _key_paths(Configuration.DEFAULT_CONFIG)
        yaml_paths = _key_paths(yaml_config)

        default_only = default_paths - yaml_paths
        yaml_only = yaml_paths - default_paths

        # Drop pinned prefixes (large yaml-only subtrees like CVE scanning).
        yaml_only = {
            path for path in yaml_only if not any(path.startswith(prefix) for prefix in _YAML_ONLY_PREFIXES)
        }

        unexpected_default_only = default_only - _DEFAULT_ONLY_ALLOWLIST
        unexpected_yaml_only = yaml_only - _YAML_ONLY_ALLOWLIST

        assert not unexpected_default_only, (
            "New DEFAULT_CONFIG-only keys (add to dexray.yaml, or to the allowlist "
            f"with a reason): {sorted(unexpected_default_only)}"
        )
        assert not unexpected_yaml_only, (
            "New dexray.yaml-only keys (add to DEFAULT_CONFIG, or to the allowlist "
            f"with a reason): {sorted(unexpected_yaml_only)}"
        )

    def test_allowlist_stays_relevant(self, yaml_config):
        # Guard against stale allowlist entries: every allowlisted default-only key
        # must actually be default-only, and likewise for yaml-only.
        default_paths = _key_paths(Configuration.DEFAULT_CONFIG)
        yaml_paths = _key_paths(yaml_config)

        stale_default = {p for p in _DEFAULT_ONLY_ALLOWLIST if p not in (default_paths - yaml_paths)}
        stale_yaml = {p for p in _YAML_ONLY_ALLOWLIST if p not in (yaml_paths - default_paths)}

        assert not stale_default, f"Stale DEFAULT-only allowlist entries: {sorted(stale_default)}"
        assert not stale_yaml, f"Stale yaml-only allowlist entries: {sorted(stale_yaml)}"
