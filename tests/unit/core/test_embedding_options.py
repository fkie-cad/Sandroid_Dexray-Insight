#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Options for embedding Insight in another tool (Sandroid): profiles, apktool, output dir.

* analysis profiles (``Configuration(profile=...)``, ``--profile``),
* apktool resolution from PATH when the configured JAR is missing,
* result files written to an explicit ``output_dir`` instead of the working directory.
"""

import json
import os
import stat
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from dexray_insight import asam
from dexray_insight.core.configuration import Configuration
from dexray_insight.core.profiles import ANALYSIS_PROFILES
from dexray_insight.core.profiles import get_profile_overrides
from dexray_insight.core.profiles import list_profiles
from dexray_insight.core.temporal_directory import TemporalDirectoryManager
from dexray_insight.core.temporal_directory import resolve_apktool

# --------------------------------------------------------------------- profiles


class TestProfiles:
    def test_known_profiles(self):
        assert {"generic", "privacy"} <= set(list_profiles())
        assert all(list_profiles().values())

    def test_generic_changes_nothing(self):
        assert Configuration(profile="generic").to_dict() == Configuration().to_dict()

    def test_privacy_keeps_privacy_modules_and_drops_heavy_ones(self):
        config = Configuration(profile="privacy")
        modules = config.config["modules"]
        for name in ("permission_analysis", "tracker_analysis", "string_analysis", "manifest_analysis"):
            assert modules[name]["enabled"] is True, name
        assert modules["api_invocation"]["enabled"] is True
        assert modules["native_analysis"]["enabled"] is False
        assert modules["signature_detection"]["enabled"] is False
        assert modules["library_detection"]["enable_similarity"] is False
        assert config.get_tool_config("apktool")["enabled"] is False
        assert config.get_temporal_analysis_config()["enabled"] is False
        assessments = config.get_security_config()["assessments"]
        assert assessments["injection"]["enabled"] is False
        assert assessments.get("pii", {}).get("enabled", True) is True
        assert config.profile == "privacy"

    def test_profile_does_not_decide_the_security_assessment(self):
        on = Configuration(profile="privacy", config_dict={"security": {"enable_owasp_assessment": True}})
        assert on.enable_security_assessment is True
        assert Configuration(profile="privacy").enable_security_assessment is False

    def test_config_dict_overrides_the_profile(self):
        config = Configuration(profile="privacy", config_dict={"modules": {"tracker_analysis": {"enabled": False}}})
        assert config.get_module_config("tracker_analysis")["enabled"] is False
        # the rest of the profile still applies
        assert config.get_module_config("native_analysis")["enabled"] is False

    def test_unknown_profile_is_an_error(self):
        with pytest.raises(ValueError, match="Unknown analysis profile"):
            Configuration(profile="nope")

    def test_overrides_are_copies(self):
        get_profile_overrides("privacy")["modules"]["native_analysis"]["enabled"] = True
        assert ANALYSIS_PROFILES["privacy"].overrides["modules"]["native_analysis"]["enabled"] is False

    def test_cli_profile_flag(self):
        with patch("sys.argv", ["dexray-insight", "app.apk", "--profile", "privacy"]):
            args = asam.parse_arguments()
        assert args.profile == "privacy"
        config = asam.create_configuration_from_args(args)
        assert config.get_module_config("native_analysis")["enabled"] is False


# ---------------------------------------------------------------------- apktool


def _executable(path):
    path.write_text("#!/bin/sh\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


class TestApktoolResolution:
    def test_existing_configured_path_wins(self, tmp_path):
        jar = tmp_path / "apktool_9.9.9.jar"
        jar.write_bytes(b"jar")
        with patch("shutil.which", return_value="/somewhere/apktool"):
            assert resolve_apktool(str(jar)) == str(jar)

    def test_missing_or_empty_path_falls_back_to_path(self, tmp_path):
        wrapper = _executable(tmp_path / "apktool")
        with patch.dict(os.environ, {"PATH": str(tmp_path)}):
            assert resolve_apktool("/opt/homebrew/Cellar/apktool/2.12.0/libexec/apktool_2.12.0.jar") == str(wrapper)
            assert resolve_apktool(None) == str(wrapper)
            assert resolve_apktool("") == str(wrapper)

    def test_nothing_found(self, tmp_path):
        with patch.dict(os.environ, {"PATH": str(tmp_path)}):
            assert resolve_apktool(None) is None

    def _manager(self, apktool_cfg):
        config = Configuration(config_dict={"tools": {"apktool": apktool_cfg}})
        return TemporalDirectoryManager(config, MagicMock())

    def _run(self, manager, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        completed = MagicMock(returncode=0)
        with patch("dexray_insight.core.temporal_directory.subprocess.run", return_value=completed) as run:
            manager.run_apktool(str(tmp_path / "app.apk"), out)
        return run.call_args[0][0]

    def test_path_wrapper_runs_directly(self, tmp_path):
        wrapper = _executable(tmp_path / "apktool")
        with patch.dict(os.environ, {"PATH": str(tmp_path)}):
            manager = self._manager({"enabled": True, "path": None})
            assert manager.check_tool_availability("apktool")
            cmd = self._run(manager, tmp_path)
        assert cmd[:2] == [str(wrapper), "decode"]
        assert "--output" in cmd

    def test_configured_jar_runs_under_java(self, tmp_path):
        jar = tmp_path / "apktool.jar"
        jar.write_bytes(b"jar")
        manager = self._manager({"enabled": True, "path": str(jar), "java_options": ["-Xmx1g"]})
        cmd = self._run(manager, tmp_path)
        assert cmd[:4] == ["java", "-Xmx1g", "-jar", str(jar)]

    def test_unavailable_apktool_is_skipped(self, tmp_path):
        with patch.dict(os.environ, {"PATH": str(tmp_path)}):
            manager = self._manager({"enabled": True, "path": "/does/not/exist.jar"})
            assert not manager.check_tool_availability("apktool")
            assert manager.run_apktool(str(tmp_path / "app.apk"), tmp_path) is False


# ------------------------------------------------------------------- output dir


class TestOutputDir:
    def test_result_files_go_to_output_dir(self, tmp_path, monkeypatch):
        cwd = tmp_path / "cwd"
        cwd.mkdir()
        monkeypatch.chdir(cwd)
        out = tmp_path / "session" / "dexray_insight"

        main = asam.dump_results_as_json_file({"a": 1}, "my app", "T", output_dir=str(out))
        sec = asam.dump_security_results_as_json_file({"s": 1}, "my app", "T", output_dir=str(out))

        assert main == str(out / "dexray_my_app_T.json")
        assert sec == str(out / "dexray_my_app_security_T.json")
        assert json.loads((out / "dexray_my_app_T.json").read_text()) == {"a": 1}
        assert list(cwd.iterdir()) == []

    def test_default_stays_in_working_directory(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert asam.dump_results_as_json_file({"a": 1}, "app", "T") == "dexray_app_T.json"
        assert (tmp_path / "dexray_app_T.json").exists()

    def test_entry_point_passes_output_dir_on_a_cache_hit(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        out = tmp_path / "out"
        engine = MagicMock()
        engine.try_full_hit.return_value = {"main": {"apk_overview": {}}, "security": {"x": 1}}
        with patch.object(asam, "AnalysisEngine", return_value=engine):
            _, main, sec = asam.start_apk_static_analysis_new(
                str(tmp_path / "app.apk"), Configuration(), output_dir=str(out)
            )
        assert main.startswith(str(out)) and os.path.exists(main)
        assert sec.startswith(str(out)) and os.path.exists(sec)
