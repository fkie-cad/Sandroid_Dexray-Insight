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
from pathlib import Path
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


# ------------------------------------------------------------------- cache keys


class TestCacheKeysIgnorePaths:
    @staticmethod
    def _keys(config_dict):
        from dexray_insight.core.analysis_engine import AnalysisEngine

        engine = AnalysisEngine(Configuration(config_dict=config_dict))
        return engine._full_hit_config_hash(["apk_overview", "string_analysis"]), engine._module_cache_key_hash()

    @staticmethod
    def _run_config(work_dir, definitions_dir, level):
        return {
            "caching": {"enabled": True, "cache_dir": str(work_dir) + "-cache"},
            "temporal_analysis": {"base_directory": str(work_dir), "cleanup_after_analysis": True},
            "modules": {
                "library_detection": {
                    "apktool_detection": {
                        "libsmali_path": str(definitions_dir / "libsmali.jsonl"),
                        "libinfo_path": str(definitions_dir / "libinfo.jsonl"),
                    }
                }
            },
            "logging": {"level": level},
        }

    def test_two_runs_with_different_work_dirs_share_the_keys(self, tmp_path):
        first = self._keys(self._run_config(tmp_path / "run-1", tmp_path / "a", "INFO"))
        second = self._keys(self._run_config(tmp_path / "run-2", tmp_path / "b", "DEBUG"))
        assert first == second

    def test_a_real_setting_still_changes_the_keys(self, tmp_path):
        base = self._run_config(tmp_path / "run", tmp_path / "a", "INFO")
        changed = self._run_config(tmp_path / "run", tmp_path / "a", "INFO")
        changed["modules"]["string_analysis"] = {"min_string_length": 9}
        assert self._keys(base) != self._keys(changed)


# ---------------------------------------------------------------------- logging


class TestEmbeddedLogging:
    def test_foreign_root_file_handlers_are_never_touched(self, tmp_path):
        import logging

        from dexray_insight.Utils.log import INSIGHT_HANDLER_MARK
        from dexray_insight.Utils.log import setup_apk_specific_debug_logging

        root = logging.getLogger()
        old_level = root.level
        host = logging.FileHandler(tmp_path / "host.log")
        mine = logging.FileHandler(tmp_path / "insight.log")
        setattr(mine, INSIGHT_HANDLER_MARK, True)
        root.addHandler(host)
        root.addHandler(mine)
        root.setLevel(logging.DEBUG)
        paths = MagicMock(logs_dir=tmp_path / "logs")
        try:
            assert setup_apk_specific_debug_logging("app", paths)
            assert host in root.handlers  # the embedding app's handler stays
            assert mine not in root.handlers  # Insight's own is moved
            moved = [h for h in root.handlers if getattr(h, INSIGHT_HANDLER_MARK, False)]
            assert moved and str(tmp_path / "logs") in moved[0].baseFilename
        finally:
            for handler in list(root.handlers):
                if handler is host or getattr(handler, INSIGHT_HANDLER_MARK, False):
                    root.removeHandler(handler)
                    handler.close()
            root.setLevel(old_level)

    def test_without_insight_handler_nothing_changes(self, tmp_path):
        import logging

        from dexray_insight.Utils.log import setup_apk_specific_debug_logging

        root = logging.getLogger()
        old_level = root.level
        host = logging.FileHandler(tmp_path / "host.log")
        root.addHandler(host)
        root.setLevel(logging.DEBUG)
        try:
            before = list(root.handlers)
            setup_apk_specific_debug_logging("app", MagicMock(logs_dir=tmp_path / "logs"))
            assert root.handlers == before
            assert not (tmp_path / "logs").exists()
        finally:
            root.removeHandler(host)
            host.close()
            root.setLevel(old_level)


# ---------------------------------------------------------- library definitions


class TestLibraryDefinitionsAreLazy:
    def test_construction_never_downloads(self, tmp_path, monkeypatch):
        from dexray_insight.modules.library_detection.engines import apktool_detection_engine as engine_module

        monkeypatch.chdir(tmp_path)
        with patch.object(engine_module.ApktoolDetectionEngine, "_update_library_definitions") as update:
            engine = engine_module.ApktoolDetectionEngine({}, MagicMock())
            update.assert_not_called()
            engine._load_library_definitions()
            update.assert_called_once()
            engine._libs_by_path = None
            engine._load_library_definitions()
            update.assert_called_once()  # checked once per engine
        assert list(tmp_path.iterdir()) == []

    def test_offline_config_never_downloads(self):
        from dexray_insight.modules.library_detection.engines import apktool_detection_engine as engine_module

        with patch.object(engine_module.ApktoolDetectionEngine, "_update_library_definitions") as update:
            engine = engine_module.ApktoolDetectionEngine(
                {"apktool_detection": {"auto_update_definitions": False}}, MagicMock()
            )
            engine._load_library_definitions()
        update.assert_not_called()

    def test_dependency_resolver_passes_the_real_module_config(self):
        from dexray_insight.core.analysis_engine import DependencyResolver

        seen = {}

        class _Module:
            def __init__(self, config):
                seen["config"] = config

            def get_dependencies(self):
                return []

        registry = MagicMock()
        registry.get_module.return_value = _Module
        config = Configuration(config_dict={"modules": {"library_detection": {"marker": 1}}})
        DependencyResolver(registry, config).resolve_dependencies(["library_detection"])
        assert seen["config"]["marker"] == 1


# ---------------------------------------------------------- .NET and kavanoz


class TestScratchFilesStayOutOfTheWorkingDirectory:
    def test_dotnet_blobs_go_to_the_private_work_dir(self, tmp_path, monkeypatch):
        from dexray_insight.modules.dotnet_analysis import DotnetAnalysisModule

        cwd = tmp_path / "cwd"
        cwd.mkdir()
        monkeypatch.chdir(cwd)
        module = DotnetAnalysisModule({})
        module._work_dir = str(tmp_path / "work")
        context = MagicMock()
        context.androguard_obj.androguard_apk.get_file.return_value = b"data"
        files = ["assemblies/assemblies.blob", "assemblies/assemblies.manifest"]
        module._discover_dotnet_files(context, files, r"App.*\.dll$", r"(assemblies)\.blob", r"assemblies.manifest")
        assert (tmp_path / "work" / ".blobs" / "assemblies.blob").exists()
        assert list(cwd.iterdir()) == []

    def test_dotnet_work_dir_is_removed(self, tmp_path):
        from dexray_insight.modules.dotnet_analysis import DotnetAnalysisModule

        module = DotnetAnalysisModule({})
        context = MagicMock(temporal_paths=MagicMock(base_dir=tmp_path))
        with patch.object(DotnetAnalysisModule, "_analyze", return_value="result"):
            assert module.analyze("app.apk", context) == "result"
        assert module._work_dir.startswith(str(tmp_path))
        assert not os.path.exists(module._work_dir)

    def test_kavanoz_temp_dir_is_removed_when_nothing_was_unpacked(self, tmp_path):
        from dexray_insight.tools.kavanoz_tool import KavanozTool

        tool = KavanozTool({})
        created = []

        def fake_analyze(apk, out):
            created.append(out)
            return MagicMock(unpacked=False)

        with (
            patch("dexray_insight.tools.kavanoz_tool.platform.machine", return_value="x86_64"),
            patch.object(KavanozTool, "_analyze_with_kavanoz", side_effect=fake_analyze),
        ):
            result = tool.execute(str(tmp_path / "app.apk"))
        assert created and not os.path.exists(created[0])
        assert result["output_directory"] is None


# ------------------------------------------------------------- profile layering


class TestProfileLayering:
    def test_shipped_dexray_yaml_does_not_cancel_the_profile(self):
        shipped = Path(asam.__file__).resolve().parents[2] / "dexray.yaml"
        config = Configuration(config_path=str(shipped), profile="privacy")
        assert config.get_module_config("native_analysis")["enabled"] is False
        assert config.get_module_config("library_detection")["enable_similarity"] is False
        assert config.get_tool_config("apktool")["enabled"] is False
        assert config.get_temporal_analysis_config()["enabled"] is False
        assert config.get_security_config()["assessments"]["injection"]["enabled"] is False

    def test_file_keys_that_differ_from_the_defaults_win(self, tmp_path):
        config_file = tmp_path / "my.yaml"
        config_file.write_text(
            "modules:\n  tracker_analysis:\n    enabled: false\n  native_analysis:\n    enabled: true\n"
        )
        config = Configuration(config_path=str(config_file), profile="privacy")
        assert config.get_module_config("tracker_analysis")["enabled"] is False  # differs: explicit
        assert config.get_module_config("native_analysis")["enabled"] is False  # same as default: profile
        assert config.get_module_config("signature_detection")["enabled"] is False

    def test_config_dict_keys_always_win(self):
        config = Configuration(profile="privacy", config_dict={"modules": {"native_analysis": {"enabled": True}}})
        assert config.get_module_config("native_analysis")["enabled"] is True

    def test_cve_flag_brings_its_prerequisites_back(self):
        with patch("sys.argv", ["dexray-insight", "app.apk", "--profile", "privacy", "-s", "--cve"]):
            args = asam.parse_arguments()
        config = asam.create_configuration_from_args(args)
        assert config.get_security_config()["cve_scanning"]["enabled"] is True
        assert config.get_module_config("native_analysis")["enabled"] is True
        assert config.get_module_config("library_detection")["enable_similarity"] is True
        assert config.get_tool_config("apktool")["enabled"] is True
        assert config.get_temporal_analysis_config()["enabled"] is True
        assert config.get_security_config()["assessments"]["vulnerable_components"]["enabled"] is True

    def test_explicitly_disabled_prerequisites_stay_off_with_one_warning(self, tmp_path, caplog):
        import logging

        config_file = tmp_path / "my.yaml"
        config_file.write_text("tools:\n  apktool:\n    enabled: false\n")
        with caplog.at_level(logging.WARNING, logger="dexray_insight.core.configuration"):
            config = Configuration(
                config_path=str(config_file),
                profile="privacy",
                config_dict={"security": {"enable_owasp_assessment": True, "cve_scanning": {"enabled": True}}},
            )
            config.merge_explicit({"logging": {"level": "INFO"}})  # a later merge re-checks
        assert config.get_tool_config("apktool")["enabled"] is False  # explicit: kept
        assert config.get_module_config("native_analysis")["enabled"] is True  # not explicit: back on
        warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
        assert warnings == ["CVE scanning is limited: tools.apktool.enabled stay as configured"]

    @staticmethod
    def _cli_config(*flags):
        shipped = Path(asam.__file__).resolve().parents[2] / "dexray.yaml"
        with patch("sys.argv", ["dexray-insight", "app.apk", "-c", str(shipped), *flags]):
            args = asam.parse_arguments()
        config, error = asam._load_or_create_configuration(args)
        assert error == 0
        return config

    def test_shipped_yaml_privacy_and_security_stays_lean(self):
        config = self._cli_config("--profile", "privacy", "-s")
        assert config.enable_security_assessment is True
        assert config.get_security_config()["cve_scanning"]["enabled"] is False
        assert config.get_tool_config("apktool")["enabled"] is False
        assert config.get_module_config("native_analysis")["enabled"] is False

    def test_shipped_yaml_privacy_with_cve_gets_its_requirements(self):
        config = self._cli_config("--profile", "privacy", "-s", "--cve")
        assert config.get_security_config()["cve_scanning"]["enabled"] is True
        assert config.get_tool_config("apktool")["enabled"] is True
        assert config.get_module_config("native_analysis")["enabled"] is True
        assert config.get_temporal_analysis_config()["enabled"] is True
        assert config.get_module_config("library_detection")["enable_similarity"] is True
        assert config.get_security_config()["assessments"]["vulnerable_components"]["enabled"] is True

    def test_cve_enabled_only_by_a_config_file_does_not_pull_requirements(self, tmp_path):
        config_file = tmp_path / "my.yaml"
        config_file.write_text("security:\n  cve_scanning:\n    enabled: true\n")
        config = Configuration(
            config_path=str(config_file),
            profile="privacy",
            config_dict={"security": {"enable_owasp_assessment": True}},
        )
        assert config.get_security_config()["cve_scanning"]["enabled"] is True
        assert config.get_tool_config("apktool")["enabled"] is False

    def test_cve_without_security_changes_nothing(self):
        config = Configuration(profile="privacy", config_dict={"security": {"cve_scanning": {"enabled": True}}})
        assert config.get_module_config("native_analysis")["enabled"] is False

    def test_without_cve_the_profile_stays_lean(self):
        with patch("sys.argv", ["dexray-insight", "app.apk", "--profile", "privacy", "-s"]):
            args = asam.parse_arguments()
        config = asam.create_configuration_from_args(args)
        assert config.get_module_config("native_analysis")["enabled"] is False


# -------------------------------------------------------------- apktool nits


class TestApktoolDetails:
    def test_directory_and_uppercase_jar(self, tmp_path):
        from dexray_insight.core.temporal_directory import is_jar

        assert is_jar("/x/APKTOOL.JAR")
        with patch.dict(os.environ, {"PATH": str(tmp_path / "empty")}):
            assert resolve_apktool(str(tmp_path)) is None  # a directory does not count

    def test_wrapper_gets_java_options_via_java_tool_options(self, tmp_path):
        wrapper = _executable(tmp_path / "apktool")
        config = Configuration(config_dict={"tools": {"apktool": {"path": str(wrapper), "java_options": ["-Xmx3g"]}}})
        manager = TemporalDirectoryManager(config, MagicMock())
        out = tmp_path / "out"
        out.mkdir()
        with patch(
            "dexray_insight.core.temporal_directory.subprocess.run", return_value=MagicMock(returncode=0)
        ) as run:
            manager.run_apktool(str(tmp_path / "app.apk"), out)
        assert run.call_args[0][0][0] == str(wrapper)
        assert "-Xmx3g" in run.call_args.kwargs["env"]["JAVA_TOOL_OPTIONS"]
