# SPDX-License-Identifier: GPL-3.0-only
"""Module wiring: engine contract, manifest facts, profiles, main JSON, cache keys."""

import json
import shutil
from types import SimpleNamespace
from unittest import mock

import pytest
from lxml import etree

from dexray_insight.core import cache_manager
from dexray_insight.core.analysis_engine import AnalysisEngine
from dexray_insight.core.base_classes import AnalysisStatus
from dexray_insight.core.base_classes import BaseResult
from dexray_insight.core.base_classes import registry
from dexray_insight.core.configuration import Configuration
from dexray_insight.core.profiles import get_profile_overrides
from dexray_insight.modules.privacy_analysis import module as mod
from dexray_insight.modules.tracker_analysis.models.tracker_models import DetectedTracker
from dexray_insight.results.FullAnalysisResults import FullAnalysisResults

from .fakes import CATALOGUE_MIN
from .fakes import scooter_scenario

MD5 = "0123456789abcdef0123456789abcdef"
NS = "http://schemas.android.com/apk/res/android"


class FakeContext(SimpleNamespace):
    def get_result(self, name):
        return self.results.get(name)


def _run_module(monkeypatch, androguard=True, trackers=None, config=None):
    x, man, names = scooter_scenario()
    monkeypatch.setattr(mod, "AndroguardIndex", lambda dx, dexes: x)
    monkeypatch.setattr(mod.ManifestFacts, "from_apk", classmethod(lambda cls, apk: man))
    obj = None
    if androguard:
        obj = mock.Mock()
        obj.get_androguard_apk.return_value = object()
        obj.get_androguard_analysis_obj.return_value = object()
        obj.get_androguard_dex.return_value = []
    tracker = SimpleNamespace(detected_trackers=[DetectedTracker(name=n) for n in (trackers or names)])
    ctx = FakeContext(androguard_obj=obj, results={"tracker_analysis": tracker})
    module = mod.PrivacyAnalysisModule({"catalogue_dir": str(CATALOGUE_MIN), **(config or {})})
    return module.analyze("x.apk", ctx)


def test_registered_with_tracker_dependency():
    from dexray_insight import modules  # noqa: F401 - registers the modules

    assert "privacy_analysis" in registry.list_modules()
    assert mod.PrivacyAnalysisModule({}).get_dependencies() == ["tracker_analysis"]


def test_analyze_success(monkeypatch):
    result = _run_module(monkeypatch)
    assert result.status == AnalysisStatus.SUCCESS
    assert result.section["status"] == "success"
    tracker_values = [
        d["value"] for s in result.section["sdks"] for d in s["detection"] if d["kind"] == "tracker_analysis"
    ]
    assert tracker_values == ["google_firebase_analytics", "firebase_crashlytics", "google_admob"]
    out = result.to_dict()
    assert out["privacy_analysis"] is result.section and out["module_name"] == "privacy_analysis"


def test_tracker_name_maps_to_signature_db_id(monkeypatch):
    result = _run_module(monkeypatch, trackers=["google doubleclick"])  # case-insensitive
    admob = next(s for s in result.section["sdks"] if s["id"] == "google_mobile_ads")
    assert {"kind": "tracker_analysis", "value": "google_doubleclick"} in admob["detection"]
    assert admob["recipient_labels"] == ["Google Ads"]


def test_analyze_without_androguard_gives_stub(monkeypatch):
    result = _run_module(monkeypatch, androguard=False)
    assert result.status == AnalysisStatus.FAILURE
    assert result.section["status"] == "failure" and result.section["schema_version"] == 1
    assert set(result.section) == {"schema_version", "status", "errors"}


def test_bad_catalogue_gives_stub(monkeypatch, tmp_path):
    result = _run_module(monkeypatch, config={"catalogue_dir": str(tmp_path)})
    assert result.status == AnalysisStatus.FAILURE
    assert "catalogue" in result.section["errors"][0]


def test_partial_is_success_and_cached(monkeypatch, tmp_path):
    monkeypatch.setattr(mod.Matcher, "field_reads", lambda self: 1 / 0)
    result = _run_module(monkeypatch)
    assert result.status == AnalysisStatus.SUCCESS and result.section["status"] == "partial"
    engine = AnalysisEngine(Configuration(config_dict={"caching": {"cache_dir": str(tmp_path / "c")}}))
    full = FullAnalysisResults(privacy_analysis=result.section)
    context = SimpleNamespace(apk_md5=MD5)
    engine.security_engine = None
    engine._maybe_cache_full_result(context, {"privacy_analysis": result}, None, full, ["privacy_analysis"])
    cached = engine.cache_manager.get_full_result(MD5, engine._full_hit_config_hash(["privacy_analysis"]))
    assert cached["main"]["privacy_analysis"]["status"] == "partial"
    # full-hit round trip: byte-identical section
    assert json.dumps(cached["main"]["privacy_analysis"]) == json.dumps(result.section)


def test_failure_blocks_cache(tmp_path):
    engine = AnalysisEngine(Configuration(config_dict={"caching": {"cache_dir": str(tmp_path / "c")}}))
    engine.security_engine = None
    failed = mod.PrivacyAnalysisResult("privacy_analysis", AnalysisStatus.FAILURE, section=mod.failure_section(["x"]))
    full = FullAnalysisResults(privacy_analysis=failed.section)
    engine._maybe_cache_full_result(
        SimpleNamespace(apk_md5=MD5), {"privacy_analysis": failed}, None, full, ["privacy_analysis"]
    )
    assert engine.cache_manager.get_full_result(MD5, engine._full_hit_config_hash(["privacy_analysis"])) is None


def test_main_json_key():
    assert "privacy_analysis" not in FullAnalysisResults().to_dict()
    section = {"schema_version": 1, "status": "success"}
    assert FullAnalysisResults(privacy_analysis=section).to_dict()["privacy_analysis"] == section
    engine = AnalysisEngine(Configuration())
    assert engine._privacy_section(None) is None
    assert engine._privacy_section(BaseResult("privacy_analysis", AnalysisStatus.SKIPPED)) is None
    crashed = BaseResult("privacy_analysis", AnalysisStatus.FAILURE, error_message="boom")
    assert engine._privacy_section(crashed) == {"schema_version": 1, "status": "failure", "errors": ["boom"]}
    ok = mod.PrivacyAnalysisResult("privacy_analysis", AnalysisStatus.SUCCESS, section=section)
    assert engine._privacy_section(ok) is section


def test_terminal_line(capsys):
    x, man, names = scooter_scenario()
    from dexray_insight.privacy.catalogue import load_catalogue

    section = mod.analyse(x, man, load_catalogue(CATALOGUE_MIN), {}, names)
    FullAnalysisResults(privacy_analysis=section)._print_privacy_summary_line()
    assert "PRIVACY (static): 12 data types" in capsys.readouterr().out
    FullAnalysisResults()._print_privacy_summary_line()
    assert capsys.readouterr().out == ""


# ------------------------------------------------------------- config / profile
def test_enabled_in_both_profiles():
    assert Configuration().get_module_config("privacy_analysis")["enabled"] is True
    overrides = get_profile_overrides("privacy")
    assert overrides["modules"]["privacy_analysis"] == {"enabled": True}
    cfg = Configuration(profile="privacy").get_module_config("privacy_analysis")
    assert cfg["enabled"] is True and cfg["max_call_sites_per_api"] == 1000


def test_explicit_off_stays_off():
    cfg = Configuration(config_dict={"modules": {"privacy_analysis": {"enabled": False}}}, profile="privacy")
    assert cfg.get_module_config("privacy_analysis")["enabled"] is False


# ------------------------------------------------------------------ cache keys
def test_schema_version_bumped():
    assert cache_manager.ANALYSIS_SCHEMA_VERSION == "2026-11-23-static-privacy-layer"


def _engine(tmp_path, catalogue_dir):
    return AnalysisEngine(
        Configuration(
            config_dict={
                "caching": {"cache_dir": str(tmp_path / "cache")},
                "modules": {"privacy_analysis": {"catalogue_dir": str(catalogue_dir)}},
            }
        )
    )


def test_full_hit_key_follows_the_catalogue(tmp_path):
    cat_dir = tmp_path / "cat"
    shutil.copytree(CATALOGUE_MIN, cat_dir)
    with_mod, without = ["privacy_analysis", "tracker_analysis"], ["tracker_analysis"]
    before = _engine(tmp_path, cat_dir)
    keys = (before._full_hit_config_hash(with_mod), before._full_hit_config_hash(without))
    sdks = cat_dir / "sdks.yaml"
    sdks.write_text(
        sdks.read_text().replace(
            "source: vendor-adjust-android-ref}\n    anchors", "source: vendor-admob-ref}\n    anchors"
        )
    )
    after = _engine(tmp_path, cat_dir)
    assert after._full_hit_config_hash(with_mod) != keys[0]
    assert after._full_hit_config_hash(without) == keys[1]


def test_old_schema_entries_are_not_served(tmp_path):
    engine = _engine(tmp_path, CATALOGUE_MIN)
    modules = ["privacy_analysis"]
    with mock.patch.object(cache_manager, "ANALYSIS_SCHEMA_VERSION", "2026-11-20-requested-permissions-sdk23-maxsdk"):
        engine._config_hash_cache = {}
        old_key = engine._full_hit_config_hash(modules)
    engine.cache_manager.set_full_result(MD5, old_key, {"main": {"apk_overview": {}}, "security": None})
    engine._config_hash_cache = {}
    new_key = engine._full_hit_config_hash(modules)
    assert new_key != old_key
    assert engine.cache_manager.get_full_result(MD5, new_key) is None


def test_privacy_catalogue_key_is_memoised(tmp_path):
    manager = cache_manager.AnalysisCacheManager(cache_dir=tmp_path / "c")
    first = manager.privacy_catalogue_key(CATALOGUE_MIN)
    with mock.patch("dexray_insight.privacy.catalogue.catalogue_digest", side_effect=AssertionError):
        assert manager.privacy_catalogue_key(CATALOGUE_MIN) == first
    assert len(first) == 16


# --------------------------------------------------------------- manifest facts
def _apk(xml: str, entries=(), files=(), resources=None):
    root = etree.fromstring(xml.encode())
    apk = mock.Mock()
    apk.get_package.return_value = root.get("package")
    apk.get_min_sdk_version.return_value = "23"
    apk.get_target_sdk_version.return_value = "34"
    apk.get_files.return_value = list(files)
    apk.get_android_manifest_xml.return_value = root
    apk.get_android_resources.return_value = resources
    apk.find_tags.side_effect = lambda tag: list(root.iter(tag))
    apk.get_value_from_tag.side_effect = lambda tag, attr: tag.get(f"{{{NS}}}{attr}")
    apk.get_permissions.return_value = []
    return apk


def test_manifest_facts_from_apk():
    xml = f"""<manifest xmlns:android="{NS}" package="com.ex.app">
      <uses-permission android:name="android.permission.READ_CONTACTS"/>
      <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" android:maxSdkVersion="22"/>
      <application android:name=".App">
        <meta-data android:name="firebase_analytics_collection_enabled" android:value="false"/>
        <meta-data android:name="google_analytics_adid_collection_enabled" android:value="@7F050001"/>
        <activity android:name=".MainActivity"><intent-filter><action android:name="android.intent.action.MAIN"/>
        </intent-filter></activity>
        <service android:name="com.sdk.Listener"
                 android:permission="android.permission.BIND_NOTIFICATION_LISTENER_SERVICE">
          <meta-data android:name="inner" android:value="1"/></service>
        <provider android:name="androidx.startup.InitializationProvider">
          <meta-data android:name="com.sdk.Init" android:value="androidx.startup"/></provider>
      </application></manifest>"""
    facts = mod.ManifestFacts.from_apk(_apk(xml, files=["assets/x.dex", "classes.dex"]))
    assert facts.application_class == "com.ex.app.App"
    assert [(c["name"], c["kind"]) for c in facts.components] == [
        ("com.ex.app.MainActivity", "activity"),
        ("com.sdk.Listener", "service"),
        ("androidx.startup.InitializationProvider", "provider"),
    ]
    assert facts.components[0]["actions"] == ["android.intent.action.MAIN"]
    assert facts.startup_initializers == ["com.sdk.Init"]
    meta = {m["name"]: m for m in facts.meta_data}
    assert meta["firebase_analytics_collection_enabled"]["scope"] == "application"
    assert meta["google_analytics_adid_collection_enabled"]["resolved"] is False
    assert meta["inner"]["scope"] == "component" and meta["inner"]["component"] == "com.sdk.Listener"
    assert list(facts.effective_permissions()) == ["android.permission.READ_CONTACTS"]


def test_unresolved_flag_state_is_unknown():
    flag = {
        "key": "k",
        "sdk_id": "s",
        "type": "bool",
        "off_when": ["false"],
        "effect": "metadata_off",
        "default_when_absent": "on",
        "data_types": ["*"],
        "items": None,
        "sources": ["src"],
    }
    meta = [{"name": "k", "value": "@7F050001", "resolved": False, "scope": "application", "component": None}]
    out = mod._flag_state(flag, meta)
    assert (out["state"], out["resolved"], out["source"]) == ("unknown", False, "docs:src")
    meta = [{"name": "k", "value": "FALSE", "resolved": True, "scope": "application", "component": None}]
    assert mod._flag_state(flag, meta)["state"] == "off"
    meta[0]["scope"] = "component"
    assert (mod._flag_state(flag, meta)["state"], mod._flag_state(flag, meta)["scope"]) == ("default", "component")
    assert mod._flag_state(flag, [])["state"] == "default"


def test_near_miss_meta_key_is_noted():
    from dexray_insight.privacy.catalogue import load_catalogue

    x, man, names = scooter_scenario()
    man.meta_data.append(
        {
            "name": "Firebase_Crashlytics_Collection_Enabled",
            "value": "false",
            "resolved": True,
            "scope": "application",
            "component": None,
        }
    )
    section = mod.analyse(x, man, load_catalogue(CATALOGUE_MIN), {}, names)
    assert any("looks like firebase_crashlytics_collection_enabled" in n for n in section["coverage"]["notes"])


@pytest.mark.parametrize(
    "files,expected",
    [
        (["lib/arm64-v8a/libflutter.so"], ["flutter"]),
        (["assets/index.android.bundle"], ["react_native"]),
        (["classes.dex"], []),
    ],
)
def test_code_outside_dex(files, expected):
    assert mod._framework_words(files) == expected
