#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Tests for the shared signature database, Exodus disk cache and protection detection."""

import json
import os
import re
import socket
import zipfile
from unittest import mock
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
import requests

from dexray_insight.core.base_classes import AnalysisContext
from dexray_insight.core.base_classes import AnalysisStatus
from dexray_insight.modules.tracker_analysis.databases.exodus_api_client import ExodusAPIClient
from dexray_insight.modules.tracker_analysis.databases.tracker_database import ENTRY_KINDS
from dexray_insight.modules.tracker_analysis.databases.tracker_database import PROTECTION_DEFEATS
from dexray_insight.modules.tracker_analysis.databases.tracker_database import TrackerDatabase
from dexray_insight.modules.tracker_analysis.databases.tracker_database import label_for_domain
from dexray_insight.modules.tracker_analysis.databases.tracker_database import load_signature_db
from dexray_insight.modules.tracker_analysis.detectors.pattern_detector import PatternDetector
from dexray_insight.modules.tracker_analysis.tracker_analysis_module import TrackerAnalysisModule
from dexray_insight.results.TrackerAnalysisResults import TrackerAnalysisResults

EXODUS_GET = "dexray_insight.modules.tracker_analysis.databases.exodus_api_client.requests.get"

EXODUS_RESPONSE = {
    "trackers": {
        "27": {
            "name": "Google Firebase Analytics",
            "code_signature": "com.google.firebase.analytics.",
            "network_signature": "firebase.com",
            "website": "https://firebase.google.com/",
        }
    }
}


def _write_json(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


class TestLoadSignatureDb:
    def test_builtin_entries_are_valid(self):
        entries = load_signature_db()
        assert entries
        for entry_id, entry in entries.items():
            assert entry["kind"] in ENTRY_KINDS, entry_id
            assert entry.get("label"), entry_id
            if entry["kind"] == "protection":
                assert set(entry["defeats"]) <= set(PROTECTION_DEFEATS), entry_id
                assert entry["confidence"] in ("high", "medium", "low"), entry_id
                assert entry.get("code_signature") or entry.get("entry_points") or entry.get("native_libs"), entry_id

    def test_exodus_derived_entries_carry_provenance(self):
        entries = load_signature_db()
        exodus = {entry_id for entry_id, entry in entries.items() if entry.get("source") == "exodus"}
        assert exodus == {"teemo", "fidzup", "krux", "ad4screen"}

    def test_legacy_tracker_database_shape_is_kept(self):
        db = TrackerDatabase.get_tracker_database()
        assert len(db) == TrackerDatabase.get_tracker_count() == 22
        admob = db["Google AdMob"]
        assert r"com\.google\.android\.gms\.ads" in admob["patterns"]
        assert admob["category"] == "Advertising"
        assert {"version_patterns", "network_patterns", "description", "website"} <= admob.keys()
        assert "Advertising" in TrackerDatabase.get_tracker_categories()

    def test_override_extends_and_overrides_by_id(self, tmp_path):
        path = _write_json(
            tmp_path / "db.json",
            {
                "entries": {
                    "google_admob": {"label": "AdMob (custom)"},
                    "acme_sdk": {"name": "Acme SDK", "label": "Acme", "patterns": [r"com\.acme\."]},
                    "acme_guard": {"kind": "protection", "name": "Acme Guard", "code_signature": r"^com\.acmeguard\."},
                }
            },
        )
        entries = load_signature_db(path)

        assert entries["google_admob"]["label"] == "AdMob (custom)"
        assert entries["google_admob"]["patterns"]  # untouched fields are kept
        assert entries["acme_sdk"]["kind"] == "tracker"  # default kind
        assert entries["acme_guard"]["kind"] == "protection"
        # the built-in database is not modified by an override
        assert load_signature_db()["google_admob"]["label"] == "Google Ads"

        db = TrackerDatabase(path)
        assert "Acme SDK" in db.get_trackers()
        assert "acme_guard" in db.get_protections()
        assert "Acme SDK" not in TrackerDatabase.get_tracker_database()

    @pytest.mark.parametrize(
        "data",
        [[], {"no_entries": {}}, {"entries": {"x": "nope"}}, {"entries": {"x": {"kind": "bogus"}}}],
    )
    def test_malformed_override_raises(self, tmp_path, data):
        with pytest.raises(ValueError):
            load_signature_db(_write_json(tmp_path / "bad.json", data))

    def test_disabled_removes_entry(self, tmp_path):
        path = _write_json(tmp_path / "db.json", {"entries": {"google_admob": {"disabled": True}}})
        entries = load_signature_db(path)
        assert "google_admob" not in entries
        assert "Google AdMob" not in TrackerDatabase(path).get_trackers()

    @pytest.mark.parametrize("field", ["network_domains", "patterns", "native_libs", "defeats"])
    def test_list_fields_must_be_lists_of_strings(self, tmp_path, field):
        path = _write_json(tmp_path / "db.json", {"entries": {"acme": {field: "acme.com"}}})
        with pytest.raises(ValueError, match=field):
            load_signature_db(path)

    def test_duplicate_tracker_names_warn(self, tmp_path, caplog):
        path = _write_json(tmp_path / "db.json", {"entries": {"admob_copy": {"name": "Google AdMob"}}})
        with caplog.at_level("WARNING"):
            load_signature_db(path)
        assert "share the name 'Google AdMob'" in caplog.text

    def test_runtime_edits_to_tracker_database_are_honoured(self, tmp_path):
        added = {"patterns": [r"com\.acme\."], "category": "Analytics"}
        replaced = {"patterns": [r"com\.custom\.admob"], "category": "Advertising"}
        with mock.patch.dict(TrackerDatabase.TRACKER_DATABASE, {"Acme": added, "Google AdMob": replaced}):
            del TrackerDatabase.TRACKER_DATABASE["Vungle"]
            trackers = TrackerDatabase().get_trackers()
            assert trackers["Acme"] is added
            assert trackers["Google AdMob"] is replaced
            assert "Vungle" not in trackers
            assert "Acme" in TrackerDatabase.get_tracker_database()
            assert TrackerDatabase.get_tracker_count() == 22

            # A user file overriding a tracker wins over the runtime edit.
            path = _write_json(tmp_path / "db.json", {"entries": {"google_admob": {"label": "AdMob"}}})
            assert TrackerDatabase(path).get_trackers()["Google AdMob"]["label"] == "AdMob"
        assert "Vungle" in TrackerDatabase().get_trackers()
        assert "Acme" not in TrackerDatabase().get_trackers()

    def test_module_falls_back_to_builtin_on_bad_override(self):
        module = TrackerAnalysisModule({"fetch_exodus_trackers": False, "tracker_db_path": "/nonexistent/db.json"})
        assert module.tracker_db_error
        assert len(module.tracker_database.get_trackers()) == 22


class TestLabelForDomain:
    @pytest.mark.parametrize(
        ("host", "expected"),
        [
            ("app-measurement.com", ("Google Analytics", "google_firebase_analytics")),
            ("firebaselogging-pa.googleapis.com", ("Google Analytics", "google_firebase_analytics")),
            ("firebaseinstallations.googleapis.com", ("Firebase", "firebase")),
            ("www.googleapis.com", ("Google", "google")),
            ("googleads.g.doubleclick.net", ("Google Ads", "google_doubleclick")),
            ("graph.facebook.com", ("Meta", "facebook_sdk")),
            ("scontent.fbcdn.net", ("Meta", "meta")),
            ("api2.amplitude.com", ("Amplitude", "amplitude")),
            ("analytics.cloud.unity3d.com", ("Unity Analytics", "unity_analytics")),
            ("config.unity3d.com", ("Unity", "unity")),
            ("auction.unityads.unity3d.com", ("Unity Ads", "unity_ads")),
            ("APPSFLYER.COM.", ("AppsFlyer", "appsflyer")),
            ("sentry.io:443", ("Sentry", "sentry")),
            ("app-measurement.com.:443", ("Google Analytics", "google_firebase_analytics")),
            ("[2001:db8::1]:443", None),
            ("2001:db8::1", None),
        ],
    )
    def test_host_lookup(self, host, expected):
        assert label_for_domain(host) == expected

    @pytest.mark.parametrize("host", ["", "example.org", "evilgoogle.com", "google.com.evil.org"])
    def test_no_match(self, host):
        assert label_for_domain(host) is None

    def test_custom_entries(self, tmp_path):
        path = _write_json(
            tmp_path / "db.json",
            {"entries": {"acme": {"kind": "recipient", "label": "Acme", "network_domains": ["t.googleapis.com"]}}},
        )
        entries = load_signature_db(path)
        assert label_for_domain("x.t.googleapis.com", entries) == ("Acme", "acme")
        assert label_for_domain("x.t.googleapis.com") == ("Google", "google")

    def test_wildcard_matches_subdomains_only(self, tmp_path):
        path = _write_json(
            tmp_path / "db.json",
            {"entries": {"acme": {"kind": "recipient", "label": "Acme", "network_domains": ["*.acme.example"]}}},
        )
        entries = load_signature_db(path)
        assert label_for_domain("api.acme.example", entries) == ("Acme", "acme")
        assert label_for_domain("acme.example", entries) is None

    def test_override_domain_wins_tie_with_builtin(self, tmp_path):
        path = _write_json(
            tmp_path / "db.json",
            {"entries": {"my_sentry": {"kind": "recipient", "label": "Our Sentry", "network_domains": ["sentry.io"]}}},
        )
        assert label_for_domain("o1.ingest.sentry.io", load_signature_db(path)) == ("Our Sentry", "my_sentry")

    def test_sandroid_recipient_parity(self):
        """Every domain of Sandroid's former recipient list keeps its label (except unity3d.com)."""
        sandroid_recipients = {
            "app-measurement.com": "Google Analytics",
            "google-analytics.com": "Google Analytics",
            "firebaselogging.googleapis.com": "Google Analytics",
            "crashlytics.com": "Crashlytics",
            "fcm.googleapis.com": "Firebase",
            "admob.com": "Google Ads",
            "googlesyndication.com": "Google Ads",
            "gstatic.com": "Google",
            "facebook.net": "Meta",
            "instagram.com": "Meta",
            "adjust.io": "Adjust",
            "branch.io": "Branch",
            "segment.com": "Segment",
            "appboy.com": "Braze",
            "cookielaw.org": "OneTrust",
            "applovin.com": "AppLovin",
            "unity3d.com": "Unity",  # was "Unity Ads"; only unityads.unity3d.com is ads-specific
            "bytedance.com": "TikTok",
            "nr-data.net": "New Relic",
            "datadoghq.com": "Datadog",
            "bugsnag.com": "Bugsnag",
        }
        for domain, label in sandroid_recipients.items():
            assert label_for_domain(domain)[0] == label, domain

    def test_domains_are_unique(self):
        seen = {}
        for entry_id, entry in load_signature_db().items():
            for domain in entry.get("network_domains", []):
                assert domain not in seen, f"{domain} in {entry_id} and {seen.get(domain)}"
                seen[domain] = entry_id


class TestExodusCache:
    def _client(self, tmp_path, **config):
        return ExodusAPIClient({"exodus_cache_path": str(tmp_path / "exodus" / "trackers.json"), **config})

    def test_default_cache_path(self):
        client = ExodusAPIClient({})
        assert client.cache_path.parts[-3:] == (".dexray_insight", "exodus_cache", "trackers.json")

    @pytest.mark.parametrize(
        ("record", "category", "categories"),
        [
            ({"categories": ["Analytics", "Ads"]}, "Analytics, Ads", ["Analytics", "Ads"]),
            ({"category": "Analytics"}, "Analytics", ["Analytics"]),
            ({"categories": []}, "Unknown", []),
            ({}, "Unknown", []),
            ({"categories": "Ads"}, "Ads", ["Ads"]),
            ({"categories": [], "category": "Analytics"}, "Analytics", ["Analytics"]),
        ],
    )
    def test_parse_reads_the_categories_list(self, record, category, categories):
        """The Exodus API publishes ``categories`` (a list), not ``category``."""
        parsed = ExodusAPIClient._parse_trackers({"trackers": {"69": {"name": "Facebook Places", **record}}})
        assert parsed[0]["category"] == category
        assert parsed[0]["categories"] == categories

    def test_online_fetch_writes_cache(self, tmp_path):
        client = self._client(tmp_path)
        response = MagicMock()
        response.json.return_value = EXODUS_RESPONSE
        with patch(EXODUS_GET, return_value=response) as get:
            trackers = client.fetch_trackers()

        get.assert_called_once()
        assert trackers[0]["name"] == "Google Firebase Analytics"
        assert json.loads(client.cache_path.read_text()) == EXODUS_RESPONSE

    def test_fetch_failure_falls_back_to_cache(self, tmp_path):
        client = self._client(tmp_path)
        client.cache_path.parent.mkdir(parents=True)
        _write_json(client.cache_path, EXODUS_RESPONSE)
        with patch(EXODUS_GET, side_effect=requests.exceptions.ConnectionError("offline")):
            trackers = client.fetch_trackers()
        assert [t["id"] for t in trackers] == ["27"]

    def test_fetch_failure_without_cache_raises(self, tmp_path):
        client = self._client(tmp_path)
        with (
            patch(EXODUS_GET, side_effect=requests.exceptions.Timeout("slow")),
            pytest.raises(Exception, match="Failed to fetch"),
        ):
            client.fetch_trackers()

    def test_corrupt_cache_is_ignored(self, tmp_path):
        client = self._client(tmp_path)
        client.cache_path.parent.mkdir(parents=True)
        client.cache_path.write_text("{not json", encoding="utf-8")
        with (
            patch(EXODUS_GET, side_effect=requests.exceptions.ConnectionError("offline")),
            pytest.raises(Exception, match="Failed to fetch"),
        ):
            client.fetch_trackers()

    def test_empty_response_falls_back_to_cache(self, tmp_path):
        client = self._client(tmp_path)
        client.cache_path.parent.mkdir(parents=True)
        _write_json(client.cache_path, EXODUS_RESPONSE)
        response = MagicMock()
        response.json.return_value = {"trackers": {}}
        with patch(EXODUS_GET, return_value=response):
            trackers = client.fetch_trackers()
        assert [t["id"] for t in trackers] == ["27"]
        assert json.loads(client.cache_path.read_text()) == EXODUS_RESPONSE  # not overwritten

    def test_empty_response_without_cache_returns_nothing(self, tmp_path):
        client = self._client(tmp_path)
        response = MagicMock()
        response.json.return_value = {"trackers": {}}
        with patch(EXODUS_GET, return_value=response):
            assert client.fetch_trackers() == []
        assert not client.cache_path.exists()

    def test_malformed_cache_entries(self, tmp_path):
        client = self._client(tmp_path, exodus_offline=True)
        client.cache_path.parent.mkdir(parents=True)
        _write_json(client.cache_path, {"trackers": {"1": "not an object", **EXODUS_RESPONSE["trackers"]}})
        assert [t["id"] for t in client.fetch_trackers()] == ["27"]

        client = self._client(tmp_path, exodus_offline=True)
        _write_json(client.cache_path, {"trackers": {"1": ["nope"]}})
        with pytest.raises(Exception, match="run once online"):
            client.fetch_trackers()

    def test_cache_temp_file_is_host_unique(self, tmp_path):
        client = self._client(tmp_path)
        replaced = []
        real_replace = os.replace

        def record(src, dst):
            replaced.append(os.path.basename(src))
            real_replace(src, dst)

        with patch("os.replace", side_effect=record):
            client._write_disk_cache(EXODUS_RESPONSE)
        host = re.sub(r"[^A-Za-z0-9.-]", "_", socket.gethostname())
        assert re.fullmatch(rf"\.trackers\.json\.{re.escape(host)}\.{os.getpid()}\.[0-9a-f]{{32}}\.tmp", replaced[0])

    def test_offline_mode_uses_cache_only(self, tmp_path):
        client = self._client(tmp_path, exodus_offline=True)
        client.cache_path.parent.mkdir(parents=True)
        _write_json(client.cache_path, EXODUS_RESPONSE)
        with patch(EXODUS_GET) as get:
            trackers = client.fetch_trackers()
        get.assert_not_called()
        assert trackers[0]["code_signature"] == "com.google.firebase.analytics."

    def test_offline_mode_without_cache_never_fetches(self, tmp_path):
        client = self._client(tmp_path, exodus_offline=True)
        with patch(EXODUS_GET) as get, pytest.raises(Exception, match="run once online"):
            client.fetch_trackers()
        get.assert_not_called()


class TestProtectionDetection:
    def test_class_names_from_dex_strings(self):
        names = PatternDetector.class_names_from_dex_strings(
            ["Lcom/scottyab/rootbeer/RootBeer;", "[Lcom/foo/Bar;", "Lcom/x;", "Hello", "L;", "Lnot a class;"]
        )
        assert names == {"com.scottyab.rootbeer.RootBeer", "com.x"}

    def test_detects_by_class_and_native_lib(self):
        protections = TrackerDatabase().get_protections()
        detected = PatternDetector().detect_protections(
            protections,
            {"com.scottyab.rootbeer.RootBeer", "com.gantix.JailMonkey.JailMonkeyModule", "com.example.Main"},
            ["lib/arm64-v8a/libtoolChecker.so", "lib/arm64-v8a/libpairipcore.so", "lib/x86/libfoo.so"],
        )
        by_id = {p.id: p for p in detected}

        assert set(by_id) == {"rootbeer", "jailmonkey", "pairip"}
        assert by_id["rootbeer"].matched_classes == ["com.scottyab.rootbeer.RootBeer"]
        assert by_id["rootbeer"].matched_libs == ["lib/arm64-v8a/libtoolChecker.so"]
        assert by_id["rootbeer"].defeats == ["root"]
        assert by_id["rootbeer"].evidence == "entry_point"
        assert by_id["jailmonkey"].evidence == "sdk_present"
        assert by_id["pairip"].evidence == "sdk_present"
        assert by_id["pairip"].matched_classes == []
        assert by_id["pairip"].matched_libs == ["lib/arm64-v8a/libpairipcore.so"]
        assert by_id["jailmonkey"].confidence == "high"

    def test_integrity_sdks_need_an_entry_point(self):
        protections = TrackerDatabase().get_protections()
        detector = PatternDetector()
        # Bare packages pulled in by Firebase Auth / reCAPTCHA / Safe Browsing
        bare = {
            "com.google.android.play.core.integrity.IntegrityManager",
            "com.google.android.play.core.integrity.internal.Foo",
            "com.google.android.gms.safetynet.SafetyNetClient",
            "com.google.android.gms.safetynet.SafetyNetApi$RecaptchaTokenResponse",
        }
        assert detector.detect_protections(protections, bare, []) == []

        found = detector.detect_protections(
            protections,
            bare
            | {
                "com.google.android.play.core.integrity.StandardIntegrityManager$PrepareIntegrityTokenRequest",
                "com.google.android.gms.safetynet.SafetyNetApi$AttestationResponse",
            },
            [],
        )
        assert {(p.id, p.evidence) for p in found} == {
            ("play_integrity", "entry_point"),
            ("safetynet", "entry_point"),
        }

    def test_low_confidence_hits_are_logged_as_possible(self, tmp_path, caplog):
        apk = tmp_path / "app.apk"
        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("lib/arm64-v8a/libshield.so", b"")
        context = AnalysisContext(apk_path=str(apk), config={}, androguard_obj=None)
        module = TrackerAnalysisModule({"fetch_exodus_trackers": False})
        with caplog.at_level("INFO"):
            found = module._detect_protections(str(apk), context, [])
        assert [p.id for p in found] == ["promon_shield"]
        assert "Possible protection: Promon SHIELD" in caplog.text
        assert "Protection detected" not in caplog.text

    def test_class_signature_is_case_sensitive_prefix(self):
        protections = TrackerDatabase().get_protections()
        detected = PatternDetector().detect_protections(
            protections, {"com.gantix.jailmonkey.Other", "org.com.scottyab.rootbeer.X"}, []
        )
        assert detected == []

    def test_native_libs_from_apk(self, tmp_path):
        apk = tmp_path / "app.apk"
        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("classes.dex", b"")
            zf.writestr("lib/arm64-v8a/libshield.so", b"")
        assert PatternDetector.native_libs_from_apk(str(apk)) == ["lib/arm64-v8a/libshield.so"]
        assert PatternDetector.native_libs_from_apk(str(tmp_path / "missing.apk")) == []

    def test_module_reports_detected_protections(self, tmp_path):
        apk = tmp_path / "app.apk"
        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("lib/armeabi-v7a/libtoolChecker.so", b"")

        dex = MagicMock()
        dex.get_strings.return_value = [
            "Lcom/scottyab/rootbeer/RootBeer;",
            "Lcom/google/android/play/core/integrity/IntegrityManagerFactory;",
        ]
        androguard_obj = MagicMock()
        androguard_obj.get_androguard_dex.return_value = [dex]
        context = AnalysisContext(apk_path=str(apk), config={}, androguard_obj=androguard_obj)

        module = TrackerAnalysisModule({"fetch_exodus_trackers": False})
        result = module.analyze(str(apk), context)

        assert result.status == AnalysisStatus.SUCCESS
        result_dict = result.to_dict()
        found = {p["id"]: p for p in result_dict["detected_protections"]}
        assert set(found) == {"rootbeer", "play_integrity"}
        assert found["rootbeer"]["matched_libs"] == ["lib/armeabi-v7a/libtoolChecker.so"]
        assert found["play_integrity"]["defeats"] == ["integrity"]
        assert found["play_integrity"]["evidence"] == "entry_point"
        assert found["rootbeer"]["evidence"] == "entry_point"

        exported = TrackerAnalysisResults(result).export_to_dict()
        assert exported["detected_protections"] == result_dict["detected_protections"]
