#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Tests for the shared signature database (loader, overrides, network labels)."""

import json

import pytest

from dexray_insight.modules.tracker_analysis.databases.tracker_database import ENTRY_KINDS
from dexray_insight.modules.tracker_analysis.databases.tracker_database import PROTECTION_DEFEATS
from dexray_insight.modules.tracker_analysis.databases.tracker_database import TrackerDatabase
from dexray_insight.modules.tracker_analysis.databases.tracker_database import label_for_domain
from dexray_insight.modules.tracker_analysis.databases.tracker_database import load_signature_db
from dexray_insight.modules.tracker_analysis.tracker_analysis_module import TrackerAnalysisModule


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
                assert entry.get("code_signature") or entry.get("native_libs"), entry_id

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
            ("config.unity3d.com", ("Unity Ads", "unity_ads")),
            ("APPSFLYER.COM.", ("AppsFlyer", "appsflyer")),
            ("sentry.io:443", ("Sentry", "sentry")),
        ],
    )
    def test_most_specific_suffix_wins(self, host, expected):
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

    def test_sandroid_recipient_parity(self):
        """Every domain of Sandroid's former recipient list keeps its label."""
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
            "unity3d.com": "Unity Ads",
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
