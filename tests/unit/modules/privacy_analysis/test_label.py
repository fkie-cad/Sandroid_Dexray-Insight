# SPDX-License-Identifier: GPL-3.0-only
"""Confidence, rows, sharing, SDK flags, consent and findings (04-design §2.8-§2.11)."""

import copy

import pytest

from dexray_insight.modules.privacy_analysis import label as lab
from dexray_insight.modules.privacy_analysis.module import analyse
from dexray_insight.privacy.catalogue import load_catalogue

from .fakes import CATALOGUE_MIN
from .fakes import FakeIndex
from .fakes import scooter_scenario

APP_HIGH = {"type": "app", "confidence": "high"}
SDK_HIGH = {"type": "sdk", "confidence": "high"}


@pytest.fixture(scope="module")
def cat():
    return load_catalogue(CATALOGUE_MIN)


@pytest.fixture(scope="module")
def base():
    return scooter_scenario()


def run(cat, x, man, trackers=()):
    section = analyse(x, man, cat, {}, list(trackers))
    assert section["status"] == "success", section["errors"]
    return section


def row(section, dt):
    return next((r for r in section["data_safety"]["rows"] if r["data_type"] == dt), None)


def finding(section, fid):
    return next((f for f in section["findings"] if f["id"] == fid), None)


# ------------------------------------------------------------ confidence table
@pytest.mark.parametrize(
    "kind,precision,uri,refl,expected",
    [
        ("content_uri", "high", "high", None, "high"),
        ("content_uri", "high", "medium", None, "medium"),
        ("api_call_site", "medium", None, None, "medium"),
        ("reflective_reference", "high", None, "medium", "medium"),
        ("reflective_reference", "high", None, "low", "low"),
        ("sdk_sink_call", "high", None, None, "medium"),
        ("api_ineffective", "high", None, None, "low"),
        ("api_call_site_no_caller", "high", None, None, "low"),
    ],
)
def test_base_confidence(kind, precision, uri, refl, expected):
    assert lab.base_confidence(kind, precision, uri, refl) == expected


def test_modifiers_in_order():
    assert lab.apply_modifiers("high", "api_call_site", APP_HIGH, True, "app_code") == "high"
    assert lab.apply_modifiers("high", "api_call_site", SDK_HIGH, True, "app_code") == "medium"  # cap
    assert (
        lab.apply_modifiers("high", "api_call_site", {"type": "app", "confidence": "medium"}, None, "app_code")
        == "medium"
    )
    assert lab.apply_modifiers("high", "api_call_site", SDK_HIGH, False, "app_code") == "low"  # cap + permission
    assert lab.apply_modifiers("high", "api_call_site", APP_HIGH, True, "app_code", False) == "medium"  # type perm
    assert lab.apply_modifiers("high", "api_call_site", APP_HIGH, True, "unknown") == "medium"
    assert lab.apply_modifiers("high", "api_call_site", APP_HIGH, False, "unknown", False) == "low"  # floor
    assert lab.apply_modifiers("high", "api_ineffective", APP_HIGH, True, "app_code") == "low"


def test_evidence_kind_precedence():
    assert lab.evidence_kind_of("source", "provider_read", False, "no_caller_found") == "api_ineffective"
    assert lab.evidence_kind_of("source", "provider_read", True, "no_caller_found") == "api_call_site_no_caller"
    assert lab.evidence_kind_of("source", "provider_read", True, "app_code") == "content_uri"
    assert lab.evidence_kind_of("source", "reflective", True, "callback") == "reflective_reference"
    assert lab.evidence_kind_of("sink", "method_call", True, "unknown") == "sdk_sink_call"
    assert lab.evidence_kind_of("source", "field_read", True, "not_checked") == "api_call_site"
    assert lab.evidence_kind_of("consent_control", "method_call", True, "app_code") is None


def test_permission_and_api_level_objects():
    assert lab.permission_object(None, {"a"}) == {"required": None, "declared": [], "satisfied": None}
    assert lab.permission_object({"all_of": ["a", "b"]}, {"a"})["satisfied"] is False
    assert lab.permission_object({"all_of": ["a", "b"]}, {"a", "b"})["satisfied"] is True
    assert lab.permission_object({"any_of": ["b", "a"]}, {"a"})["declared"] == ["a"]
    lvl = lab.api_level_object({"since": 1, "effective_until": 29}, 29)
    assert lvl["effective_for_app"] is False
    assert lab.api_level_object({"effective_until": 29}, None)["effective_for_app"] is True


# ----------------------------------------------------------------- the rows
def test_fixture_rows_status_and_hidden(cat, base):
    section = run(cat, *base)
    assert row(section, "location.approx_location")["status"] == "likely_collected"
    assert row(section, "contacts.contacts")["status"] == "may_be_collected"
    photos = row(section, "photo_video.photos")
    assert (photos["status"], photos["hidden_by_default"]) == ("possible", True)
    ids = row(section, "identifiers.other")
    assert [e["kind"] for e in ids["evidence"]] == [
        "sdk_auto_collects",
        "sdk_auto_collects",
        "api_call_site",
        "api_call_site",
        "reflective_reference",
        "api_ineffective",
        "sdk_configured_off",
        "permission_declared",
    ]


def test_medium_sdk_never_likely(cat, base):
    x, man, trackers = copy.deepcopy(base)
    # drop every AdMob anchor: class prefix only -> medium -> sdk_present (low)
    man.components = [c for c in man.components if "gms.ads" not in c["name"]]
    man.meta_data = [d for d in man.meta_data if "gms.ads" not in d["name"]]
    section = run(cat, x, man, trackers)
    admob = next(s for s in section["sdks"] if s["id"] == "google_mobile_ads")
    assert admob["confidence"] == "medium"
    diag = row(section, "app_performance.performance_diagnostics")
    assert diag["status"] == "possible" and diag["hidden_by_default"] is True
    assert [e["kind"] for e in diag["evidence"]] == ["sdk_present"]


def test_tracker_analysis_alone_detects_nothing(cat):
    section = run(cat, FakeIndex(), scooter_scenario()[1].__class__(package="a.b"), ["Google AdMob"])
    assert section["sdks"] == []


def test_switched_off_row_stays_visible_and_findings_unaffected(cat, base):
    x, man, trackers = copy.deepcopy(base)
    # without the app consent control, the Firebase flag means "configured_off"
    del x.methods[next(k for k in x.methods if k.name == "onConsent")]
    x.calls = [c for c in x.calls if c[0].name != "onConsent" and c[1].name != "onConsent"]
    section = run(cat, x, man, trackers)
    fa = next(s for s in section["sdks"] if s["id"] == "firebase_analytics")
    assert [c["status"] for c in fa["collects"]] == ["configured_off", "configured_off"]
    ui = row(section, "actions_in_app.user_interaction")
    assert ui["hidden_by_default"] is False
    assert any(e["kind"] == "sdk_configured_off" for e in ui["evidence"])
    assert section["consent"]["controls"] == []
    assert finding(section, "sdk_sink_with_app_data") is not None


def test_switched_off_in_manifest_status(cat):
    rows = lab.build_rows(
        cat,
        [],
        {},
        [{"id": "s", "role": "analytics", "collects": [], "sharing_override": None}],
        [
            {
                "data_type": "identifiers.other",
                "kind": "sdk_configured_off",
                "confidence": "low",
                "source": "manifest:k",
                "sdk_id": "s",
            }
        ],
        {},
    )
    assert rows[0]["status"] == "switched_off_in_manifest" and rows[0]["hidden_by_default"] is False


def test_flag_coverage_by_item():
    flags = [
        {
            "sdk_id": "s",
            "state": "off",
            "data_types": ["identifiers.other"],
            "items": ["advertising_id"],
            "effect": "adid_collection_off",
            "key": "k",
            "value": "false",
        }
    ]
    assert (
        lab.collects_status("s", {"data_type": "identifiers.other", "item": "advertising_id"}, flags, False)[0]
        == "configured_off"
    )
    assert lab.collects_status("s", {"data_type": "identifiers.other", "item": "other"}, flags, False)[0] == "active"
    assert lab.collects_status("s", {"data_type": "identifiers.other", "item": None}, flags, False)[0] == "active"
    suspended = [{**flags[0], "effect": "collection_suspended_until_enabled", "data_types": ["*"], "items": None}]
    assert lab.collects_status("s", {"data_type": "x.y", "item": None}, suspended, True)[0] == "runtime_controlled"
    assert lab.collects_status("s", {"data_type": "x.y", "item": None}, suspended, False)[0] == "configured_off"
    permanent = [{**suspended[0], "effect": "collection_off_permanently"}]
    assert lab.collects_status("s", {"data_type": "x.y", "item": None}, permanent, True)[0] == "configured_off"
    assert lab.collects_status("s", {"data_type": "x.y", "item": None}, [], True)[0] == "runtime_controlled"


def test_sharing_sink_sdk_and_meta_override(cat):
    sdks = [
        {"id": "meta_app_events", "role": "analytics", "collects": [], "sharing_override": "possible_sharing"},
        {"id": "fa", "role": "analytics", "collects": [], "sharing_override": None},
    ]
    sink = {
        "id": "cs-0001",
        "api_id": "sink.x",
        "evidence_kind": "sdk_sink_call",
        "data_types": ["personal.personal_identifiers"],
        "origin": {"type": "app", "sdk_id": None, "name": None, "confidence": "high"},
    }
    meta = {"cs-0001": {"type_conf": {"personal.personal_identifiers": "medium"}, "sdk_id": "meta_app_events"}}
    [r] = lab.build_rows(cat, [sink], meta, sdks, [], {})
    assert r["sharing_hint"]["value"] == "possible_sharing"
    assert r["sharing_hint"]["sdk_ids"] == ["meta_app_events"]
    assert r["sharing_hint"]["confidence"] == "medium"  # call-site evidence >= medium
    assert r["purpose_hints"] == ["analytics"]
    meta["cs-0001"]["sdk_id"] = "fa"
    [r] = lab.build_rows(cat, [sink], meta, sdks, [], {})
    assert (r["sharing_hint"]["value"], r["sharing_hint"]["confidence"]) == ("service_provider_likely", "low")


def test_hidden_rule_with_unsatisfied_dangerous_permission(cat):
    site = {
        "id": "cs-0001",
        "api_id": "loc.lm.last_known",
        "evidence_kind": "api_call_site",
        "data_types": ["location.precise_location"],
        "origin": {"type": "library", "sdk_id": None, "name": "androidx", "confidence": "medium"},
    }
    meta = {"cs-0001": {"type_conf": {"location.precise_location": "low"}, "dangerous_unsatisfied": True}}
    [r] = lab.build_rows(cat, [site], meta, [], [], {})
    assert (r["status"], r["confidence"], r["hidden_by_default"]) == ("possible", "low", True)
    meta["cs-0001"]["dangerous_unsatisfied"] = False
    assert lab.build_rows(cat, [site], meta, [], [], {})[0]["hidden_by_default"] is False


def test_origins_order(cat, base):
    section = run(cat, *base)
    assert [(o["type"], o["sdk_id"], o["call_site_count"]) for o in row(section, "identifiers.other")["origins"]] == [
        ("sdk", "adjust", 2),
        ("sdk", "braze", 1),
        ("unattributed", None, 1),
    ]


# ----------------------------------------------------------------- consent
@pytest.mark.parametrize(
    "cmps,writes,reads,roles,expected",
    [
        ([{"id": "x"}], True, True, ["ads"], "cmp_detected"),
        ([], True, False, ["ads"], "tcf_writer_without_known_cmp"),
        ([], False, True, ["ads"], "tcf_reader_only"),
        ([], False, False, ["analytics"], "none_detected"),
        ([], False, False, ["crash"], "not_applicable"),
    ],
)
def test_consent_verdicts(cmps, writes, reads, roles, expected):
    channels = {"tcf": {"writes": writes, "reads": reads}, "gpp": {"writes": False, "reads": False}}
    assert lab.consent_verdict(cmps, channels, [{"role": r} for r in roles]) == expected


def test_cmp_detection_suppresses_consent_findings(cat, base):
    x, man, trackers = copy.deepcopy(base)
    x.add("Lcom/google/android/ump/UserMessagingPlatform;->load()V")
    section = run(cat, x, man, trackers)
    assert section["consent"]["verdict"] == "cmp_detected"
    assert section["consent"]["cmps"][0]["id"] == "google_ump"
    assert section["consent"]["cmps"][0]["confidence"] == "high"
    assert finding(section, "no_consent_mechanism") is None
    assert finding(section, "sdk_identifier_access_without_consent") is None


def test_tcf_writer_suppresses_no_consent(cat, base):
    x, man, trackers = copy.deepcopy(base)
    put = (
        "Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)"
        "Landroid/content/SharedPreferences$Editor;"
    )
    x.add("Lcom/example/scooter/consent/Own;->save()V", strings=["IABTCF_TCString"], invokes=[(put, 4)])
    section = run(cat, x, man, trackers)
    assert section["consent"]["verdict"] == "tcf_writer_without_known_cmp"
    assert section["consent"]["tcf"]["writers"] == [
        {"origin": {"type": "app", "sdk_id": None, "name": None}, "count": 1}
    ]
    assert finding(section, "no_consent_mechanism") is None


# ----------------------------------------------------------------- findings
def test_fixture_findings(cat, base):
    section = run(cat, *base)
    assert [f["id"] for f in section["findings"]] == [
        "no_consent_mechanism",
        "sdk_identifier_access_without_consent",
        "non_resettable_identifier",
        "sdk_collection_default_on",
        "sdk_sink_with_app_data",
    ]
    nri = finding(section, "non_resettable_identifier")
    assert nri["evidence"]["call_site_ids"] == ["cs-0003"]  # the unsatisfied IMEI site is excluded
    assert "One more site" in nri["summary"]


def test_identifier_access_needs_reachability(cat, base):
    x, man, trackers = copy.deepcopy(base)
    x.calls = [c for c in x.calls if c[0].name != "getGoogleAdId"]  # cut the reflective chain
    section = run(cat, x, man, trackers)
    site = next(s for s in section["call_sites"] if s["api_id"] == "ids.gms.advertising_id")
    assert site["reachability"] == "no_caller_found"
    assert finding(section, "sdk_identifier_access_without_consent") is None


def test_non_resettable_needs_an_included_site(cat, base):
    x, man, trackers = copy.deepcopy(base)
    x.calls = [c for c in x.calls if c[0].cls != "Lbo/app/bj;"]
    assert finding(run(cat, x, man, trackers), "non_resettable_identifier") is None


def test_permission_without_call_site(cat, base):
    x, man, trackers = copy.deepcopy(base)
    man.permission_entries.append(
        {"name": "android.permission.READ_CALENDAR", "tag": "uses-permission", "max_sdk_version": None}
    )
    f = finding(run(cat, x, man, trackers), "permission_without_call_site")
    assert f["evidence"]["permissions"] == ["android.permission.READ_CALENDAR"]
    assert f["evidence"]["data_types"] == ["calendar.calendar"]
    # suppressed for code outside DEX (Flutter) ...
    man.files.append("lib/arm64-v8a/libflutter.so")
    section = run(cat, x, man, trackers)
    assert section["coverage"]["code_outside_dex"] == ["flutter"]
    assert finding(section, "permission_without_call_site") is None


def test_permission_without_call_site_suppressed_for_heavy_obfuscation(cat):
    from dexray_insight.modules.privacy_analysis.module import ManifestFacts

    x = FakeIndex()
    x.classes.update({f"Lq/{i:03d};" for i in range(10)})
    man = ManifestFacts(
        package="a.b",
        permission_entries=[
            {"name": "android.permission.READ_CALENDAR", "tag": "uses-permission", "max_sdk_version": None}
        ],
    )
    section = run(cat, x, man)
    assert section["coverage"]["obfuscation_level"] == "heavy"
    assert finding(section, "permission_without_call_site") is None


@pytest.mark.parametrize(
    "perm,max_sdk,picker,fires",
    [
        ("android.permission.READ_MEDIA_IMAGES", None, False, True),
        ("android.permission.READ_EXTERNAL_STORAGE", None, False, True),
        ("android.permission.READ_EXTERNAL_STORAGE", 32, False, False),
        ("android.permission.READ_MEDIA_IMAGES", None, True, False),
    ],
)
def test_broad_media_access(cat, perm, max_sdk, picker, fires):
    from dexray_insight.modules.privacy_analysis.module import ManifestFacts

    x = FakeIndex()
    if picker:
        x.add(
            "Lcom/a/b/Pick;->go()V",
            classes=["Landroidx/activity/result/contract/ActivityResultContracts$PickVisualMedia;"],
        )
    # androidx's own reference never counts
    x.add("Landroidx/activity/result/X;->y()V", strings=["android.provider.action.PICK_IMAGES"])
    man = ManifestFacts(
        package="com.a.b",
        min_sdk=21,
        permission_entries=[{"name": perm, "tag": "uses-permission", "max_sdk_version": max_sdk}],
    )
    assert (finding(run(cat, x, man), "broad_media_access") is not None) is fires


def test_join_words():
    assert lab.join_words(["a"]) == "a"
    assert lab.join_words(["a", "b"]) == "a and b"
    assert lab.join_words(["a", "b", "c"]) == "a, b and c"


def test_admob_tracker_id_without_anchor_never_detects(cat):
    """VOI shape: only the ads-identifier library (excluded prefix) plus a tracker_analysis hit."""
    from dexray_insight.modules.privacy_analysis.module import ManifestFacts

    x = FakeIndex()
    x.classes.update({f"Lcom/google/android/gms/ads/identifier/C{i};" for i in range(6)})
    x.add(
        "Lcom/google/android/gms/ads/identifier/AdvertisingIdClient;->getAdvertisingIdInfo()V",
        strings=["com.google.android.gms.ads.identifier.internal.IAdvertisingIdService"],
    )
    section = run(cat, x, ManifestFacts(package="io.voiapp.voi"), ["Google AdMob", "Google DoubleClick"])
    assert "google_mobile_ads" not in {s["id"] for s in section["sdks"]}
    assert section["consent"]["verdict"] == "not_applicable"
