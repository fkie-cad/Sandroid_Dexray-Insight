# SPDX-License-Identifier: GPL-3.0-only
"""Static privacy layer on real APKs (04-design §6.2, §6.3).

exampleapp is in the repository. The other APKs are not: point the tests at them with
environment variables and they skip when an APK is missing.

* ``DEXRAY_PRIVACY_CORPUS``: a directory holding the corpus APKs under the file names
  below (``CORPUS_FILES``);
* ``DEXRAY_PRIVACY_APK_<NAME>`` (``VOI``, ``SPIN``, ``NEXTCLOUD``, ``WIKIPEDIA``,
  ``GROK``, ``SUNRISE``): the path of one APK, which wins over the directory.

The exampleapp golden projection is rewritten with ``--update-privacy-golden`` (review
the diff by hand).
"""

import json
import os
from functools import lru_cache
from pathlib import Path

import pytest

from dexray_insight.privacy.catalogue import DATA_DIR

ROOT = Path(__file__).resolve().parents[2]
EXAMPLEAPP = ROOT / "example_samples" / "exampleapp-release.apk"
GOLDEN = ROOT / "tests" / "fixtures" / "privacy" / "exampleapp_expected.json"
#: File names of the corpus APKs (as downloaded) inside ``DEXRAY_PRIVACY_CORPUS``.
CORPUS_FILES = {
    "VOI": "VOI Scooters Get Magic Wheels_v2.24.2_apkpure.com.apk",
    "SPIN": "Spin Electric Scooters_v2.21.0_apkpure.com.apk",
    "NEXTCLOUD": "Nextcloud_3.31.1_APKPure.apk",
    "WIKIPEDIA": "org.wikipedia_50616.apk",
    "GROK": "ai.x.grok.apk",
    "SUNRISE": "Sunrise Resorts And Cruises_1.0.0_APKPure.apk",
}


def corpus_apk(name: str) -> Path:
    """Where the corpus APK ``name`` is configured (it may not exist)."""
    explicit = os.environ.get(f"DEXRAY_PRIVACY_APK_{name}")
    if explicit:
        return Path(explicit).expanduser()
    base = os.environ.get("DEXRAY_PRIVACY_CORPUS")
    return Path(base).expanduser() / CORPUS_FILES[name] if base else Path("/nonexistent") / CORPUS_FILES[name]


VOI = corpus_apk("VOI")
SPIN = corpus_apk("SPIN")
NEXTCLOUD = corpus_apk("NEXTCLOUD")
WIKIPEDIA = corpus_apk("WIKIPEDIA")
GROK = corpus_apk("GROK")
SUNRISE = corpus_apk("SUNRISE")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not (DATA_DIR / "apis.yaml").exists(), reason="bundled catalogue not present"),
]


@lru_cache(maxsize=4)
def section_for(apk: str, trackers: tuple[str, ...] = ()) -> dict:
    from androguard.misc import AnalyzeAPK
    from loguru import logger

    from dexray_insight.modules.privacy_analysis.module import ManifestFacts
    from dexray_insight.modules.privacy_analysis.module import analyse
    from dexray_insight.modules.privacy_analysis.scanner import AndroguardIndex
    from dexray_insight.privacy.catalogue import load_catalogue

    logger.remove()
    a, d, dx = AnalyzeAPK(apk)
    return analyse(AndroguardIndex(dx, d), ManifestFacts.from_apk(a), load_catalogue(), {}, list(trackers))


def projection(section: dict) -> dict:
    """The golden projection of §6.2."""
    return {
        "rows": [
            [r["data_type"], r["status"], r["confidence"], sorted({o["type"] for o in r["origins"]})]
            for r in section["data_safety"]["rows"]
        ],
        "sdks": [[s["id"], s["confidence"]] for s in section["sdks"]],
        "consent_verdict": section["consent"]["verdict"],
        "findings": [f["id"] for f in section["findings"]],
        "call_site_count": len(section["call_sites"]),
    }


def need(path: Path) -> str:
    if not path.exists():
        pytest.skip(f"{path.name} not available (set DEXRAY_PRIVACY_CORPUS or DEXRAY_PRIVACY_APK_*)")
    return str(path)


# ------------------------------------------------------------------ exampleapp
def test_exampleapp_golden(request):
    section = section_for(need(EXAMPLEAPP))
    assert section["status"] == "success", section["errors"]
    got = projection(section)
    if request.config.getoption("--update-privacy-golden"):
        GOLDEN.write_text(json.dumps(got, indent=2) + "\n")
    assert got == json.loads(GOLDEN.read_text())


def test_exampleapp_known_facts():
    section = section_for(need(EXAMPLEAPP))
    sites = section["call_sites"]
    # NotificationManagerCompat reads Settings.Secure without "android_id": no site
    assert not [s for s in sites if s["api_id"] == "ids.settings.android_id"]
    [twilight] = [s for s in sites if s["caller"]["class"] == "Landroidx/appcompat/app/TwilightManager;"]
    assert (twilight["origin"]["type"], twilight["origin"]["name"]) == ("library", "androidx.appcompat.app")
    assert twilight["permission"]["satisfied"] is False
    # the search passes AppCompat's internal base method instead of stopping at "no caller found"
    assert twilight["reachability"] != "no_caller_found"
    for dt in twilight["data_types"]:
        row = next(r for r in section["data_safety"]["rows"] if r["data_type"] == dt)
        assert row["hidden_by_default"] is True
    assert all(s["origin"]["type"] != "app" for s in sites if not s["caller"]["class"].startswith("Lcom/example/"))


def test_exampleapp_through_the_engine(tmp_path):
    """The full pipeline puts the section into the main JSON."""
    from dexray_insight import asam

    cfg = asam.Configuration(
        config_dict={
            "caching": {"cache_dir": str(tmp_path / "cache")},
            "security": {"enable_owasp_assessment": False},
            "temporal_analysis": {"base_directory": str(tmp_path / "work")},
            "modules": {"tracker_analysis": {"exodus_offline": True}},
            "logging": {"level": "WARNING"},
        },
        profile="privacy",
    )
    results, main_file, _ = asam.start_apk_static_analysis_new(
        need(EXAMPLEAPP), cfg, print_results_to_terminal=False, output_dir=str(tmp_path)
    )
    main = json.loads(Path(main_file).read_text())
    assert main["privacy_analysis"]["schema_version"] == 1
    assert main["privacy_analysis"]["status"] == "success"
    assert projection(main["privacy_analysis"]) == json.loads(GOLDEN.read_text())


# ------------------------------------------------------------------------- VOI
VOI_TRACKERS = ("Firebase Crashlytics", "Google AdMob", "Google DoubleClick", "Google Firebase Analytics")


@pytest.fixture(scope="module")
def voi():
    return section_for(need(VOI), VOI_TRACKERS)


def test_voi_rows_and_sdks(voi):
    assert voi["status"] == "success", voi["errors"]
    types = {r["data_type"] for r in voi["data_safety"]["rows"]}
    # contacts.contacts (design §6.3) is gone on purpose: both VOI contact reads had URI evidence only
    # elsewhere in the class (Glide/Picasso generic loaders), which no longer types a site.
    assert {"identifiers.other", "location.precise_location"} <= types
    sdks = {s["id"]: s for s in voi["sdks"]}
    assert sdks["adjust"]["confidence"] == "high"
    assert any(d["value"] == "com.appboy." for d in sdks["braze"]["detection"])
    assert "fabric_crashlytics" in sdks


def test_voi_admob_not_detected(voi):
    """tracker_analysis reports AdMob (from the ads-identifier string) but that alone never detects it."""
    assert "google_mobile_ads" not in {s["id"] for s in voi["sdks"]}
    for row in voi["data_safety"]["rows"]:
        assert "google_mobile_ads" not in row["sdks_collecting"]
        if row["status"] == "likely_collected":
            assert all(e.get("sdk_id") != "google_mobile_ads" for e in row["evidence"])


def test_voi_no_app_origin_on_sdk_code(voi):
    foreign = (
        "Lzendesk/",
        "Lno/nordicsemi/",
        "Lcom/mapbox/",
        "Lcom/appboy/",
        "Lcom/stripe/",
        "Lcom/braintreepayments/",
        "Lq/a/a/a/a/",
    )
    for site in voi["call_sites"]:
        if site["caller"]["class"].startswith(foreign):
            assert site["origin"]["type"] != "app", site
    mac = [s for s in voi["call_sites"] if s["caller"]["class"] == "Lcom/adjust/sdk/MacAddressUtil;"]
    assert mac and all(s["origin"]["sdk_id"] == "adjust" for s in mac)


def test_voi_consent(voi):
    assert voi["consent"]["verdict"] == "none_detected"
    finding = next(f for f in voi["findings"] if f["id"] == "no_consent_mechanism")
    assert "adjust" in finding["evidence"]["sdk_ids"]


def test_voi_build_serial_field_read(voi):
    """Review-2 B1: field reads work on real androguard (Magnes reads Build.SERIAL)."""
    serial = [s for s in voi["call_sites"] if s["api_id"] == "ids.build.serial_field"]
    assert [(s["caller"]["class"], s["caller"]["method"]) for s in serial] == [("Lq/a/a/a/a/i;", "a")]
    assert serial[0]["match"] == "field_read"
    # renamed Magnes code is placed by its own strings (magnes_guid, c.paypal.com ...), never as the app
    assert (serial[0]["origin"]["sdk_id"], serial[0]["origin"]["rule"]) == ("paypal_magnes", "string_anchor")


def test_voi_no_feature_conditional_or_self_call_overclaims(voi):
    rows = {r["data_type"]: r for r in voi["data_safety"]["rows"]}
    # Analytics' in-app purchase events need Play Billing, which VOI does not have
    assert rows["financial.purchase_history"]["status"] != "likely_collected"
    # GoogleSignInAccount calling its own getters is not a data access (SDK documentation of
    # depends-on-usage items may still list the types, as low "sdk_present" evidence)
    for dt in ("personal.name", "personal.email_address"):
        assert dt not in rows or {e["kind"] for e in rows[dt]["evidence"]} <= {"sdk_present", "permission_declared"}
    flags = {(f["key"], f["sdk_id"]): f for f in voi["manifest_flags"]}
    assert flags[("firebase_crashlytics_collection_enabled", "fabric_crashlytics")]["state"] == "on"


def test_voi_renamed_set_user_id_is_noted(voi):
    notes = " ".join(voi["coverage"]["notes"])
    assert "removed or renamed by R8" in notes and "sink.firebase.set_user_id" in notes


# -------------------------------------------------------------------- others
def test_wikipedia_app_sites_are_app_code():
    section = section_for(need(WIKIPEDIA))
    app = [s for s in section["call_sites"] if s["origin"]["type"] == "app"]
    assert len(app) >= 5
    for site in app:
        assert site["caller"]["class"].startswith("Lorg/wikipedia/"), site
        assert not site["origin"]["via"], site  # never reached through androidx internals
    ads = {s["id"] for s in section["sdks"] if s["role"] in ("ads", "attribution")}
    for row in section["data_safety"]["rows"]:
        if row["status"] == "likely_collected":
            assert not {e.get("sdk_id") for e in row["evidence"] if e["kind"] == "sdk_auto_collects"} & ads


def test_nextcloud_provider_reads_and_namespace():
    section = section_for(need(NEXTCLOUD))
    prov = [s for s in section["call_sites"] if s["match"] == "provider_read"]
    assert prov and all(s["uri_evidence"]["where"] in ("same_method", "caller") for s in prov)  # never same_class
    # own-provider queries next to MediaStore inserts/deletes no longer type audio rows
    types = {r["data_type"]: r for r in section["data_safety"]["rows"]}
    for dt in ("audio.sound_recordings", "audio.music_files"):
        assert dt not in types or types[dt]["status"] == "possible"
    assert "com.nextcloud" in section["app"]["app_namespaces"]
    for site in section["call_sites"]:
        if site["caller"]["class"].startswith(("Lcom/nextcloud/utils/", "Lcom/nextcloud/ui/")):
            assert site["origin"]["type"] == "app", site


def test_spin_runs():
    section = section_for(need(SPIN))
    assert section["status"] == "success", section["errors"]
    serial = {s["caller"]["class"] for s in section["call_sites"] if s["api_id"] == "ids.build.serial_field"}
    assert len(serial) >= 5  # stripe3ds2, RN AndroidInfoModule, onfido, dyneti, RNDeviceInfo
    rows = {r["data_type"]: r for r in section["data_safety"]["rows"]}
    assert rows.get("financial.purchase_history", {}).get("status") != "likely_collected"
    self_calls = [
        s for s in section["call_sites"] if s["caller"]["class"].startswith("Lcom/google/android/gms/auth/api/signin/")
    ]
    assert self_calls == []


def test_wikipedia_appcompat_location_is_not_app():
    section = section_for(need(WIKIPEDIA))
    for site in section["call_sites"]:
        if site["api_id"] == "loc.lm.last_known" and site["origin"]["type"] == "app":
            assert not site["origin"]["via"], site  # no app origin through AppCompat internals


def _prov(section, cls, method):
    return sorted(
        (s["api_id"], s["uri_evidence"]["where"])
        for s in section["call_sites"]
        if s["match"] == "provider_read" and s["caller"]["class"] == cls and s["caller"]["method"] == method
    )


def test_nextcloud_recovered_provider_reads():
    """Constants, the VCard URIs and one level of caller evidence recover true reads (08-precision re-run)."""
    section = section_for(need(NEXTCLOUD))
    # Contacts.CONTENT_VCARD_URI (newly catalogued), inside Uri.withAppendedPath
    for cls in ("Lcom/nextcloud/client/jobs/ContactsBackupWork;", "Lcom/nextcloud/client/jobs/ContactsImportWork;"):
        assert _prov(section, cls, "getContactFromCursor") == [("prov.contacts", "same_method")]
    # static final Uri IMAGES_MEDIA_URI = MediaStore.Images.Media.EXTERNAL_CONTENT_URI, read in the method
    assert ("prov.media_images", "same_method") in _prov(
        section, "Lcom/owncloud/android/datamodel/MediaProvider;", "getImageFolders"
    )
    # insertContentIntoDB(Uri, ...) queries its parameter; the caller passes the MediaStore URIs
    assert _prov(section, "Lcom/owncloud/android/utils/FilesSyncHelper;", "insertAllDBEntriesForSyncedFolder") == [
        ("prov.media_images", "caller"),
        ("prov.media_images", "caller"),
        ("prov.media_video", "caller"),
        ("prov.media_video", "caller"),
    ]
    # FileDataStorageManager's own-provider queries stay untyped
    assert not _prov(
        section, "Lcom/owncloud/android/datamodel/FileDataStorageManager;", "getCapabilityCursorForAccount"
    )


def test_spin_branch_alternatives_reach_the_caller():
    """imagepicker getRealPathFromURI picks Images/Video/Audio in branches, then calls getDataColumn(uri)."""
    section = section_for(need(SPIN))
    assert _prov(section, "Lcom/imagepicker/utils/RealPathUtil;", "getRealPathFromURI") == [
        ("prov.media_audio", "caller"),
        ("prov.media_images", "caller"),
        ("prov.media_video", "caller"),
    ]


# ------------------------------------------------------ assessment follow-up
def test_voi_r8_attribution(voi):
    """10-assessment W1: VOI's own renamed code and renamed SDK code get owners."""
    by_class = {}
    for site in voi["call_sites"]:
        by_class.setdefault(site["caller"]["class"], site["origin"])
    # c.a.a.* is VOI's repackaged code: LogaryService.kt, CameraSource, UserInfoRepository.kt
    for cls in ("Lc/a/a/x0/l;", "Lc/a/a/j0/b;", "Lc/a/a/z0/f$a;"):
        assert (by_class[cls]["type"], by_class[cls]["rule"], by_class[cls]["confidence"]) == (
            "app",
            "app_reference",
            "medium",
        ), cls
    # SourceFile names: OneSignal.java (m.k.f1), PayPalDataCollector.java
    assert (by_class["Lm/k/f1;"]["sdk_id"], by_class["Lm/k/f1;"]["rule"]) == ("onesignal", "source_file")
    assert by_class["Lm/m/a/a/a/a/a;"]["sdk_id"] == "paypal_magnes"
    for origin in by_class.values():
        assert origin["confidence"] != "high" or origin["rule"] in ("sdk_prefix", "app_namespace")
    sink = [s for s in voi["call_sites"] if s["api_id"] == "sink.braze.change_user"]
    assert sink and all(s["origin"]["type"] == "app" for s in sink)
    assert "sdk_sink_with_app_data" in {f["id"] for f in voi["findings"]}


def test_spin_bridge_entries():
    """10-assessment B W1: @ReactMethod modules are entry points, not dead code."""
    section = section_for(need(SPIN))
    bridged = [s for s in section["call_sites"] if s["reachability"] == "bridge_entry"]
    assert len(bridged) >= 20 and all(s["bridge"]["kind"] == "react_native" for s in bridged)
    assert all(s["bridge"]["name_in_bundle"] is not False for s in bridged)  # None: name too short to search
    serial = [s for s in bridged if s["caller"]["method"] == "getSerialNumberSync"]
    assert serial  # the Hermes bundle names it
    # getUniqueIdSync is absent from the Hermes bundle: no JS caller, so no bridge entry (12-verify)
    unique_id = [s for s in section["call_sites"] if s["caller"]["method"] == "getUniqueIdSync"]
    assert unique_id and all(s["reachability"] == "no_caller_found" for s in unique_id)
    assert section["coverage"]["reduced_by"] == ["react_native"]
    assert all(r["coverage_caveat"] for r in section["data_safety"]["rows"])
    # the RNFirebase bridge switches Analytics collection: a consent control, not "none"
    assert section["consent"]["verdict"] == "consent_controls_only"


def test_grok_held_out():
    """Held-out APK: own-account reads are left out, Mixpanel is found though renamed."""
    section = section_for(need(GROK))
    assert section["coverage"]["own_data_reads_skipped"] >= 16
    assert not [s for s in section["call_sites"] if s["api_id"] == "acct.user_data"]
    sdks = {s["id"]: s["confidence"] for s in section["sdks"]}
    assert sdks.get("mixpanel") == "low" and sdks.get("firebase_crashlytics") == "high"
    assert "google_firebase_analytics" not in sdks and "firebase_analytics" not in sdks
    assert "heavy_obfuscation" in section["coverage"]["reduced_by"]
    # AppCompat's TwilightManager (R8-merged y/e) is reached from Intercom only through
    # renamed frames: at most a low-confidence guess, and no Intercom sharing hint (12-verify)
    for site in section["call_sites"]:
        if site["caller"]["class"] == "Ly/e;":
            assert site["origin"]["confidence"] == "low"
    for row in section["data_safety"]["rows"]:
        if row["data_type"].startswith("location."):
            assert "intercom" not in ((row["sharing_hint"] or {}).get("sdk_ids") or [])
    # w/c.createIntent: INTENT_SENDER_REQUEST and REQUEST_PERMISSIONS are no picker sites
    wc = [s for s in section["call_sites"] if s["caller"]["class"] == "Lw/c;" and s["api_id"].startswith("intent.")]
    assert {s["caller"]["offset"] for s in wc}.isdisjoint({22, 46})


def test_nextcloud_camera_intents_are_not_double_counted():
    section = section_for(need(NEXTCLOUD))
    seen = {}
    for s in section["call_sites"]:
        if s["api_id"].startswith("intent.") and s["caller"]["method"] == "uploadFromCamera":
            seen.setdefault(s["caller"]["offset"], []).append(s["api_id"])
    assert seen and all(len(v) == 1 for v in seen.values()), seen


def test_grok_config_split_is_not_a_clean_result():
    split = GROK.parent / "config.arm64_v8a.apk"
    section = section_for(need(split))
    assert section["status"] == "partial" and section["coverage"]["code_analysed"] is False
    assert {"no_dex", "split_apk"} <= set(section["coverage"]["reduced_by"])


def test_sunrise_flutter_is_flagged():
    section = section_for(need(SUNRISE))
    assert "flutter" in section["coverage"]["reduced_by"]
    assert all("Flutter (Dart) code" in r["coverage_caveat"] for r in section["data_safety"]["rows"])
