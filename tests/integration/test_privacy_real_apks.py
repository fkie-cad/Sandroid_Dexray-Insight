# SPDX-License-Identifier: GPL-3.0-only
"""Static privacy layer on real APKs (04-design §6.2, §6.3).

exampleapp is in the repository; the other APKs are local-only and skip when missing.
The exampleapp golden projection is rewritten with ``--update-privacy-golden``
(review the diff by hand).
"""

import json
from functools import lru_cache
from pathlib import Path

import pytest

from dexray_insight.privacy.catalogue import DATA_DIR

ROOT = Path(__file__).resolve().parents[2]
EXAMPLEAPP = ROOT / "example_samples" / "exampleapp-release.apk"
GOLDEN = ROOT / "tests" / "fixtures" / "privacy" / "exampleapp_expected.json"
VOI = Path(
    "/Users/jan-niclas.hilgert/Desktop/Work/micro_mobility/voi/VOI Scooters Get Magic Wheels_v2.24.2_apkpure.com.apk"
)
SPIN = Path("/Users/jan-niclas.hilgert/Desktop/Work/micro_mobility/spin/Spin Electric Scooters_v2.21.0_apkpure.com.apk")
NEXTCLOUD = Path("/Users/jan-niclas.hilgert/Downloads/Installers/Nextcloud_3.31.1_APKPure.apk")
WIKIPEDIA = Path("/Users/jan-niclas.hilgert/Desktop/Work/Sandroid/testing-2.1/apks/org.wikipedia_50616.apk")

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
        pytest.skip(f"{path.name} not available")
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
    assert serial[0]["match"] == "field_read" and serial[0]["origin"]["type"] == "unattributed"


def test_voi_no_feature_conditional_or_self_call_overclaims(voi):
    rows = {r["data_type"]: r for r in voi["data_safety"]["rows"]}
    # Analytics' in-app purchase events need Play Billing, which VOI does not have
    assert rows["financial.purchase_history"]["status"] != "likely_collected"
    # GoogleSignInAccount calling its own getters is not a data access
    assert "personal.name" not in rows and "personal.email_address" not in rows
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
