# SPDX-License-Identifier: GPL-3.0-only
"""Regressions for the 10-assessment follow-up.

Own-data reads, the body-sensor filter, consent wording, code-less input, coverage
caveats, R8-proof attribution (app references, SourceFile names, Firebase registrars),
bridge entry points, user-mediated intents and the catalogue additions.
"""

import shutil
from unittest.mock import MagicMock

import pytest

from dexray_insight.modules.privacy_analysis.label import CONSENT_HEDGE
from dexray_insight.modules.privacy_analysis.label import build_findings
from dexray_insight.modules.privacy_analysis.label import consent_verdict
from dexray_insight.modules.privacy_analysis.label import coverage_caveat
from dexray_insight.modules.privacy_analysis.module import ManifestFacts
from dexray_insight.modules.privacy_analysis.module import analyse
from dexray_insight.modules.privacy_analysis.module import summary_line
from dexray_insight.privacy.catalogue import CatalogueError
from dexray_insight.privacy.catalogue import load_catalogue

from .fakes import CATALOGUE_MIN
from .fakes import FakeIndex
from .fakes import check_contract

ANDROID_ID = (
    "Landroid/provider/Settings$Secure;->getString(Landroid/content/ContentResolver;Ljava/lang/String;)"
    "Ljava/lang/String;"
)
BY_TYPE = "Landroid/accounts/AccountManager;->getAccountsByType(Ljava/lang/String;)[Landroid/accounts/Account;"
USER_DATA = (
    "Landroid/accounts/AccountManager;->getUserData(Landroid/accounts/Account;Ljava/lang/String;)Ljava/lang/String;"
)
QUERY_INTENTS = "Landroid/content/pm/PackageManager;->queryIntentActivities(Landroid/content/Intent;I)Ljava/util/List;"
SET_PACKAGE = "Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;"
DEFAULT_SENSOR = "Landroid/hardware/SensorManager;->getDefaultSensor(I)Landroid/hardware/Sensor;"
REGISTER = (
    "Landroid/hardware/SensorManager;->registerListener(Landroid/hardware/SensorEventListener;"
    "Landroid/hardware/Sensor;I)Z"
)
NEW_INTENT = "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"


@pytest.fixture(scope="module")
def bundled():
    return load_catalogue()


@pytest.fixture(scope="module")
def cat():
    return load_catalogue(CATALOGUE_MIN)


def man(**kw):
    base = {"package": "com.ex.app", "min_sdk": 26, "target_sdk": 34}
    base.update(kw)
    return ManifestFacts(**base)


def run(cat, x, manifest=None, trackers=()):
    section = analyse(x, manifest or man(), cat, {}, list(trackers))
    check_contract(section)
    return section


def by_api(section, api_id):
    return [s for s in section["call_sites"] if s["api_id"] == api_id]


# ------------------------------------------------------------------- own data
def test_own_account_type_is_left_out(bundled):
    x = FakeIndex()
    own = x.add("Lcom/ex/app/Auth;->own()V", invokes=[(BY_TYPE, 4)])
    other = x.add("Lcom/ex/app/Auth;->other()V", invokes=[(BY_TYPE, 4)])
    x.args[(own, 4)] = (False, [None, ("string", "com.ex.app")])
    x.args[(other, 4)] = (False, [None, ("string", "com.google")])
    section = run(bundled, x)
    assert [s["caller"]["method"] for s in by_api(section, "acct.accounts_by_type")] == ["other"]
    assert section["coverage"]["own_data_reads_skipped"] == 1
    assert any("own data" in n for n in section["coverage"]["notes"])


def test_own_account_type_from_a_string_resource(bundled):
    x = FakeIndex()
    own = x.add("Lcom/ex/app/Auth;->own()V", invokes=[(BY_TYPE, 4)])
    x.args[(own, 4)] = (False, [None, ("res_string", 0x7F130001)])
    section = run(bundled, x, man(account_types=["org.ex.account"], resolve_string={0x7F130001: "org.ex.account"}.get))
    assert by_api(section, "acct.accounts_by_type") == []


def test_user_data_of_the_own_authenticator_is_left_out(bundled):
    x = FakeIndex()
    x.add("Lcom/ex/app/Auth;->token(Landroid/accounts/Account;)V", invokes=[(USER_DATA, 4)])
    assert len(by_api(run(bundled, x), "acct.user_data")) == 1  # no own authenticator: kept
    assert by_api(run(bundled, x, man(account_types=["com.ex.app"])), "acct.user_data") == []


def test_own_package_intent_query_is_left_out(bundled):
    x = FakeIndex()
    own = x.add("Lcom/ex/lib/Shortcuts;->listeners()V", invokes=[(SET_PACKAGE, 2), (QUERY_INTENTS, 8)])
    x.args[(own, 2)] = (False, [None, ("own_package", None)])
    x.add("Lcom/ex/lib/Browser;->handlers()V", invokes=[(QUERY_INTENTS, 8)])
    section = run(bundled, x)
    assert [s["caller"]["class"] for s in by_api(section, "app.query_intent_activities")] == ["Lcom/ex/lib/Browser;"]


def test_body_sensor_needs_the_sensor_type_not_any_int(bundled):
    x = FakeIndex()
    # an SDK_INT check (21) next to a gyroscope registration: not a body sensor
    gyro = x.add("Lcom/ex/app/Gyro;->start()V", ints=[21, 31], invokes=[(DEFAULT_SENSOR, 2), (REGISTER, 10)])
    x.args[(gyro, 2)] = (False, [None, ("int", 4)])
    # the step counter is fetched in <init>, registered in another method
    init = x.add("Lcom/ex/app/Steps;-><init>()V", invokes=[(DEFAULT_SENSOR, 2)])
    x.args[(init, 2)] = (False, [None, ("int", 19)])
    x.add("Lcom/ex/app/Steps;->start()V", invokes=[(REGISTER, 10)])
    section = run(bundled, x)
    assert [s["caller"]["class"] for s in by_api(section, "sensor.body")] == ["Lcom/ex/app/Steps;"]


def test_register_trace_records_ints_package_name_and_string_resources():
    from dexray_insight.modules.privacy_analysis.scanner import trace_registers

    def ins(op, regs, length=2, literal=None, method=None):
        i = MagicMock()
        i.get_op_value.return_value = op
        i.get_length.return_value = length
        kind = MagicMock()
        kind.name = "REGISTER"
        i.get_operands.return_value = [(kind, r) for r in regs]
        i.get_literals.return_value = [literal]
        i.cm.vm.get_cm_method.return_value = method
        return i

    em = MagicMock()
    em.get_code.return_value = None
    pkg = ["Landroid/content/Context;", "getPackageName", ["()", "Ljava/lang/String;"]]
    res = ["Landroid/content/Context;", "getString", ["(I)", "Ljava/lang/String;"]]
    call = ["Lx/Y;", "f", ["(I Ljava/lang/String; Ljava/lang/String;)", "V"]]
    em.get_instructions.return_value = [
        ins(0x13, [0], 4, literal=19),  # 0  const/16 v0, 19
        ins(0x6E, [5], 6, method=pkg),  # 4
        ins(0x0C, [1]),  # 10 move-result-object v1
        ins(0x14, [2], 6, literal=0x7F130001),  # 12 const v2, 0x7f130001
        ins(0x6E, [5, 2], 6, method=res),  # 18
        ins(0x0C, [3]),  # 24
        ins(0x71, [0, 1, 3], 6, method=call),  # 26
    ]
    _callee, _static, args = trace_registers(em, stop_offset=26)
    assert args == [[("int", 19)], [("own_package", None)], [("res_string", 0x7F130001)]]


# ------------------------------------------------------------------- consent
def test_consent_controls_only_verdict():
    empty = {"tcf": {"writes": False, "reads": False}}
    assert consent_verdict([], empty, [{"role": "attribution"}], {"adjust"}) == "consent_controls_only"
    assert consent_verdict([], empty, [{"role": "attribution"}], set()) == "none_detected"
    assert consent_verdict([{"id": "x"}], empty, [], {"adjust"}) == "cmp_detected"


def _findings(cat, controlled):
    sdk = {"id": "adjust", "name": "Adjust", "role": "attribution", "confidence": "high", "collects": []}
    site = {
        "id": "cs-0001",
        "api_id": "ids.settings.android_id",
        "api_label": "Settings.Secure ANDROID_ID",
        "data_types": ["identifiers.other"],
        "origin": {"type": "sdk", "sdk_id": "adjust", "name": "Adjust"},
        "reachability": "sdk_entry",
        "evidence_kind": "api_call_site",
        "permission": {"satisfied": None, "declared": []},
        "match": "method_call",
        "role": "source",
        "api_level": {"effective_for_app": True},
        "confidence": "medium",
    }
    consent = {
        "cmps": [],
        "tcf": {"writes": False},
        "gpp": {"writes": False},
    }
    meta = {"cs-0001": {"non_resettable": False, "deciding_app_class": False}}
    return build_findings(cat, [site], meta, [sdk], [], consent, {}, {}, False, controlled)


def test_consent_findings_are_hedged_and_respect_app_consent_controls(cat):
    found = {f["id"]: f for f in _findings(cat, set())}
    for fid in ("no_consent_mechanism", "sdk_identifier_access_without_consent"):
        assert CONSENT_HEDGE in found[fid]["summary"]
        assert "Potential TDDDG" not in found[fid]["summary"]
    assert not {f["id"] for f in _findings(cat, {"adjust"})} & {
        "no_consent_mechanism",
        "sdk_identifier_access_without_consent",
    }


# -------------------------------------------------------- coverage honesty
def test_codeless_apk_is_partial_with_a_coverage_note(cat):
    perms = [{"name": "android.permission.ACCESS_FINE_LOCATION", "tag": "uses-permission", "max_sdk_version": None}]
    section = run(cat, FakeIndex(dex=0), man(split_name="config.arm64_v8a", permission_entries=perms))
    assert section["status"] == "partial"
    assert any("no DEX code" in e for e in section["errors"])
    assert section["coverage"]["code_analysed"] is False
    assert section["coverage"]["reduced_by"] == ["no_dex", "split_apk"]
    assert all("No DEX code was analysed" in r["coverage_caveat"] for r in section["data_safety"]["rows"])
    assert summary_line(section).startswith("PRIVACY (static): no DEX code analysed")


def test_coverage_caveat_reaches_rows_and_summary(cat):
    x = FakeIndex()
    x.add("La/b;->c()V", strings=["android_id"], invokes=[(ANDROID_ID, 4)])
    for i in range(10):
        x.classes.add(f"Lz/{i};")
    section = run(cat, x, man(files=["assets/index.android.bundle", "lib/arm64-v8a/libreactnativejni.so"]))
    assert section["coverage"]["reduced_by"] == ["heavy_obfuscation", "react_native"]
    [row] = [r for r in section["data_safety"]["rows"] if r["data_type"] == "identifiers.other"]
    assert "React Native (JavaScript) code" in row["coverage_caveat"]
    assert "1 of 1 call sites are in obfuscated code" in row["coverage_caveat"]
    assert "coverage reduced: heavy obfuscation, React Native (JavaScript) code" in summary_line(section)


def test_coverage_caveat_is_none_for_full_coverage():
    assert coverage_caveat({"reduced_by": []}, [{"type": "unattributed", "call_site_count": 3}]) is None
    # heavy obfuscation only matters for rows with unattributed sites
    assert coverage_caveat({"reduced_by": ["heavy_obfuscation"]}, [{"type": "app", "call_site_count": 3}]) is None


# ------------------------------------------------------------ R8 attribution
def _android_id_reader(x, ref):
    return x.add(ref, strings=["android_id"], invokes=[(ANDROID_ID, 4)])


def test_direct_app_reference_names_obfuscated_app_code(cat):
    x = FakeIndex()
    x.add("Lcom/ex/app/MainActivity;->go()V")
    _android_id_reader(x, "La/b/c;->id()V")
    x.call("La/b/c;->id()V", "Lcom/ex/app/MainActivity;->go()V", 8)
    # one more hop (d.e.f only calls a.b.c): never carried over (R8 merges classes)
    _android_id_reader(x, "Ld/e/f;->id()V")
    x.call("Ld/e/f;->id()V", "La/b/c;->id()V", 8)
    section = run(cat, x)
    origins = {s["caller"]["class"]: s["origin"] for s in section["call_sites"]}
    assert origins["La/b/c;"]["type"] == "app" and origins["La/b/c;"]["confidence"] == "medium"
    assert origins["La/b/c;"]["rule"] == "app_reference"
    assert origins["La/b/c;"]["evidence"] == ["references:Lcom/ex/app/MainActivity;"]
    assert origins["Ld/e/f;"]["type"] == "unattributed"


def test_app_resource_reads_name_app_code_unless_library_resources_too(cat):
    x = FakeIndex()
    x.classes.update({"Lcom/ex/app/R$string;", "Lcom/lib/R$id;"})
    x.add("La/a/a;->id()V", strings=["android_id"], sgets=["Lcom/ex/app/R$string;->title:I"], invokes=[(ANDROID_ID, 4)])
    x.add(
        "Lb/b/b;->id()V",
        strings=["android_id"],
        sgets=["Lcom/ex/app/R$string;->title:I", "Lcom/lib/R$id;->x:I"],
        invokes=[(ANDROID_ID, 4)],
    )
    origins = {s["caller"]["class"]: s["origin"] for s in run(cat, x)["call_sites"]}
    assert origins["La/a/a;"]["rule"] == "app_reference"
    assert origins["La/a/a;"]["evidence"] == ["resources:Lcom/ex/app/R$string;"]
    assert origins["Lb/b/b;"]["type"] == "unattributed"


def test_source_file_names_an_sdk_but_never_with_high_confidence(bundled):
    x = FakeIndex()
    _android_id_reader(x, "Lm/k/f1;->id()V")
    x.source_files["Lm/k/f1;"] = "OneSignal.java"
    alone = run(bundled, x)
    [site] = by_api(alone, "ids.settings.android_id")
    assert (site["origin"]["sdk_id"], site["origin"]["rule"], site["origin"]["confidence"]) == (
        "onesignal",
        "source_file",
        "low",
    )
    [sdk] = alone["sdks"]
    assert sdk["confidence"] == "low" and [d["kind"] for d in sdk["detection"]] == ["source_file"]
    # an independent detection (class prefix + anchor) supports it: medium, never high
    x.classes.add("Lcom/onesignal/OneSignal;")
    supported = run(bundled, x)
    [site] = by_api(supported, "ids.settings.android_id")
    assert site["origin"]["confidence"] == "medium"
    # a SourceFile of a curated SDK blocks the app-reference rule
    x.add("Lcom/ex/app/Main;->go()V")
    x.call("Lm/k/f1;->id()V", "Lcom/ex/app/Main;->go()V", 8)
    [site] = by_api(run(bundled, x), "ids.settings.android_id")
    assert site["origin"]["type"] == "sdk"


def test_generic_source_file_names_are_ignored(bundled):
    x = FakeIndex()
    _android_id_reader(x, "Lm/k/f1;->id()V")
    x.source_files["Lm/k/f1;"] = "SourceFile"
    [site] = by_api(run(bundled, x), "ids.settings.android_id")
    assert site["origin"]["type"] == "unattributed"


def test_firebase_registrar_names_renamed_component_classes(bundled):
    x = FakeIndex()
    registrar = "Lcom/google/firebase/crashlytics/CrashlyticsRegistrar;"
    x.add(registrar + "->getComponents()Ljava/util/List;", classes=["La/a/z;"])
    _android_id_reader(x, "La/a/z;->id()V")
    key = "com.google.firebase.components:com.google.firebase.crashlytics.CrashlyticsRegistrar"
    meta = [{"name": key, "value": "x", "resolved": True, "scope": "component", "component": "c"}]
    [site] = by_api(run(bundled, x, man(meta_data=meta)), "ids.settings.android_id")
    assert (site["origin"]["sdk_id"], site["origin"]["rule"]) == ("firebase_crashlytics", "component_registrar")
    assert site["origin"]["evidence"] == ["registrar:com.google.firebase.crashlytics.CrashlyticsRegistrar"]
    # a readable class outside the SDK refers to it too: no claim
    x.add("Lcom/ex/app/Main;->go()V", classes=["La/a/z;"])
    [site] = by_api(run(bundled, x, man(meta_data=meta)), "ids.settings.android_id")
    assert site["origin"]["rule"] != "component_registrar"


# ---------------------------------------------------------- bridge entries
def test_react_method_is_a_bridge_entry_not_dead_code(cat):
    x = FakeIndex()
    method = _android_id_reader(x, "Lcom/learnium/RNDeviceInfo/RNDeviceModule;->getUniqueIdSync()Ljava/lang/String;")
    x.annotations[method] = ["Lcom/facebook/react/bridge/ReactMethod;"]
    files = ["assets/index.android.bundle"]
    section = run(cat, x, man(files=files, read_file=lambda p: b"NativeModules.RNDeviceInfo.getUniqueIdSync()"))
    [site] = section["call_sites"]
    assert site["reachability"] == "bridge_entry" and site["evidence_kind"] == "api_call_site"
    assert site["confidence"] != "low"
    assert site["bridge"] == {
        "kind": "react_native",
        "entry": "Lcom/learnium/RNDeviceInfo/RNDeviceModule;->getUniqueIdSync",
        "name_in_bundle": True,
    }


@pytest.mark.parametrize(
    "ref, supers, kind",
    [
        (
            "Lorg/plug/Plug;->execute(Ljava/lang/String;Lorg/json/JSONArray;Lorg/apache/cordova/CallbackContext;)Z",
            {"Lorg/plug/Plug;": ("Lorg/apache/cordova/CordovaPlugin;", [])},
            "cordova",
        ),
        (
            "Lorg/plug/Chan;->onMethodCall(Lio/flutter/plugin/common/MethodCall;"
            "Lio/flutter/plugin/common/MethodChannel$Result;)V",
            {},
            "flutter",
        ),
    ],
)
def test_cordova_and_flutter_bridges(cat, ref, supers, kind):
    x = FakeIndex()
    _android_id_reader(x, ref)
    x.supers.update(supers)
    [site] = run(cat, x)["call_sites"]
    assert site["reachability"] == "bridge_entry" and site["bridge"]["kind"] == kind
    assert site["bridge"]["name_in_bundle"] is None


def test_javascript_interface_reached_through_a_helper(cat):
    x = FakeIndex()
    _android_id_reader(x, "Lorg/lib/Js;->helper()Ljava/lang/String;")
    entry = x.add("Lorg/lib/Js;->deviceId()Ljava/lang/String;")
    x.call("Lorg/lib/Js;->deviceId()Ljava/lang/String;", "Lorg/lib/Js;->helper()Ljava/lang/String;", 2)
    x.annotations[entry] = ["Landroid/webkit/JavascriptInterface;"]
    [site] = run(cat, x)["call_sites"]
    assert site["reachability"] == "bridge_entry" and site["bridge"]["kind"] == "javascript_interface"


# --------------------------------------------------------- catalogue refresh
def test_user_mediated_intent_is_low_possible_evidence(bundled):
    x = FakeIndex()
    x.add("Lcom/ex/app/Upload;->camera()V", strings=["android.media.action.IMAGE_CAPTURE"], invokes=[(NEW_INTENT, 4)])
    x.add("Lcom/ex/app/Upload;->other()V", strings=["android.intent.action.VIEW"], invokes=[(NEW_INTENT, 4)])
    section = run(bundled, x)
    [site] = by_api(section, "intent.photo_capture")
    assert site["evidence_kind"] == "user_mediated_intent" and site["confidence"] == "low"
    [row] = [r for r in section["data_safety"]["rows"] if r["data_type"] == "photo_video.photos"]
    assert row["status"] == "possible"


@pytest.mark.parametrize(
    "api_id, ref",
    [
        (
            "loc.fused.legacy_api",
            "Lcom/google/android/gms/location/FusedLocationProviderApi;->getLastLocation("
            "Lcom/google/android/gms/common/api/GoogleApiClient;)Landroid/location/Location;",
        ),
        ("loc.wifi.ssid", "Landroid/net/wifi/WifiInfo;->getSSID()Ljava/lang/String;"),
        ("ids.bt.bonded_devices", "Landroid/bluetooth/BluetoothAdapter;->getBondedDevices()Ljava/util/Set;"),
        (
            "app.install_referrer",
            "Lcom/android/installreferrer/api/InstallReferrerClient;->getInstallReferrer()"
            "Lcom/android/installreferrer/api/ReferrerDetails;",
        ),
        (
            "consent.firebase.consent_mode",
            "Lcom/google/firebase/analytics/FirebaseAnalytics;->setConsent(Ljava/util/Map;)V",
        ),
    ],
)
def test_new_catalogue_entries_match(bundled, api_id, ref):
    x = FakeIndex()
    x.add("Lcom/ex/app/A;->a()V", invokes=[(ref, 4)])
    assert by_api(run(bundled, x), api_id)


def test_consent_mode_call_from_the_app_controls_analytics(bundled):
    x = FakeIndex()
    x.add(
        "Lcom/ex/app/Consent;->apply()V",
        invokes=[("Lcom/google/firebase/analytics/FirebaseAnalytics;->setConsent(Ljava/util/Map;)V", 4)],
    )
    x.classes.update({"Lcom/google/firebase/analytics/FirebaseAnalytics;", "Lcom/google/android/gms/measurement/A;"})
    section = run(bundled, x)
    assert section["consent"]["verdict"] == "consent_controls_only"
    assert [c["api_id"] for c in section["consent"]["controls"]] == ["consent.firebase.consent_mode"]


def test_mixpanel_is_found_through_its_config_keys_when_renamed(bundled):
    x = FakeIndex()
    x.add(
        "Lyg/j;->a()V", strings=["com.mixpanel.android.MPConfig.EnableDebugLogging", "https://api.mixpanel.com/track"]
    )
    [sdk] = run(bundled, x)["sdks"]
    assert sdk["id"] == "mixpanel" and sdk["confidence"] == "low"


def test_shared_sdk_strings_are_not_anchors(bundled):
    """Values that two SDKs ship (Fabric and Firebase Crashlytics, the Facebook core keys) detect nothing."""
    x = FakeIndex()
    x.add("La/b;->c()V", strings=["com.crashlytics.android.build_id", "com.facebook.sdk.ApplicationId"])
    assert run(bundled, x)["sdks"] == []


def _cat_dir(tmp_path):
    d = tmp_path / "cat"
    shutil.copytree(CATALOGUE_MIN, d)
    return d


def test_catalogue_rejects_unknown_own_data_and_duplicate_source_files(tmp_path):
    d = _cat_dir(tmp_path)
    path = d / "apis.yaml"
    text = path.read_text()
    first = text.index("    precision:")
    path.write_text(text[:first] + "    own_data: everything\n" + text[first:])
    with pytest.raises(CatalogueError, match="own_data"):
        load_catalogue(d)
    for name, value, match in (("cat2", "Same.java", "listed for"), ("cat3", "SourceFile", "plain")):
        d2 = tmp_path / name
        shutil.copytree(CATALOGUE_MIN, d2)
        sdks = (
            (d2 / "sdks.yaml")
            .read_text()
            .replace(
                "    prefixes:",
                f"    source_files: [{{value: {value}, source: vendor-meta-app-events}}]\n    prefixes:",
            )
        )
        (d2 / "sdks.yaml").write_text(sdks)
        with pytest.raises(CatalogueError, match=match):
            load_catalogue(d2)
