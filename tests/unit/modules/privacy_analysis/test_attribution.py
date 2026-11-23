# SPDX-License-Identifier: GPL-3.0-only
"""Attribution rules 1-9, namespaces, desynth and the obfuscation test (04-design §2.6)."""

import pytest

from dexray_insight.modules.privacy_analysis.attribution import Attributor
from dexray_insight.modules.privacy_analysis.attribution import SdkTrie
from dexray_insight.modules.privacy_analysis.attribution import build_app_namespaces
from dexray_insight.modules.privacy_analysis.attribution import desynth
from dexray_insight.modules.privacy_analysis.attribution import is_obfuscated
from dexray_insight.privacy.catalogue import load_catalogue

from .fakes import CATALOGUE_MIN
from .fakes import FakeIndex
from .fakes import m

API = "Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;"


@pytest.fixture(scope="module")
def cat():
    return load_catalogue(CATALOGUE_MIN)


def make(cat, index=None, namespaces=("io.voiapp.voi",), hits=None, components=None):
    trie = SdkTrie(cat.sdks)
    return Attributor(index or FakeIndex(), cat.sdks, trie, list(namespaces), hits, components)


@pytest.mark.parametrize(
    "cls,out",
    [
        ("Lcom/a/B$c;", "Lcom/a/B;"),
        ("Lcom/a/B$$ExternalSyntheticLambda0;", "Lcom/a/B;"),
        ("Lcom/a/B;", "Lcom/a/B;"),
        ("La;", "La;"),
    ],
)
def test_desynth(cls, out):
    assert desynth(cls) == out


@pytest.mark.parametrize(
    "cls,obf",
    [
        ("Lq/a/a/a/a/i;", True),
        ("La;", True),
        ("Lab/c/Xyz;", True),
        ("Lab/c/Xyzw;", False),
        ("Lbo/app/bj;", False),  # "app" has three characters
        ("Lcom/a/b;", False),
        ("Lq/a/b$1;", True),
    ],
)
def test_is_obfuscated(cls, obf):
    assert is_obfuscated(cls) is obf


def test_rule1_prefix_and_exclude(cat):
    a = make(cat)
    o = a.base("Lcom/adjust/sdk/MacAddressUtil;")
    assert (o.type, o.sdk_id, o.confidence, o.rule) == ("sdk", "adjust", "high", "sdk_prefix")
    # AdMob excludes the ads-identifier library, which is transparent instead
    assert a.base("Lcom/google/android/gms/ads/identifier/AdvertisingIdClient;") is None
    o = a.frame_origin(m("Lcom/google/android/gms/ads/identifier/AdvertisingIdClient;->a()V"))
    assert (o.type, o.rule, o.name) == ("library", "transparent_library", "com.google.android.gms.ads.identifier")
    assert a.base("Lcom/google/android/gms/ads/AdView;").sdk_id == "google_mobile_ads"


def test_rule2_obfuscated_prefix(cat):
    o = make(cat).base("Lbo/app/bj;")
    assert (o.type, o.sdk_id, o.confidence) == ("sdk", "braze", "medium")


def test_rule3_app_namespace_and_repackaging(cat):
    a = make(cat)
    assert a.base("Lio/voiapp/voi/ride/RideActivity;").confidence == "high"
    o = a.base("Lio/voiapp/voi/a/b;")
    assert (o.type, o.confidence, o.rule) == ("app", "medium", "app_namespace")


def test_rule9_and_rule8(cat):
    a = make(cat)
    o = a.frame_origin(m("Lzendesk/support/Guide;->x()V"))
    assert (o.type, o.name, o.rule) == ("library", "zendesk.support", "third_party_package")
    o = a.frame_origin(m("Lcom/mapbox/android/telemetry/Tele;->x()V"))
    assert o.name == "com.mapbox.android"
    o = a.frame_origin(m("Lq/a/a/a/a/i;->a()V"))
    assert (o.type, o.confidence, o.rule) == ("unattributed", "low", "obfuscated")


def test_rule5_called_only_by_sdk(cat):
    x = FakeIndex()
    x.add("Lx/y/a;->a()V")
    x.add("Lcom/adjust/sdk/Util;->go()V", invokes=[("Lx/y/a;->a()V", 2)])
    o = make(cat, x).frame_origin(m("Lx/y/a;->a()V"))
    assert (o.type, o.sdk_id, o.rule, o.confidence) == ("sdk", "adjust", "called_only_by_sdk", "medium")
    # one app caller breaks it
    x.add("Lio/voiapp/voi/Main;->go()V", invokes=[("Lx/y/a;->a()V", 2)])
    assert make(cat, x).frame_origin(m("Lx/y/a;->a()V")).type == "unattributed"


def test_rule6_string_anchor_and_rule7_manifest_anchor(cat):
    a = make(cat, hits={"Lx/y/b;": {"meta_app_events": 1}})
    o = a.frame_origin(m("Lx/y/b;->a()V"))
    assert (o.sdk_id, o.rule) == ("meta_app_events", "string_anchor")
    # package needs >= 2 hits
    a = make(cat, hits={"Lx/y/b;": {"meta_app_events": 1}})
    assert a.frame_origin(m("Lx/y/c;->a()V")).type == "unattributed"
    a = make(cat, hits={"Lx/y/b;": {"meta_app_events": 2}})
    assert a.frame_origin(m("Lx/y/c;->a()V")).rule == "string_anchor"
    a = make(cat, components={"x.y": {"braze"}})
    o = a.frame_origin(m("Lx/y/d;->a()V"))
    assert (o.sdk_id, o.rule) == ("braze", "manifest_anchor")


def test_rule4_wrapper_with_two_origins(cat):
    x = FakeIndex()
    x.add("Landroidx/core/telephony/TelephonyManagerCompat;->getImei()Ljava/lang/String;", invokes=[(API, 4)])
    x.add(
        "Lio/voiapp/voi/Dev;->id()V",
        invokes=[("Landroidx/core/telephony/TelephonyManagerCompat;->getImei()Ljava/lang/String;", 10)],
    )
    x.add(
        "Lcom/adjust/sdk/Dev;->id()V",
        invokes=[("Landroidx/core/telephony/TelephonyManagerCompat;->getImei()Ljava/lang/String;", 12)],
    )
    frames = make(cat, x).site_frames(
        m("Landroidx/core/telephony/TelephonyManagerCompat;->getImei()Ljava/lang/String;"), 4
    )
    assert [(f.cls, off, o.type, o.sdk_id) for f, off, o, _ in frames] == [
        ("Lio/voiapp/voi/Dev;", 10, "app", None),
        ("Lcom/adjust/sdk/Dev;", 12, "sdk", "adjust"),
    ]
    assert frames[0][3] == ["Landroidx/core/telephony/TelephonyManagerCompat;->getImei"]


def test_rule4_without_upstream_is_library(cat):
    x = FakeIndex()
    x.add("Landroidx/appcompat/app/TwilightManager;->get()V", invokes=[(API, 4)])
    [(frame, off, origin, via)] = make(cat, x).site_frames(m("Landroidx/appcompat/app/TwilightManager;->get()V"), 4)
    assert (origin.type, origin.name, origin.rule, origin.confidence) == (
        "library",
        "androidx",
        "transparent_library",
        "medium",
    )
    assert off == 4 and via == []


def test_mediation_innermost_sdk_wins(cat):
    x = FakeIndex()
    x.add("Lcom/adjust/sdk/Inner;->id()V", invokes=[(API, 2)])
    x.add("Lbo/app/zz;->a()V", invokes=[("Lcom/adjust/sdk/Inner;->id()V", 2)])
    [(_f, _o, origin, _v)] = make(cat, x).site_frames(m("Lcom/adjust/sdk/Inner;->id()V"), 2)
    assert origin.sdk_id == "adjust"


def test_namespaces_voi_like(cat):
    trie = SdkTrie(cat.sdks)
    comps = [
        "io.voiapp.voi.MainActivity",
        "io.voiapp.foo.Receiver",
        "zendesk.support.guide.ViewArticleActivity",
        "com.mapbox.android.telemetry.TelemetryService",
        "com.appboy.push.AppboyFirebaseMessagingService",
        "no.nordicsemi.android.dfu.DfuService",
        "androidx.work.impl.WorkManagerService",
    ]
    ns = build_app_namespaces("io.voiapp.voi", "io.voiapp.voi.VoiApp", comps, trie)
    assert ns == ["io.voiapp.foo", "io.voiapp.voi"]
    a = Attributor(FakeIndex(), cat.sdks, trie, ns)
    for cls in (
        "Lzendesk/support/X;",
        "Lcom/mapbox/android/telemetry/T;",
        "Lno/nordicsemi/android/D;",
        "Lcom/appboy/A;",
    ):
        assert a.frame_origin(m(cls + "->x()V")).type != "app"
    assert a.base("Lio/voiapp/foo/Bar;").type == "app"


def test_namespaces_drop_sdk_and_short_candidates(cat):
    trie = SdkTrie(cat.sdks)
    assert build_app_namespaces("com.adjust.sdk", None, [], trie) == []
    assert build_app_namespaces("app", None, [], trie) == []
    assert build_app_namespaces("com.ex.app", "com.ex.app.sub.App", ["com.ex.app.x.Y"], trie) == ["com.ex.app"]
