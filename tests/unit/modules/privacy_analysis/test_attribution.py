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
    return Attributor(
        index or FakeIndex(), cat.sdks, trie, list(namespaces), hits, components, True, set(cat.wrapper_classes)
    )


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
    # AdMob excludes the ads-identifier library, which stays a plain library
    assert a.base("Lcom/google/android/gms/ads/identifier/AdvertisingIdClient;") is None
    o = a.frame_origin(m("Lcom/google/android/gms/ads/identifier/AdvertisingIdClient;->a()V"))
    assert (o.type, o.rule, o.name) == ("library", "third_party_package", "com.google.android")
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


def test_rule4_wrapper_keeps_every_upstream_caller(cat):
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
    x.add(
        "Lio/voiapp/voi/Other;->id()V",
        invokes=[("Landroidx/core/telephony/TelephonyManagerCompat;->getImei()Ljava/lang/String;", 6)],
    )
    frames = make(cat, x).site_frames(
        m("Landroidx/core/telephony/TelephonyManagerCompat;->getImei()Ljava/lang/String;"), 4
    )
    assert [(f.cls, off, o.type, o.sdk_id) for f, off, o, _ in frames] == [
        ("Lcom/adjust/sdk/Dev;", 12, "sdk", "adjust"),
        ("Lio/voiapp/voi/Dev;", 10, "app", None),
        ("Lio/voiapp/voi/Other;", 6, "app", None),  # a second app caller is kept (review-1 S1)
    ]
    assert frames[1][3] == ["Landroidx/core/telephony/TelephonyManagerCompat;->getImei"]


def test_rule4_wrapper_without_upstream_is_library(cat):
    x = FakeIndex()
    x.add("Landroidx/core/telephony/TelephonyManagerCompat$Api26Impl;->getImei()V", invokes=[(API, 4)])
    [(frame, off, origin, via)] = make(cat, x).site_frames(
        m("Landroidx/core/telephony/TelephonyManagerCompat$Api26Impl;->getImei()V"), 4
    )
    assert (origin.type, origin.name, origin.rule, origin.confidence) == (
        "library",
        "androidx.core.telephony.TelephonyManagerCompat",
        "transparent_library",
        "medium",
    )
    assert off == 4 and via == []


def test_androidx_is_not_transparent(cat):
    """AppCompat's night-mode location probe stays AppCompat's, even when an app activity reaches it."""
    x = FakeIndex()
    x.add("Landroidx/appcompat/app/TwilightManager;->get()V", invokes=[(API, 4)])
    x.add(
        "Landroidx/appcompat/app/AppCompatDelegateImpl;->applyDayNight()V",
        invokes=[("Landroidx/appcompat/app/TwilightManager;->get()V", 2)],
    )
    x.add(
        "Lio/voiapp/voi/GalleryActivity;->onConfigurationChanged()V",
        invokes=[("Landroidx/appcompat/app/AppCompatDelegateImpl;->applyDayNight()V", 8)],
    )
    [(frame, off, origin, via)] = make(cat, x).site_frames(m("Landroidx/appcompat/app/TwilightManager;->get()V"), 4)
    assert frame.cls == "Landroidx/appcompat/app/TwilightManager;"
    assert (origin.type, origin.name, origin.rule) == ("library", "androidx.appcompat.app", "third_party_package")


def test_self_calls(cat):
    a = make(cat)
    acct = "Lcom/google/android/gms/auth/api/signin/GoogleSignInAccount;"
    assert a.same_owner(acct, acct)  # getters called by its own writeToParcel
    assert a.same_owner("Lcom/google/android/gms/auth/api/signin/internal/Store;", acct)
    assert a.same_owner(
        "Lcom/google/firebase/analytics/internal/Z;", "Lcom/google/firebase/analytics/FirebaseAnalytics;"
    )
    assert not a.same_owner(
        "Lcom/google/android/gms/measurement/internal/zzbd;",
        "Lcom/google/android/gms/ads/identifier/AdvertisingIdClient$Info;",
    )
    assert not a.same_owner("Landroid/telephony/Fake;", "Landroid/telephony/TelephonyManager;")
    assert not a.same_owner("Lio/voiapp/voi/Login;", acct)


def test_mediation_innermost_sdk_wins(cat):
    x = FakeIndex()
    x.add("Lcom/adjust/sdk/Inner;->id()V", invokes=[(API, 2)])
    x.add("Lbo/app/zz;->a()V", invokes=[("Lcom/adjust/sdk/Inner;->id()V", 2)])
    [(_f, _o, origin, _v)] = make(cat, x).site_frames(m("Lcom/adjust/sdk/Inner;->id()V"), 2)
    assert origin.sdk_id == "adjust"


def ns(cat, package, app_class=None):
    return build_app_namespaces(package, app_class, SdkTrie(cat.sdks), cat.shared_roots, cat.framework_prefixes)


def test_namespaces_voi_like(cat):
    assert ns(cat, "io.voiapp.voi", "io.voiapp.voi.VoiApp") == ["io.voiapp"]
    a = Attributor(FakeIndex(), cat.sdks, SdkTrie(cat.sdks), ns(cat, "io.voiapp.voi"))
    for cls in (
        "Lzendesk/support/X;",
        "Lcom/mapbox/android/telemetry/T;",
        "Lno/nordicsemi/android/D;",
        "Lcom/appboy/A;",
    ):
        assert a.frame_origin(m(cls + "->x()V")).type != "app"
    assert a.base("Lio/voiapp/foo/Bar;").type == "app"


def test_namespaces_nextcloud_root_and_application_package(cat):
    """com.nextcloud.utils/ui are app code; so is the owncloud Application package."""
    assert ns(cat, "com.nextcloud.client", "com.owncloud.android.MainApp") == ["com.nextcloud", "com.owncloud.android"]
    a = Attributor(FakeIndex(), cat.sdks, SdkTrie(cat.sdks), ns(cat, "com.nextcloud.client"))
    assert a.base("Lcom/nextcloud/utils/CalendarEventManager;").type == "app"
    assert a.base("Lcom/nextcloud/ui/ImageDetailFragment;").type == "app"


@pytest.mark.parametrize(
    "package,app_class,expected",
    [
        ("com.google.android.apps.foo", None, ["com.google.android.apps.foo"]),  # shared root: package only
        ("io.github.user.app", None, ["io.github.user.app"]),
        ("com.ex.app", "io.flutter.app.FlutterApplication", ["com.ex"]),  # framework Application class
        ("com.ex.app", "com.facebook.react.ReactApplication", ["com.ex"]),
        ("com.ex.app", "com.ex.app.sub.App", ["com.ex"]),
        ("com.adjust.sdk", None, []),  # under a curated SDK prefix
        ("app", None, []),
    ],
)
def test_namespace_rules(cat, package, app_class, expected):
    assert ns(cat, package, app_class) == expected


def test_curated_sdk_beats_app_namespace(cat):
    a = Attributor(FakeIndex(), cat.sdks, SdkTrie(cat.sdks), ["com"])
    assert a.base("Lcom/adjust/sdk/Adjust;").type == "sdk"
