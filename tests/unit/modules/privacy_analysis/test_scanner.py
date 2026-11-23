# SPDX-License-Identifier: GPL-3.0-only
"""Code index adapter, matching (04-design §2.5) and reachability (§2.7)."""

from unittest.mock import MagicMock

import pytest

from dexray_insight.modules.privacy_analysis.module import ManifestFacts
from dexray_insight.modules.privacy_analysis.module import analyse
from dexray_insight.modules.privacy_analysis.scanner import AndroguardIndex
from dexray_insight.modules.privacy_analysis.scanner import MRef
from dexray_insight.modules.privacy_analysis.scanner import Reachability
from dexray_insight.modules.privacy_analysis.scanner import host_in
from dexray_insight.privacy.catalogue import load_catalogue

from .fakes import CATALOGUE_MIN
from .fakes import QUERY
from .fakes import FakeIndex
from .fakes import m

P = "android.permission."
GET_STRING = (
    "Landroid/provider/Settings$Secure;->getString(Landroid/content/ContentResolver;Ljava/lang/String;)"
    "Ljava/lang/String;"
)
OPEN_FD = (
    "Landroid/content/ContentResolver;->openFileDescriptor(Landroid/net/Uri;Ljava/lang/String;)"
    "Landroid/os/ParcelFileDescriptor;"
)
CONTACTS_URI = "Landroid/provider/ContactsContract$Contacts;->CONTENT_URI:Landroid/net/Uri;"
IMAGES_URI = "Landroid/provider/MediaStore$Images$Media;->EXTERNAL_CONTENT_URI:Landroid/net/Uri;"


@pytest.fixture(scope="module")
def cat():
    return load_catalogue(CATALOGUE_MIN)


def manifest(perms=(), min_sdk=26, components=(), app_class=None, entries=None):
    return ManifestFacts(
        package="com.ex.app",
        min_sdk=min_sdk,
        target_sdk=34,
        application_class=app_class,
        components=list(components),
        permission_entries=(
            entries
            if entries is not None
            else [{"name": p, "tag": "uses-permission", "max_sdk_version": None} for p in perms]
        ),
    )


def sites(cat, x, man=None, **cfg):
    section = analyse(x, man or manifest(), cat, cfg)
    assert section["status"] == "success", section["errors"]
    return section["call_sites"], section


# ------------------------------------------------------------------ adapter
def _ma(cls, name, desc, external=False):
    ma = MagicMock()
    ma.class_name, ma.name, ma.descriptor = cls, name, desc
    ma.is_external.return_value = external
    return ma


def test_androguard_adapter_converts_descriptors_and_sorts_xrefs():
    target = _ma(
        "Landroid/provider/Settings$Secure;",
        "getString",
        "(Landroid/content/ContentResolver; Ljava/lang/String;)Ljava/lang/String;",
        external=True,
    )
    b = _ma("Lcom/b/B;", "z", "(I Ljava/lang/String;)V")
    a = _ma("Lcom/a/A;", "y", "()V")
    target.get_xref_from.return_value = {(MagicMock(), b, 30), (MagicMock(), a, 12), (MagicMock(), a, 4)}
    dx = MagicMock()
    dx.get_classes.return_value = []
    dx.get_method_analysis_by_name.side_effect = lambda c, n, d: (
        target if (c, n, d) == (target.class_name, target.name, target.descriptor) else None
    )
    idx = AndroguardIndex(dx, [])
    found = idx.find_method(
        "Landroid/provider/Settings$Secure;",
        "getString",
        "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;",
    )
    assert found is not None
    assert idx.callers(found) == [
        (MRef("Lcom/a/A;", "y", "()V"), 4),
        (MRef("Lcom/a/A;", "y", "()V"), 12),
        (MRef("Lcom/b/B;", "z", "(ILjava/lang/String;)V"), 30),
    ]
    assert idx.find_method("La;", "nope", "()V") is None


def test_androguard_adapter_decodes_instructions():
    def ins(op, length=2, **kw):
        i = MagicMock()
        i.get_op_value.return_value = op
        i.get_length.return_value = length
        i.get_ref_kind.return_value = 7
        i.get_literals.return_value = kw.get("lits", [])
        return i

    vm = MagicMock()
    vm.get_cm_string.return_value = "android_id"
    vm.get_cm_field.return_value = ["Landroid/os/Build;", "Ljava/lang/String;", "SERIAL"]  # [class, type, name]
    vm.get_cm_method.return_value = ["La/B;", "m", ["(I Ljava/lang/String;)", "V"]]
    vm.get_cm_type.return_value = "Lx/Y;"
    code = [ins(0x1A), ins(0x13, lits=[18]), ins(0x62, 4), ins(0x6E, 6), ins(0x22)]
    for i in code:
        i.cm.vm = vm
    meth = MagicMock()
    meth.get_instructions.return_value = code
    ma = _ma("Lc/C;", "f", "()V")
    ma.get_method.return_value = meth
    dx = MagicMock()
    dx.get_classes.return_value = []
    dx.get_method_analysis_by_name.return_value = ma
    facts = AndroguardIndex(dx, []).facts(MRef("Lc/C;", "f", "()V"))
    assert facts.strings == (("android_id", 0),)
    assert facts.ints == frozenset({18})
    assert facts.sgets == (("Landroid/os/Build;->SERIAL:Ljava/lang/String;", 4),)
    assert facts.invokes == ((MRef("La/B;", "m", "(ILjava/lang/String;)V"), 8),)
    assert facts.classes == (("Lx/Y;", 14),)


def test_host_in():
    assert host_in("https://app.adjust.com/session", "app.adjust.com")
    assert host_in("x.app.adjust.com", "app.adjust.com")
    assert not host_in("https://evilapp.adjust.com.example", "app.adjust.com")


# ---------------------------------------------------------------- matching
def test_requires_positive_and_negative(cat):
    x = FakeIndex()
    x.add("Lcom/ex/app/Id;->a()V", strings=["android_id"], invokes=[(GET_STRING, 6)])
    x.add(
        "Landroidx/core/app/NotificationManagerCompat;->b()V",
        strings=["enabled_notification_listeners"],
        invokes=[(GET_STRING, 6)],
    )
    got, _ = sites(cat, x)
    assert [(s["api_id"], s["caller"]["class"]) for s in got] == [("ids.settings.android_id", "Lcom/ex/app/Id;")]


def test_int_literals_requirement(cat, tmp_path):
    import shutil

    d = tmp_path / "cat"
    shutil.copytree(CATALOGUE_MIN, d)
    apis = d / "apis.yaml"
    apis.write_text(
        apis.read_text().replace(
            'requires: {const_string_any: ["android_id"], const_int_any: []}',
            "requires: {const_string_any: [], const_int_any: [18, 19]}",
        )
    )
    c2 = load_catalogue(d)
    x = FakeIndex()
    x.add("Lcom/ex/app/A;->a()V", ints=[19], invokes=[(GET_STRING, 2)])
    x.add("Lcom/ex/app/B;->a()V", ints=[5], invokes=[(GET_STRING, 2)])
    got, _ = sites(c2, x)
    assert [s["caller"]["class"] for s in got] == ["Lcom/ex/app/A;"]


def test_provider_uri_levels(cat):
    x = FakeIndex()
    # same method: static field (high)
    x.add("Lcom/ex/app/A;->a()V", sgets=[CONTACTS_URI], invokes=[(QUERY, 10)])
    # same class (synthetic sibling holds the URI string): never typed
    x.add("Lcom/ex/app/B;->q()V", invokes=[(QUERY, 10)])
    x.add("Lcom/ex/app/B$1;->uri()V", strings=["content://com.android.contacts/data"])
    # one hop up: authority string in the caller: never typed
    x.add("Lcom/ex/app/C;->q()V", invokes=[(QUERY, 10)])
    x.add("Lcom/ex/app/D;->go()V", strings=["com.android.contacts"], invokes=[("Lcom/ex/app/C;->q()V", 2)])
    # unresolved
    x.add("Lcom/ex/app/E;->q()V", invokes=[(QUERY, 10)])
    got, section = sites(cat, x, manifest([P + "READ_CONTACTS"]))
    prov = [s for s in got if s["match"] == "provider_read"]
    assert [
        (s["caller"]["class"], s["uri_evidence"]["kind"], s["uri_evidence"]["where"], s["confidence"]) for s in prov
    ] == [("Lcom/ex/app/A;", "static_field", "same_method", "high")]
    assert section["coverage"]["provider_reads_unresolved"] == 3
    assert "2 provider reads have URI evidence only outside the reading method; they are not typed" in (
        section["coverage"]["notes"]
    )


def test_provider_longest_uri_prefix_wins(cat):
    x = FakeIndex()
    x.add("Lcom/ex/app/P;->q()V", strings=["content://com.android.contacts/profile/data"], invokes=[(QUERY, 4)])
    got, _ = sites(cat, x)
    assert [s["api_id"] for s in got] == ["prov.contacts_profile"]


def test_provider_through_wrapper(cat):
    x = FakeIndex()
    wrapper = "Landroidx/core/content/ContentResolverCompat;->query(Landroid/net/Uri;)Landroid/database/Cursor;"
    x.add(wrapper, invokes=[(QUERY, 8)])
    x.add("Lcom/ex/app/W;->load()V", sgets=[CONTACTS_URI], invokes=[(wrapper, 14)])
    [site], _ = sites(cat, x)
    assert site["caller"] == {"class": "Lcom/ex/app/W;", "method": "load", "descriptor": "()V", "offset": 14}
    assert site["origin"]["via"] == ["Landroidx/core/content/ContentResolverCompat;->query"]
    assert site["uri_evidence"]["where"] == "same_method"


@pytest.mark.parametrize(
    "strings,invokes,kept",
    [
        (["w"], [], False),
        (["rw"], [], False),
        (["r"], [], True),
        (["w", "r"], [], True),
        (
            [],
            [
                "Landroid/content/ContentResolver;->insert(Landroid/net/Uri;Landroid/content/ContentValues;)"
                "Landroid/net/Uri;"
            ],
            False,
        ),
    ],
)
def test_fd_carrier_write_filter(cat, strings, invokes, kept):
    x = FakeIndex()
    x.add(
        "Lcom/ex/app/Photo;->save()V",
        strings=strings,
        sgets=[IMAGES_URI],
        invokes=[(OPEN_FD, 20)] + [(i, 2) for i in invokes],
    )
    got, _ = sites(cat, x)
    assert bool([s for s in got if s["api_id"] == "prov.media_images"]) is kept


def test_field_read_needs_the_field_id(cat):
    x = FakeIndex()
    x.add("Lcom/ex/app/Ser;->s()V", sgets=["Landroid/os/Build;->SERIAL:Ljava/lang/String;"])
    got, _ = sites(cat, x, manifest(min_sdk=21))
    assert [(s["api_id"], s["match"], s["api"]) for s in got] == [
        ("ids.build.serial_field", "field_read", "Landroid/os/Build;->SERIAL:Ljava/lang/String;")
    ]

    class NoScan(FakeIndex):
        def field_defined(self, field_ref):
            return False

        def sget_sites(self, field_refs):
            raise AssertionError("no scan without a field id")

    y = NoScan()
    y.add("Lcom/ex/app/Ser;->s()V")
    assert sites(cat, y)[0] == []


@pytest.mark.parametrize(
    "marker",
    [
        "Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;",
        "Ljava/lang/Class;->forName(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;",
        "Ljava/lang/ClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;",
    ],
)
def test_reflection_overloads(cat, marker):
    x = FakeIndex()
    x.add(
        "Lcom/ex/app/R;->r()V",
        strings=["com.google.android.gms.ads.identifier.AdvertisingIdClient", "getAdvertisingIdInfo"],
        invokes=[(marker, 6)],
    )
    [site], _ = sites(cat, x, manifest(["com.google.android.gms.permission.AD_ID"]))
    assert (site["match"], site["evidence_kind"], site["confidence"], site["caller"]["offset"]) == (
        "reflective",
        "reflective_reference",
        "medium",
        6,
    )
    assert site["api_label"].endswith("(via reflection)")


def test_reflection_class_only_and_helper_hop(cat):
    x = FakeIndex()
    helper = "Lcom/ex/app/Refl;->invoke(Ljava/lang/String;)Ljava/lang/Object;"
    x.add(helper, invokes=[("Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;", 2)])
    x.add(
        "Lcom/ex/app/U;->u()V",
        strings=["com.google.android.gms.ads.identifier.AdvertisingIdClient"],
        invokes=[(helper, 8)],
    )
    x.add("Lcom/ex/app/N;->n()V", strings=["com.google.android.gms.ads.identifier.AdvertisingIdClient"])
    got, _ = sites(cat, x)
    assert [(s["caller"]["class"], s["caller"]["offset"]) for s in got] == [("Lcom/ex/app/U;", 8)]
    assert got[0]["confidence"] == "low"  # class only, then permission AD_ID missing: already low


def test_max_sdk_below_min_sdk_is_not_declared(cat):
    x = FakeIndex()
    x.add("Lcom/ex/app/C;->q()V", sgets=[CONTACTS_URI], invokes=[(QUERY, 4)])
    entries = [{"name": P + "READ_CONTACTS", "tag": "uses-permission", "max_sdk_version": 22}]
    [site], section = sites(cat, x, manifest(min_sdk=26, entries=entries))
    assert site["permission"] == {"required": {"any_of": [P + "READ_CONTACTS"]}, "declared": [], "satisfied": False}
    assert section["permissions"] == []
    entries[0]["max_sdk_version"] = 28
    [site], section = sites(cat, x, manifest(min_sdk=26, entries=entries))
    assert site["permission"]["satisfied"] is True
    assert section["permissions"][0]["max_sdk_version"] == 28


def test_sdk_self_use_is_skipped(cat):
    x = FakeIndex()
    x.add("Lcom/google/firebase/analytics/FirebaseAnalytics;->setUserId(Ljava/lang/String;)V")
    x.add(
        "Lcom/google/firebase/analytics/internal/Z;->z()V",
        invokes=[("Lcom/google/firebase/analytics/FirebaseAnalytics;->setUserId(Ljava/lang/String;)V", 2)],
    )
    x.add(
        "Lcom/ex/app/Login;->l()V",
        invokes=[("Lcom/google/firebase/analytics/FirebaseAnalytics;->setUserId(Ljava/lang/String;)V", 2)],
    )
    got, _ = sites(cat, x)
    assert [s["caller"]["class"] for s in got] == ["Lcom/ex/app/Login;"]


def test_renamed_sdk_api_is_named_in_notes(cat):
    x = FakeIndex()
    x.add("Lcom/google/firebase/analytics/FirebaseAnalytics;->a(Ljava/lang/String;)V")
    _, section = sites(
        cat,
        x,
        ManifestFacts(
            package="com.ex.app",
            meta_data=[
                {
                    "name": "com.google.firebase.components:com.google.firebase.analytics.connector.internal."
                    "AnalyticsConnectorRegistrar",
                    "value": "x",
                    "resolved": True,
                    "scope": "component",
                    "component": "c",
                }
            ],
        ),
    )
    notes = section["coverage"]["notes"]
    assert any(
        "not found by name (removed or renamed by R8, or not bundled)" in n and "sink.firebase.set_user_id" in n
        for n in notes
    )


def test_manifest_component_entry(cat):
    comp = {
        "name": "com.ex.app.Notif",
        "kind": "service",
        "permission": "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
        "actions": [],
    }
    [site], _ = sites(cat, FakeIndex(), manifest(components=[comp]))
    assert site["match"] == "manifest_component"
    assert site["caller"] == {"class": "Lcom/ex/app/Notif;", "method": None, "descriptor": None, "offset": None}
    assert site["permission"] == {"required": None, "declared": [], "satisfied": None}
    assert site["reachability"] == "app_code" and site["chain"] == []


def test_per_api_caps(cat):
    x = FakeIndex()
    for i in range(5):
        x.add(f"Lcom/other/I{i};->a()V", strings=["android_id"], invokes=[(GET_STRING, 2)])
    got, section = sites(cat, x, max_call_sites_per_api=3, reachability_max_sites_per_api=2)
    assert len(got) == 3
    assert [s["reachability"] for s in got] == ["no_caller_found", "no_caller_found", "not_checked"]
    assert got[2]["chain"] == []
    assert section["coverage"]["limits_hit"] == ["max_call_sites_per_api:ids.settings.android_id:2"]


# ------------------------------------------------------------- reachability
def reach(x, start, app=("Lcom/ex/app/",), entries=(), **kw):
    r = Reachability(x, lambda c: c.startswith(app), set(entries), **kw)
    return r.reach(m(start))


def test_reach_app_code_and_start_frame_rule():
    x = FakeIndex()
    x.add("Lcom/sdk/A;->a()V")
    x.add("Lcom/sdk/B;->b()V", invokes=[("Lcom/sdk/A;->a()V", 2)])
    x.add("Lcom/ex/app/Main;->go()V", invokes=[("Lcom/sdk/B;->b()V", 2)])
    res = reach(x, "Lcom/sdk/A;->a()V")
    assert res.reachability == "app_code"
    assert res.chain == ["Lcom/sdk/A;->a", "Lcom/sdk/B;->b", "Lcom/ex/app/Main;->go"]
    # an app frame without callers decides for itself
    assert reach(x, "Lcom/ex/app/Main;->go()V").chain == ["Lcom/ex/app/Main;->go"]


def test_reach_sdk_entry_and_callback():
    x = FakeIndex()
    x.add("Lcom/sdk/A;->a()V")
    x.add("Lcom/sdk/Svc;->onNewToken(Ljava/lang/String;)V", invokes=[("Lcom/sdk/A;->a()V", 2)])
    assert reach(x, "Lcom/sdk/A;->a()V", entries=["Lcom/sdk/Svc;"]).reachability == "sdk_entry"
    x.add("Lq/a/h;->run()V", invokes=[("Lcom/sdk/A;->a()V", 4)])
    x.supers["Lq/a/h;"] = ("Ljava/lang/Object;", ["Ljava/lang/Runnable;"])
    assert reach(x, "Lcom/sdk/A;->a()V", entries=["Lcom/sdk/Svc;"]).reachability == "sdk_entry"
    res = reach(x, "Lcom/sdk/A;->a()V")
    assert res.reachability == "callback" and res.chain[-1] == "Lq/a/h;->run"


def test_reach_cha_hop_through_internal_base():
    x = FakeIndex()
    x.add("Landroidx/x/Twilight;->loc()V")
    x.add("Landroidx/x/Impl$Auto;->mode()I", invokes=[("Landroidx/x/Twilight;->loc()V", 2)])
    x.add("Landroidx/x/Impl$Base;->mode()I")
    x.supers["Landroidx/x/Impl$Auto;"] = ("Landroidx/x/Impl$Base;", [])
    x.add("Lcom/ex/app/Main;->onCreate()V", invokes=[("Landroidx/x/Impl$Base;->mode()I", 4)])
    res = reach(x, "Landroidx/x/Twilight;->loc()V")
    assert res.reachability == "app_code"
    assert "Landroidx/x/Impl$Base;->mode" in res.chain


def test_reach_unknown_and_no_caller():
    x = FakeIndex()
    prev = "Lcom/s/M0;->m()V"
    x.add(prev)
    for i in range(1, 12):
        cur = f"Lcom/s/M{i};->m()V"
        x.add(cur, invokes=[(prev, 2)])
        prev = cur
    assert reach(x, "Lcom/s/M0;->m()V", max_depth=6).reachability == "unknown"
    assert reach(x, "Lcom/s/M0;->m()V", max_depth=20).reachability == "no_caller_found"
    assert reach(x, "Lcom/s/M0;->m()V", max_depth=20, max_nodes=3).reachability == "unknown"


# ------------------------------------------------------- review/precision fixes
MEDIA_INSERT = (
    "Landroid/content/ContentResolver;->insert(Landroid/net/Uri;Landroid/content/ContentValues;)Landroid/net/Uri;"
)


def test_own_provider_query_next_to_mediastore_insert_is_not_media(cat):
    """Nextcloud FileDataStorageManager: a class that inserts into MediaStore and queries its own provider."""
    x = FakeIndex()
    x.add("Lcom/ex/app/Store;->save()V", sgets=[IMAGES_URI], invokes=[(MEDIA_INSERT, 4)])
    x.add(
        "Lcom/ex/app/Store;->capabilities()V",
        sgets=["Lcom/ex/app/Meta;->CONTENT_URI_CAP:Landroid/net/Uri;"],
        invokes=[(QUERY, 8)],
    )
    got, section = sites(cat, x, manifest([P + "READ_EXTERNAL_STORAGE"]))
    assert [s for s in got if s["match"] == "provider_read"] == []
    assert section["data_safety"]["rows"][0]["data_type"] != "photo_video.photos" or all(
        e["kind"] == "permission_declared" for e in section["data_safety"]["rows"][0]["evidence"]
    )
    assert section["coverage"]["provider_reads_unresolved"] == 1


def test_wrapper_with_two_app_callers_resolves_each_uri(cat):
    """Review-1 S1: every upstream caller of ContentResolverCompat keeps its own URI."""
    x = FakeIndex()
    wrapper = "Landroidx/core/content/ContentResolverCompat;->query(Landroid/net/Uri;)Landroid/database/Cursor;"
    x.add(wrapper, invokes=[(QUERY, 8)])
    x.add("Lcom/ex/app/A;->contacts()V", sgets=[CONTACTS_URI], invokes=[(wrapper, 14)])
    x.add("Lcom/ex/app/B;->images()V", sgets=[IMAGES_URI], invokes=[(wrapper, 20)])
    got, _ = sites(cat, x, manifest([P + "READ_CONTACTS", P + "READ_EXTERNAL_STORAGE"]))
    assert [(s["api_id"], s["caller"]["class"], s["caller"]["offset"]) for s in got] == [
        ("prov.contacts", "Lcom/ex/app/A;", 14),
        ("prov.media_images", "Lcom/ex/app/B;", 20),
    ]


def _catalogue_with(tmp_path, file, old, new):
    import shutil

    d = tmp_path / "cat"
    shutil.copytree(CATALOGUE_MIN, d)
    path = d / file
    text = path.read_text()
    assert old in text
    path.write_text(text.replace(old, new, 1))
    return load_catalogue(d)


def test_provider_read_honours_requires(tmp_path):
    """Review-1 S2: a provider entry with requires matches only with the required const string."""
    c2 = _catalogue_with(
        tmp_path,
        "apis.yaml",
        '      authority_strings: ["com.android.contacts"]\n    data_types: [contacts.contacts]',
        '      authority_strings: ["com.android.contacts"]\n    requires: {const_string_any: ["display_name"]}\n'
        "    data_types: [contacts.contacts]",
    )
    x = FakeIndex()
    x.add("Lcom/ex/app/Flags;->q()V", sgets=[CONTACTS_URI], invokes=[(QUERY, 4)])
    x.add("Lcom/ex/app/Names;->q()V", strings=["display_name"], sgets=[CONTACTS_URI], invokes=[(QUERY, 4)])
    got, _ = sites(c2, x)
    assert [s["caller"]["class"] for s in got] == ["Lcom/ex/app/Names;"]


def test_reflection_honours_requires(tmp_path):
    c2 = _catalogue_with(
        tmp_path,
        "apis.yaml",
        '    reflection: {class: "com.google.android.gms.ads.identifier.AdvertisingIdClient", method: "getAdvertisingIdInfo"}',
        '    reflection: {class: "com.google.android.gms.ads.identifier.AdvertisingIdClient", method: "getAdvertisingIdInfo"}\n'
        '    requires: {const_string_any: ["getId"], const_int_any: []}',
    )
    x = FakeIndex()
    target = "com.google.android.gms.ads.identifier.AdvertisingIdClient"
    forname = "Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;"
    x.add("Lcom/ex/app/R1;->r()V", strings=[target], invokes=[(forname, 2)])
    x.add("Lcom/ex/app/R2;->r()V", strings=[target, "getId"], invokes=[(forname, 2)])
    got, _ = sites(c2, x)
    assert [s["caller"]["class"] for s in got] == ["Lcom/ex/app/R2;"]


def test_library_self_call_is_not_a_site(cat):
    """GoogleSignInAccount-style: a library calling its own API is not a data access."""
    x = FakeIndex()
    api = (
        "Lcom/google/android/gms/ads/identifier/AdvertisingIdClient;->getAdvertisingIdInfo(Landroid/content/Context;)"
        "Lcom/google/android/gms/ads/identifier/AdvertisingIdClient$Info;"
    )
    x.add("Lcom/google/android/gms/ads/identifier/AdvertisingIdClient$1;->run()V", invokes=[(api, 4)])
    x.add("Lcom/google/android/gms/measurement/internal/zzbd;->a()V", invokes=[(api, 6)])
    got, _ = sites(cat, x)
    assert [s["caller"]["class"] for s in got] == ["Lcom/google/android/gms/measurement/internal/zzbd;"]


def test_androguard_sget_scan_uses_encoded_methods():
    """Review-2 B1: DEX.get_methods() yields MethodIdItem (no code); the scan must use get_encoded_methods()."""
    ins = MagicMock()
    ins.get_op_value.return_value = 0x62
    ins.get_length.return_value = 4
    ins.get_ref_kind.return_value = 3
    ins.cm.vm.get_cm_field.return_value = ["Landroid/os/Build;", "Ljava/lang/String;", "SERIAL"]
    em = MagicMock()
    em.get_class_name.return_value = "Lq/a/a/a/a/i;"
    em.get_name.return_value = "a"
    em.get_descriptor.return_value = "(Landroid/content/Context;)Ljava/lang/String;"
    em.get_instructions.return_value = [ins]
    method_id = MagicMock(spec=["get_class_name", "get_name"])  # no get_code, like MethodIdItem
    dex = MagicMock()
    dex.get_methods.return_value = [method_id]
    dex.get_encoded_methods.return_value = [em]
    dx = MagicMock()
    dx.get_classes.return_value = []
    sites_ = AndroguardIndex(dx, [dex]).sget_sites({"Landroid/os/Build;->SERIAL:Ljava/lang/String;"})
    assert sites_ == {
        "Landroid/os/Build;->SERIAL:Ljava/lang/String;": [
            (MRef("Lq/a/a/a/a/i;", "a", "(Landroid/content/Context;)Ljava/lang/String;"), 0)
        ]
    }


def test_androguard_sget_scan_on_real_dex():
    """A real DEX (exampleapp): the scan finds framework static-field reads with byte offsets."""
    from pathlib import Path

    apk = Path(__file__).resolve().parents[4] / "example_samples" / "exampleapp-release.apk"
    if not apk.exists():
        pytest.skip("exampleapp missing")
    from androguard.misc import AnalyzeAPK
    from loguru import logger

    logger.remove()
    _a, d, dx = AnalyzeAPK(str(apk))
    idx = AndroguardIndex(dx, d)
    field = "Landroid/os/Build$VERSION;->SDK_INT:I"
    assert idx.field_defined(field)
    found = idx.sget_sites({field})[field]
    assert found  # before the fix: always empty
    method, offset = found[0]
    assert any(f == field and off == offset for f, off in idx.facts(method).sgets)


# --------------------------------------------- recovered provider reads (follow-up)
SMS_INBOX_CONST = "Lcom/ex/app/SmsReader;->INCOMING_SMS:Landroid/net/Uri;"
HELPER = "Lcom/ex/app/Resolver;->query(Landroid/content/ContentResolver;Landroid/net/Uri;)Landroid/database/Cursor;"


def test_static_final_uri_constant_is_same_method_evidence(cat, tmp_path):
    """Appium SmsReader: static final Uri INCOMING_SMS = Uri.parse("content://sms/inbox")."""
    c2 = _catalogue_with(
        tmp_path,
        "apis.yaml",
        "  - id: prov.media_images",
        """  - id: prov.sms
    label: "SMS provider read"
    group: providers
    role: source
    match: provider_read
    refs: []
    carriers: content_resolver_read
    uri_evidence: {static_fields: [], uri_prefixes: ["content://sms"], authority_strings: []}
    data_types: [email_text_message.text_messages]
    permission: {any_of: [android.permission.READ_SMS]}
    api: {since: 1, deprecated: null, removed: null, effective_until: null}
    precision: high
    sources: [aosp-api-versions]
  - id: prov.media_images""",
    )
    x = FakeIndex()
    x.add("Lcom/ex/app/SmsReader;->listSms()V", sgets=[SMS_INBOX_CONST], invokes=[(QUERY, 12)])
    x.constants[SMS_INBOX_CONST] = ("string", "content://sms/inbox")
    # a constant of another class initialised from a framework field
    x.add(
        "Lcom/ex/app/Media;->folders()V", sgets=["Lcom/ex/app/Const;->IMAGES:Landroid/net/Uri;"], invokes=[(QUERY, 8)]
    )
    x.constants["Lcom/ex/app/Const;->IMAGES:Landroid/net/Uri;"] = ("field", IMAGES_URI)
    x.classes.add("Lcom/ex/app/Const;")
    got, _ = sites(c2, x, manifest([P + "READ_SMS", P + "READ_EXTERNAL_STORAGE"]))
    assert [(s["api_id"], s["caller"]["class"], s["uri_evidence"]) for s in got] == [
        (
            "prov.media_images",
            "Lcom/ex/app/Media;",
            {"kind": "static_field", "value": IMAGES_URI, "where": "same_method"},
        ),
        (
            "prov.sms",
            "Lcom/ex/app/SmsReader;",
            {"kind": "uri_string", "value": "content://sms/inbox", "where": "same_method"},
        ),
    ]
    assert all(s["confidence"] == "high" for s in got)


def test_non_constant_field_is_not_evidence(cat):
    """A Uri field that is not a resolved static final constant gives nothing (no class-wide scan)."""
    x = FakeIndex()
    x.add(
        "Lcom/ex/app/Own;->q()V", sgets=["Lcom/ex/app/Meta;->CONTENT_URI_CAP:Landroid/net/Uri;"], invokes=[(QUERY, 4)]
    )
    x.add("Lcom/ex/app/Own;->other()V", sgets=[IMAGES_URI])  # same class, never used
    got, section = sites(cat, x)
    assert got == [] and section["coverage"]["provider_reads_unresolved"] == 1


def _helper_index():
    x = FakeIndex()
    x.add(HELPER, invokes=[(QUERY, 6)])
    # the helper passes its own Uri parameter (param 1) to query(): register 1 of query is the Uri
    x.args[(m(HELPER), 6)] = (False, [("param", 0), ("param", 1), None, None, None, None])
    return x


def test_caller_passing_a_catalogued_uri_types_the_read_at_the_caller(cat):
    x = _helper_index()
    x.add("Lcom/ex/app/Contacts;->load()V", sgets=[CONTACTS_URI], invokes=[(HELPER, 20)])
    x.args[(m("Lcom/ex/app/Contacts;->load()V"), 20)] = (True, [None, ("field", CONTACTS_URI)])
    x.add("Lcom/ex/app/Images;->load()V", invokes=[(HELPER, 30)])
    x.args[(m("Lcom/ex/app/Images;->load()V"), 30)] = (True, [None, ("field", "Lcom/ex/app/C;->IMG:Landroid/net/Uri;")])
    x.constants["Lcom/ex/app/C;->IMG:Landroid/net/Uri;"] = ("field", IMAGES_URI)
    x.classes.update({"Lcom/ex/app/C;", "Lcom/ex/app/Meta;"})
    x.add("Lcom/ex/app/Own;->load()V", invokes=[(HELPER, 40)])  # passes something else
    x.args[(m("Lcom/ex/app/Own;->load()V"), 40)] = (True, [None, ("field", "Lcom/ex/app/Meta;->OWN:Landroid/net/Uri;")])
    got, section = sites(cat, x, manifest([P + "READ_CONTACTS", P + "READ_EXTERNAL_STORAGE"]))
    assert [
        (
            s["api_id"],
            s["caller"]["class"],
            s["caller"]["offset"],
            s["uri_evidence"]["where"],
            s["confidence"],
            s["origin"]["via"],
        )
        for s in got
    ] == [
        ("prov.contacts", "Lcom/ex/app/Contacts;", 20, "caller", "medium", ["Lcom/ex/app/Resolver;->query"]),
        ("prov.media_images", "Lcom/ex/app/Images;", 30, "caller", "medium", ["Lcom/ex/app/Resolver;->query"]),
    ]
    assert section["coverage"]["provider_reads_unresolved"] == 0


def test_caller_step_needs_the_unchanged_uri_parameter(cat):
    """If the helper does not pass its own Uri parameter to the carrier, callers are not consulted."""
    x = FakeIndex()
    x.add(HELPER, invokes=[(QUERY, 6)])
    x.args[(m(HELPER), 6)] = (False, [("param", 0), None, None, None, None, None])  # Uri reassigned
    x.add("Lcom/ex/app/Contacts;->load()V", invokes=[(HELPER, 20)])
    x.args[(m("Lcom/ex/app/Contacts;->load()V"), 20)] = (True, [None, ("field", CONTACTS_URI)])
    got, section = sites(cat, x)
    assert got == [] and section["coverage"]["provider_reads_unresolved"] == 1


def test_trace_registers_on_androguard_shaped_code():
    """The register trace resolves sget, Uri.parse, moves, parameters and <clinit> stores."""
    from dexray_insight.modules.privacy_analysis.scanner import trace_registers

    def ins(op, regs, length=2, string=None, field=None, method=None):
        i = MagicMock()
        i.get_op_value.return_value = op
        i.get_length.return_value = length
        reg_kind = MagicMock()
        reg_kind.name = "REGISTER"
        i.get_operands.return_value = [(reg_kind, r) for r in regs]
        i.cm.vm.get_cm_string.return_value = string
        i.cm.vm.get_cm_field.return_value = field
        i.cm.vm.get_cm_method.return_value = method
        return i

    parse = ["Landroid/net/Uri;", "parse", ["(Ljava/lang/String;)", "Landroid/net/Uri;"]]
    query = [
        "Landroid/content/ContentResolver;",
        "query",
        [
            "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String;" " [Ljava/lang/String; Ljava/lang/String;)",
            "Landroid/database/Cursor;",
        ],
    ]
    em = MagicMock()
    em.get_code.return_value.get_registers_size.return_value = 8
    em.get_code.return_value.get_ins_size.return_value = 2
    em.get_access_flags_string.return_value = "public"
    em.get_descriptor.return_value = "(Landroid/net/Uri;)V"
    code = [
        ins(0x1A, [0], 4, string="content://sms/inbox"),  # 0
        ins(0x71, [0], 6, method=parse),  # 4
        ins(0x0C, [1]),  # 10 move-result-object v1
        ins(0x07, [2, 1]),  # 12 move-object v2, v1
        ins(0x6E, [6, 2, 3, 3, 3, 3], 6, method=query),  # 14 query(v2 = parsed)
        ins(0x6E, [6, 7, 3, 3, 3, 3], 6, method=query),  # 20 query(v7 = the Uri parameter)
    ]
    em.get_instructions.return_value = code
    callee, is_static, args = trace_registers(em, stop_offset=14)
    assert (callee.name, is_static, args[1]) == ("query", False, [("string", "content://sms/inbox")])
    assert trace_registers(em, stop_offset=20)[2][1] == [("param", 0)]
    clinit = MagicMock()
    clinit.get_code.return_value = None
    field = ["Lcom/ex/app/C;", "Landroid/net/Uri;", "IMG"]
    clinit.get_instructions.return_value = [
        ins(
            0x62,
            [0],
            4,
            field=["Landroid/provider/MediaStore$Images$Media;", "Landroid/net/Uri;", "EXTERNAL_CONTENT_URI"],
        ),
        ins(0x69, [0], 4, field=field),
    ]
    assert trace_registers(clinit, sput_field="Lcom/ex/app/C;->IMG:Landroid/net/Uri;") == [[("field", IMAGES_URI)]]
    # branch alternatives (imagepicker getRealPathFromURI): writes without a read in between merge;
    # a write after a read replaces (a reused register does not leak values)
    video = ["Landroid/provider/MediaStore$Video$Media;", "Landroid/net/Uri;", "EXTERNAL_CONTENT_URI"]
    images = ["Landroid/provider/MediaStore$Images$Media;", "Landroid/net/Uri;", "EXTERNAL_CONTENT_URI"]
    branchy = MagicMock()
    branchy.get_code.return_value = None
    branchy.get_instructions.return_value = [
        ins(0x62, [0], 4, field=images),  # 0  v0 = Images
        ins(0x28, [], 2),  # 4  goto
        ins(0x62, [0], 4, field=video),  # 6  v0 = Video (other branch)
        ins(0x6E, [6, 0, 3, 3, 3, 3], 6, method=query),  # 10 query(v0)
        ins(0x1A, [0], 4, string="x"),  # 16 v0 reused after the read
        ins(0x6E, [6, 0, 3, 3, 3, 3], 6, method=query),  # 20
    ]
    assert trace_registers(branchy, stop_offset=10)[2][1] == [
        ("field", IMAGES_URI),
        ("field", "Landroid/provider/MediaStore$Video$Media;->EXTERNAL_CONTENT_URI:Landroid/net/Uri;"),
    ]
    assert trace_registers(branchy, stop_offset=20)[2][1] == [("string", "x")]
