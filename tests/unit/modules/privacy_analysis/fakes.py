# SPDX-License-Identifier: GPL-3.0-only
"""Dict-built fake :class:`CodeIndex` and the scooter scenario of the contract fixture.

``scooter_scenario()`` builds code and manifest facts from which the pipeline,
run on ``tests/fixtures/privacy/catalogue_min``, reproduces
``tests/fixtures/privacy/insight_privacy_result.example.json`` (apart from the
``generator`` block).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from dataclasses import field
from pathlib import Path

from dexray_insight.modules.privacy_analysis.module import ManifestFacts
from dexray_insight.modules.privacy_analysis.scanner import MethodFacts
from dexray_insight.modules.privacy_analysis.scanner import MRef
from dexray_insight.privacy.catalogue import to_jvm

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "privacy"
CATALOGUE_MIN = FIXTURES / "catalogue_min"
CONTRACT = FIXTURES / "insight_privacy_result.example.json"


def m(ref: str) -> MRef:
    """``Lcls;->name(desc)ret`` -> MRef."""
    cls, rest = ref.split("->", 1)
    name, desc = rest.split("(", 1)
    return MRef(cls, name, to_jvm("(" + desc))


@dataclass
class FakeIndex:
    """A :class:`CodeIndex` built from dicts.

    ``methods`` maps internal methods to their facts; ``calls`` holds
    ``(caller, callee, offset)`` edges (callees may be external); ``classes`` are
    extra internal classes; ``supers`` maps a class to ``(superclass, [interfaces])``.
    """

    methods: dict[MRef, MethodFacts] = field(default_factory=dict)
    calls: list[tuple[MRef, MRef, int]] = field(default_factory=list)
    classes: set[str] = field(default_factory=set)
    supers: dict[str, tuple[str | None, list[str]]] = field(default_factory=dict)
    dex: int = 1
    fields: set[str] = field(default_factory=set)
    class_ref_map: dict[str, list[MRef]] = field(default_factory=dict)
    #: static final field -> ("field", ref) | ("string", s), as read from its <clinit>
    constants: dict[str, tuple] = field(default_factory=dict)
    #: (method, offset) -> (is_static, [register values]) of the invoke there
    args: dict[tuple, tuple] = field(default_factory=dict)
    #: class -> DEX SourceFile name
    source_files: dict[str, str] = field(default_factory=dict)
    #: method -> annotation class descriptors
    annotations: dict[MRef, list[str]] = field(default_factory=dict)

    def add(self, ref: str, strings=(), ints=(), sgets=(), invokes=(), classes=()) -> MRef:
        """Add an internal method; ``invokes`` = ``[(callee ref, offset)]`` also become call edges."""
        method = m(ref)
        inv = tuple((m(c) if isinstance(c, str) else c, off) for c, off in invokes)
        self.methods[method] = MethodFacts(
            tuple((s, i) for i, s in enumerate(strings)),
            frozenset(ints),
            tuple((f, i) for i, f in enumerate(sgets)),
            inv,
            tuple((c, i) for i, c in enumerate(classes)),
        )
        for callee, off in inv:
            self.calls.append((method, callee, off))
        for c, _ in self.methods[method].classes:
            self.class_ref_map.setdefault(c, []).append(method)
        return method

    def call(self, caller: str, callee: str, offset: int = 0) -> None:
        """Add a call edge without touching facts (adds the invoke to the caller facts too)."""
        c, t = m(caller), m(callee)
        facts = self.methods.get(c, MethodFacts())
        self.methods[c] = MethodFacts(
            facts.strings, facts.ints, facts.sgets, facts.invokes + ((t, offset),), facts.classes
        )
        self.calls.append((c, t, offset))

    # -- CodeIndex
    def _internal_classes(self) -> set[str]:
        return {x.cls for x in self.methods} | set(self.classes)

    def dex_count(self) -> int:
        return self.dex

    def class_names(self) -> list[str]:
        return sorted(self._internal_classes())

    def has_class(self, cls: str) -> bool:
        return cls in self._internal_classes()

    def find_method(self, cls, name, desc):
        ref = MRef(cls, name, to_jvm(desc))
        if ref in self.methods or any(t == ref for _, t, _ in self.calls):
            return ref
        return None

    def callers(self, method):
        return sorted({(c, off) for c, t, off in self.calls if t == method})

    def is_internal_method(self, method):
        return method in self.methods

    def superclass(self, cls):
        if not self.has_class(cls):
            return None
        return self.supers.get(cls, ("Ljava/lang/Object;", []))[0]

    def interfaces(self, cls):
        if not self.has_class(cls):
            return []
        return sorted(self.supers.get(cls, (None, []))[1])

    def class_methods(self, cls):
        return sorted(x for x in self.methods if x.cls == cls)

    def facts(self, method):
        return self.methods.get(method, MethodFacts())

    def strings(self):
        return sorted({s for f in self.methods.values() for s, _ in f.strings})

    def string_users(self, value):
        return sorted(x for x, f in self.methods.items() if value in f.string_set)

    def field_defined(self, field_ref):
        return field_ref in self.fields or any(field_ref in f.sget_set for f in self.methods.values())

    def sget_sites(self, field_refs):
        out = {}
        for method, facts in sorted(self.methods.items()):
            for f, off in facts.sgets:
                if f in field_refs:
                    out.setdefault(f, []).append((method, off))
        return {k: sorted(v) for k, v in out.items()}

    def static_constant(self, field_ref):
        return self.constants.get(field_ref)

    def invoke_args(self, method, offset):
        callee = next((c for c, off in self.facts(method).invokes if off == offset), None)
        if callee is None:
            return None
        is_static, values = self.args.get((method, offset), (True, []))
        return callee, is_static, [v if isinstance(v, list) else [v] for v in values]

    def source_file(self, cls):
        return self.source_files.get(cls)

    def method_annotations(self, method):
        return sorted(self.annotations.get(method, []))

    def class_referrers(self, cls):
        out = {c.cls for c, t, _ in self.calls if t.cls == cls}
        out |= {x.cls for x, f in self.methods.items() if any(c == cls for c, _ in f.classes)}
        return sorted(c for c in out if c != cls and self.has_class(c))

    def static_readers(self, owners, field_refs=frozenset(), only=None):
        out = {}
        for method, facts in self.methods.items():
            for f, _ in facts.sgets:
                owner = f.split("->", 1)[0]
                if owner in owners and owner != method.cls:
                    out.setdefault(owner, set()).add(method.cls)
            for c, _ in facts.classes:
                if c in owners and c != method.cls:
                    out.setdefault(c, set()).add(method.cls)
        return {k: sorted(v) for k, v in out.items()}

    def class_refs(self, cls):
        refs = set(self.class_ref_map.get(cls, []))
        refs |= {c for c, t, _ in self.calls if t.cls == cls}
        return sorted(refs)


# --------------------------------------------------------------------- scenario
QUERY = (
    "Landroid/content/ContentResolver;->query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;"
    "[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;"
)
GET_STRING = "Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"
APP_ON_CREATE = "Lcom/example/scooter/ScooterApp;->onCreate()V"


def _fill(index: FakeIndex, prefix: str, total: int) -> None:
    """Add filler classes so ``prefix`` (dotted) has ``total`` internal classes."""
    have = sum(1 for c in index.class_names() if c[1:-1].replace("/", ".").startswith(prefix))
    base = "L" + prefix.replace(".", "/")
    for i in range(total - have):
        index.classes.add(f"{base}Filler{i:04d};")


def scooter_scenario() -> tuple[FakeIndex, ManifestFacts, list[str]]:
    """Code, manifest and tracker names of the fictional ``com.example.scooter``."""
    x = FakeIndex(dex=3)
    # cs-0001 consent control in app code
    x.add(
        "Lcom/example/scooter/settings/ConsentGate;->onConsent(Z)V",
        invokes=[("Lcom/google/firebase/analytics/FirebaseAnalytics;->setAnalyticsCollectionEnabled(Z)V", 8)],
    )
    x.add(
        "Lcom/example/scooter/MainActivity;->onCreate(Landroid/os/Bundle;)V",
        invokes=[("Lcom/example/scooter/settings/ConsentGate;->onConsent(Z)V", 4)],
    )
    x.add("Lcom/google/firebase/analytics/FirebaseAnalytics;->setAnalyticsCollectionEnabled(Z)V")
    x.add("Lcom/google/firebase/analytics/FirebaseAnalytics;->setUserId(Ljava/lang/String;)V")
    # cs-0002 Adjust reflective advertising-ID read, reached from the Application class
    x.add(
        "Lcom/adjust/sdk/Reflection;->getAdvertisingInfoObject(Landroid/content/Context;)Ljava/lang/Object;",
        strings=["com.google.android.gms.ads.identifier.AdvertisingIdClient", "getAdvertisingIdInfo"],
        invokes=[("Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;", 12)],
    )
    x.add(
        "Lcom/adjust/sdk/Util;->getGoogleAdId(Landroid/content/Context;)Ljava/lang/String;",
        invokes=[
            ("Lcom/adjust/sdk/Reflection;->getAdvertisingInfoObject(Landroid/content/Context;)Ljava/lang/Object;", 6)
        ],
    )
    x.add(
        "Lcom/adjust/sdk/ActivityHandler;->initI()V",
        invokes=[
            ("Lcom/adjust/sdk/Util;->getGoogleAdId(Landroid/content/Context;)Ljava/lang/String;", 10),
            ("Lcom/adjust/sdk/DeviceInfo;-><init>(Landroid/content/Context;)V", 20),
        ],
    )
    x.add(
        "Lcom/adjust/sdk/Adjust;->onCreate(Lcom/adjust/sdk/AdjustConfig;)V",
        invokes=[("Lcom/adjust/sdk/ActivityHandler;->initI()V", 4)],
    )
    x.add(APP_ON_CREATE, invokes=[("Lcom/adjust/sdk/Adjust;->onCreate(Lcom/adjust/sdk/AdjustConfig;)V", 30)])
    x.supers["Lcom/example/scooter/ScooterApp;"] = ("Landroid/app/Application;", [])
    # cs-0005 Adjust MAC read (ineffective for minSdk 23)
    x.add(
        "Lcom/adjust/sdk/DeviceInfo;-><init>(Landroid/content/Context;)V",
        invokes=[("Lcom/adjust/sdk/MacAddressUtil;->getRawMacAddress(Landroid/content/Context;)Ljava/lang/String;", 8)],
    )
    x.add(
        "Lcom/adjust/sdk/MacAddressUtil;->getRawMacAddress(Landroid/content/Context;)Ljava/lang/String;",
        invokes=[("Landroid/net/wifi/WifiInfo;->getMacAddress()Ljava/lang/String;", 30)],
    )
    x.classes.update({"Lcom/adjust/sdk/AdjustReferrerReceiver;"})
    # cs-0003 Braze (bo.app) ANDROID_ID, reached through a manifest service
    x.add(
        "Lbo/app/bj;->b(Landroid/content/Context;)Ljava/lang/String;",
        strings=["android_id"],
        invokes=[
            (
                "Landroid/provider/Settings$Secure;->getString(Landroid/content/ContentResolver;"
                "Ljava/lang/String;)Ljava/lang/String;",
                18,
            )
        ],
    )
    x.add(
        "Lcom/appboy/Appboy;->getDeviceId()Ljava/lang/String;",
        invokes=[("Lbo/app/bj;->b(Landroid/content/Context;)Ljava/lang/String;", 6)],
    )
    x.add(
        "Lcom/appboy/push/AppboyFirebaseMessagingService;->onNewToken(Ljava/lang/String;)V",
        invokes=[("Lcom/appboy/Appboy;->getDeviceId()Ljava/lang/String;", 2)],
    )
    x.supers["Lcom/appboy/push/AppboyFirebaseMessagingService;"] = (
        "Lcom/google/firebase/messaging/FirebaseMessagingService;",
        [],
    )
    # cs-0004 obfuscated IMEI read through a Runnable
    x.add(
        "Lq/a/a/a/a/i;->a(Landroid/content/Context;)Ljava/lang/String;",
        invokes=[("Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;", 24)],
    )
    x.add("Lq/a/a/a/a/h;->run()V", invokes=[("Lq/a/a/a/a/i;->a(Landroid/content/Context;)Ljava/lang/String;", 4)])
    x.supers["Lq/a/a/a/a/h;"] = ("Ljava/lang/Object;", ["Ljava/lang/Runnable;"])
    # cs-0006 app location
    x.add(
        "Lcom/example/scooter/ride/LocationRepo;->current(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        invokes=[
            (
                "Lcom/google/android/gms/location/FusedLocationProviderClient;->getCurrentLocation("
                "ILcom/google/android/gms/tasks/CancellationToken;)Lcom/google/android/gms/tasks/Task;",
                42,
            )
        ],
    )
    x.add(
        "Lcom/example/scooter/ride/RideViewModel;->startRide()V",
        invokes=[
            (
                "Lcom/example/scooter/ride/LocationRepo;->current(Lkotlin/coroutines/Continuation;)"
                "Ljava/lang/Object;",
                10,
            )
        ],
    )
    # cs-0007 app contacts query with CONTENT_URI
    x.add(
        "Lcom/example/scooter/invite/ContactPicker;->load()Ljava/util/List;",
        sgets=["Landroid/provider/ContactsContract$Contacts;->CONTENT_URI:Landroid/net/Uri;"],
        invokes=[(QUERY, 56)],
    )
    x.add(
        "Lcom/example/scooter/invite/InviteFragment;->onViewCreated(Landroid/view/View;Landroid/os/Bundle;)V",
        invokes=[("Lcom/example/scooter/invite/ContactPicker;->load()Ljava/util/List;", 14)],
    )
    # cs-0008 app setUserId sink
    x.add(
        "Lcom/example/scooter/auth/Session;->onLogin(Ljava/lang/String;)V",
        invokes=[("Lcom/google/firebase/analytics/FirebaseAnalytics;->setUserId(Ljava/lang/String;)V", 20)],
    )
    x.add(
        "Lcom/example/scooter/auth/LoginViewModel;->submit()V",
        invokes=[("Lcom/example/scooter/auth/Session;->onLogin(Ljava/lang/String;)V", 8)],
    )
    # four provider reads without URI evidence
    for i in range(4):
        x.add(
            f"Lcom/example/scooter/data/Store{i};->read(Landroid/net/Uri;)Landroid/database/Cursor;",
            invokes=[(QUERY, 6)],
        )
    # AdMob TCF readers (3) and a US-privacy reader (1)
    x.add(
        "Lcom/google/android/gms/ads/internal/consent/Tcf;->a()Ljava/lang/String;",
        strings=["IABTCF_TCString"],
        invokes=[(GET_STRING, 4)],
    )
    x.add(
        "Lcom/google/android/gms/ads/internal/consent/Tcf;->b()Ljava/lang/String;",
        strings=["IABTCF_gdprApplies"],
        invokes=[(GET_STRING, 4)],
    )
    x.add(
        "Lcom/google/android/gms/ads/internal/consent/Tcf;->c()Ljava/lang/String;",
        strings=["IABTCF_TCString", "IABTCF_AddtlConsent"],
        invokes=[(GET_STRING, 4)],
    )
    x.add(
        "Lcom/google/android/gms/ads/internal/consent/Usp;->a()Ljava/lang/String;",
        strings=["IABUSPrivacy_String"],
        invokes=[(GET_STRING, 4)],
    )
    x.classes.update({"Lcom/google/android/gms/ads/AdActivity;", "Lcom/adjust/sdk/AdjustConfig;"})
    # the shipped SDKs read their manifest switches (the key strings occur in their code)
    x.add(
        "Lcom/google/android/gms/measurement/internal/Cfg;->flags()V",
        strings=["firebase_analytics_collection_enabled", "google_analytics_adid_collection_enabled"],
    )
    x.add(
        "Lcom/google/firebase/crashlytics/internal/Cfg;->flags()V", strings=["firebase_crashlytics_collection_enabled"]
    )
    x.add("Lcom/google/android/gms/ads/internal/Cfg;->appId()V", strings=["com.google.android.gms.ads.APPLICATION_ID"])

    # class census of the fixture
    for prefix, total in (
        ("com.google.android.gms.measurement.", 194),
        ("com.google.firebase.analytics.", 41),
        ("com.google.firebase.crashlytics.", 120),
        ("com.google.android.gms.ads.", 812),
        ("com.adjust.sdk.", 154),
        ("bo.app.", 263),
        ("com.appboy.", 311),
    ):
        _fill(x, prefix, total)
    obfuscated = 4120 - 2  # q.a.a.a.a.h and .i are obfuscated already
    for i in range(obfuscated):
        x.classes.add(f"Lz{i // 1000}/{i % 1000:03d};")
    rest = 18234 - len(x.class_names())
    for i in range(rest):
        x.classes.add(f"Lcom/example/lib/Filler{i:05d};")

    manifest = ManifestFacts(
        package="com.example.scooter",
        min_sdk=23,
        target_sdk=34,
        application_class="com.example.scooter.ScooterApp",
        components=[
            {
                "name": "com.example.scooter.MainActivity",
                "kind": "activity",
                "permission": None,
                "actions": ["android.intent.action.MAIN"],
            },
            {
                "name": "com.appboy.push.AppboyFirebaseMessagingService",
                "kind": "service",
                "permission": None,
                "actions": ["com.google.firebase.MESSAGING_EVENT"],
            },
            {"name": "com.google.android.gms.ads.AdActivity", "kind": "activity", "permission": None, "actions": []},
            {
                "name": "com.adjust.sdk.AdjustReferrerReceiver",
                "kind": "receiver",
                "permission": None,
                "actions": ["com.android.vending.INSTALL_REFERRER"],
            },
            {
                "name": "com.google.firebase.components.ComponentDiscoveryService",
                "kind": "service",
                "permission": None,
                "actions": [],
            },
        ],
        meta_data=[
            {
                "name": "firebase_analytics_collection_enabled",
                "value": "false",
                "resolved": True,
                "scope": "application",
                "component": None,
            },
            {
                "name": "google_analytics_adid_collection_enabled",
                "value": "false",
                "resolved": True,
                "scope": "application",
                "component": None,
            },
            {
                "name": "com.google.android.gms.ads.APPLICATION_ID",
                "value": "ca-app-pub-0000000000000000~0000000000",
                "resolved": True,
                "scope": "application",
                "component": None,
            },
            {
                "name": "com.google.firebase.components:com.google.firebase.analytics.connector.internal."
                "AnalyticsConnectorRegistrar",
                "value": "com.google.firebase.components.ComponentRegistrar",
                "resolved": True,
                "scope": "component",
                "component": "com.google.firebase.components.ComponentDiscoveryService",
            },
            {
                "name": "com.google.firebase.components:com.google.firebase.crashlytics.CrashlyticsRegistrar",
                "value": "com.google.firebase.components.ComponentRegistrar",
                "resolved": True,
                "scope": "component",
                "component": "com.google.firebase.components.ComponentDiscoveryService",
            },
        ],
        permission_entries=[
            {"name": "android.permission.INTERNET", "tag": "uses-permission", "max_sdk_version": None},
            {"name": "android.permission.ACCESS_COARSE_LOCATION", "tag": "uses-permission", "max_sdk_version": None},
            {"name": "android.permission.ACCESS_FINE_LOCATION", "tag": "uses-permission", "max_sdk_version": None},
            {"name": "android.permission.READ_CONTACTS", "tag": "uses-permission", "max_sdk_version": None},
            {"name": "android.permission.READ_EXTERNAL_STORAGE", "tag": "uses-permission", "max_sdk_version": 32},
            {"name": "com.google.android.gms.permission.AD_ID", "tag": "uses-permission", "max_sdk_version": None},
        ],
        files=["AndroidManifest.xml", "classes.dex", "classes2.dex", "classes3.dex", "resources.arsc"],
    )
    trackers = ["Firebase Crashlytics", "Google AdMob", "Google Firebase Analytics"]
    return x, manifest, trackers


def strip_generator(section: dict) -> dict:
    """Copy of a section without the run-specific ``generator`` block."""
    out = dict(section)
    out.pop("generator", None)
    return out


_VOCAB = re.compile(r"\b(collects|collected|shares|shared|sends|sent|reads|are read|passes)\b", re.IGNORECASE)
_ALLOWED_BEFORE = ("can", "may", "code that", "documents", "documentation", "declared")


def vocabulary_violations(text: str) -> list[str]:
    """Matches of the §4.5 action words not preceded (within 3 words) by an allowed word."""
    bad = []
    for match in _VOCAB.finditer(text):
        before = " ".join(text[: match.start()].lower().split()[-3:])
        if not any(word in before for word in _ALLOWED_BEFORE):
            bad.append(match.group(0))
    return bad


# ------------------------------------------------------------- contract checks
def _keys(obj: dict) -> set[str]:
    return set(obj)


def check_contract(section: dict) -> None:
    """Assert the §1.2-§1.4 shape: the fixture's key set per object type and closed enum values.

    Optional keys (``*(opt)*`` in the design) are allowed to be missing.
    """
    import json

    from dexray_insight.privacy import catalogue as c

    fixture = json.loads(CONTRACT.read_text())["privacy_analysis"]
    assert section["schema_version"] == 1
    assert section["status"] in c.SECTION_STATUSES
    if section["status"] == "failure":
        assert {"schema_version", "status", "errors"} <= set(section)
        return
    assert set(section) == set(fixture)
    for key in ("generator", "app", "coverage"):
        assert set(section[key]) == set(fixture[key]), key
    assert section["coverage"]["obfuscation_level"] in c.OBFUSCATION_LEVELS
    assert all(r in c.COVERAGE_REDUCTIONS for r in section["coverage"]["reduced_by"])
    assert isinstance(section["coverage"]["code_analysed"], bool)
    row_keys = set(fixture["data_safety"]["rows"][0])
    for row in section["data_safety"]["rows"]:
        assert set(row) == row_keys
        assert row["status"] in c.ROW_STATUSES and row["confidence"] in c.CONFIDENCES
        assert row["coverage_caveat"] is None or isinstance(row["coverage_caveat"], str)
        assert all(p in c.PURPOSES for p in row["purpose_hints"])
        for o in row["origins"]:
            assert set(o) == {"type", "sdk_id", "name", "call_site_count"} and o["type"] in c.ORIGIN_TYPES
        if row["sharing_hint"] is not None:
            assert set(row["sharing_hint"]) == {"value", "confidence", "sdk_ids", "reason"}
            assert row["sharing_hint"]["value"] in c.SHARING_HINTS
        for e in row["evidence"]:
            assert {"kind", "confidence", "source"} <= set(e)
            assert e["kind"] in c.EVIDENCE_KINDS and e["confidence"] in c.CONFIDENCES
            assert set(e) <= {
                "kind",
                "confidence",
                "source",
                "api_id",
                "origin",
                "count",
                "call_site_ids",
                "sdk_id",
                "mode",
                "item",
                "collects_status",
                "permission",
                "flag",
                "value",
                "note",
            }
            if e["kind"] in c.CALL_SITE_EVIDENCE_KINDS:
                assert {"api_id", "origin", "count", "call_site_ids"} <= set(e)
            if "collects_status" in e:
                assert e["collects_status"] in c.COLLECT_STATUSES
    site_keys = set(fixture["call_sites"][0])
    for site in section["call_sites"]:
        assert set(site) == site_keys
        assert re.match(r"^cs-\d{4,}$", site["id"])
        assert site["match"] in c.MATCHES and site["role"] in c.ROLES
        assert site["reachability"] in c.REACHABILITIES and site["confidence"] in c.CONFIDENCES
        assert site["evidence_kind"] is None or site["evidence_kind"] in c.EVIDENCE_KINDS
        assert set(site["caller"]) == {"class", "method", "descriptor", "offset"}
        assert " " not in (site["caller"]["descriptor"] or "") and " " not in site["api"]
        assert set(site["origin"]) == {"type", "sdk_id", "name", "confidence", "rule", "via", "evidence"}
        assert all(isinstance(e, str) for e in site["origin"]["evidence"])
        if site["bridge"] is not None:
            assert site["reachability"] == "bridge_entry"
            assert set(site["bridge"]) == {"kind", "entry", "name_in_bundle"}
            assert site["bridge"]["kind"] in c.BRIDGE_KINDS
        assert site["origin"]["type"] in c.ORIGIN_TYPES and site["origin"]["rule"] in c.ORIGIN_RULES
        assert set(site["permission"]) == {"required", "declared", "satisfied"}
        assert set(site["api_level"]) == set(fixture["call_sites"][0]["api_level"])
        assert len(site["chain"]) <= 6
        if site["uri_evidence"] is not None:
            assert site["uri_evidence"]["kind"] in c.URI_EVIDENCE_KINDS
            assert site["uri_evidence"]["where"] in c.URI_EVIDENCE_WHERE
    ids = [s["id"] for s in section["call_sites"]]
    assert ids == [f"cs-{i:04d}" for i in range(1, len(ids) + 1)]
    sdk_keys = set(fixture["sdks"][0])
    for sdk in section["sdks"]:
        assert set(sdk) == sdk_keys
        assert sdk["role"] in c.SDK_ROLES and sdk["confidence"] in c.CONFIDENCES
        assert sdk["sharing_hint"] in c.SHARING_HINTS
        for d in sdk["detection"]:
            assert d["kind"] in c.DETECTION_KINDS
    for perm in section["permissions"]:
        assert set(perm) == set(fixture["permissions"][0])
    for flag in section["manifest_flags"]:
        assert set(flag) == set(fixture["manifest_flags"][0])
        assert flag["state"] in c.FLAG_STATES and flag["effect"] in c.FLAG_EFFECTS
    assert set(section["consent"]) == set(fixture["consent"])
    assert section["consent"]["verdict"] in c.CONSENT_VERDICTS
    for ch in ("tcf", "gpp", "us_privacy"):
        assert set(section["consent"][ch]) == set(fixture["consent"]["tcf"])
    finding_ids = [f["id"] for f in section["findings"]]
    assert finding_ids == sorted(finding_ids, key=c.FINDING_IDS.index)
    for f in section["findings"]:
        assert set(f) == set(fixture["findings"][0])
        assert set(f["evidence"]) == {"call_site_ids", "sdk_ids", "permissions", "data_types"}
        assert f["severity"] in c.SEVERITIES and f["confidence"] in c.CONFIDENCES
        for values in f["evidence"].values():
            assert values == sorted(values)
    assert list(section["compliance_refs"]) == sorted(section["compliance_refs"])
    used = {r for row in section["data_safety"]["rows"] for r in row["compliance"]}
    used |= {r for f in section["findings"] for r in f["compliance"]}
    assert used == set(section["compliance_refs"])


def static_texts(section: dict) -> list[str]:
    """Every static sentence of a section: titles, summaries, reasons, notes, the disclaimer."""
    texts = [section.get("disclaimer", "")]
    texts += section.get("coverage", {}).get("notes", [])
    for row in section.get("data_safety", {}).get("rows", []):
        if row["sharing_hint"]:
            texts.append(row["sharing_hint"]["reason"])
        texts += [e["note"] for e in row["evidence"] if e.get("note")]
    for f in section.get("findings", []):
        texts += [f["title"], f["summary"]]
    texts += [r["coverage_caveat"] for r in section.get("data_safety", {}).get("rows", []) if r["coverage_caveat"]]
    return texts
