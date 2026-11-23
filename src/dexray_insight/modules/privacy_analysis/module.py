# SPDX-License-Identifier: GPL-3.0-only
"""The ``privacy_analysis`` module: a draft Data safety label from static analysis.

:func:`analyse` is the whole pipeline over a :class:`~.scanner.CodeIndex` and
:class:`ManifestFacts`; :class:`PrivacyAnalysisModule` adapts it to the engine
(androguard objects in, :class:`PrivacyAnalysisResult` out). The result contract
is documented in ``docs/privacy_analysis.rst``.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from dataclasses import field
from typing import Any

from ...core.base_classes import AnalysisContext
from ...core.base_classes import AnalysisStatus
from ...core.base_classes import BaseAnalysisModule
from ...core.base_classes import BaseResult
from ...core.base_classes import register_module
from ...privacy.catalogue import ANDROID_REFERENCE_API
from ...privacy.catalogue import DETECTION_KINDS
from ...privacy.catalogue import SCHEMA_VERSION
from ...privacy.catalogue import Catalogue
from ...privacy.catalogue import dotted_class
from ...privacy.catalogue import jvm_class
from ...privacy.catalogue import load_catalogue
from ...privacy.catalogue import split_method_ref
from .attribution import Attributor
from .attribution import SdkTrie
from .attribution import build_app_namespaces
from .attribution import is_obfuscated
from .attribution import package_of
from .label import DISCLAIMER
from .label import api_level_object
from .label import apply_modifiers
from .label import base_confidence
from .label import build_findings
from .label import build_rows
from .label import collects_status
from .label import consent_verdict
from .label import effective_sharing
from .label import evidence_kind_of
from .label import origin_key
from .label import origin_short
from .label import permission_object
from .label import sdk_evidence_items
from .scanner import AndroguardIndex
from .scanner import CodeIndex
from .scanner import Matcher
from .scanner import MRef
from .scanner import Reachability
from .scanner import combined_pattern
from .scanner import host_in

logger = logging.getLogger(__name__)

DEFAULT_CONFIG = {
    "max_call_sites_per_api": 1000,
    "reachability_max_sites_per_api": 200,
    "reachability_max_depth": 6,
    "reachability_max_nodes": 200,
    "string_anchor_attribution": True,
}
NOTE_RUNTIME_CODE = "Code loaded at runtime (from assets or downloads) and native code are not analysed."
NOTE_CURATED = "SDK attribution covers the curated SDK list only; other third-party code is shown by package name."
_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
_COMPONENT_TAGS = {
    "activity": "activity",
    "activity-alias": "activity",
    "service": "service",
    "receiver": "receiver",
    "provider": "provider",
}
_FRAMEWORKS = {
    "flutter": "flutter",
    "react native": "react_native",
    "xamarin": "xamarin",
    ".net maui": "xamarin",
    "xamarin/.net maui": "xamarin",
    "cordova/ionic": "cordova",
    "unity": "unity",
}
_SECONDARY_CODE = re.compile(r"^assets/.+\.(dex|jar|apk)$", re.IGNORECASE)


# ------------------------------------------------------------------ manifest facts
@dataclass
class ManifestFacts:
    """What the privacy layer reads from the manifest and the APK file list.

    Class names are dotted. ``meta_data`` items are ``{name, value, resolved, scope,
    component}``; ``components`` items are ``{name, kind, permission, actions}``;
    ``permission_entries`` are ``{name, tag, max_sdk_version}`` in manifest order.
    """

    package: str | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    application_class: str | None = None
    components: list[dict[str, Any]] = field(default_factory=list)
    meta_data: list[dict[str, Any]] = field(default_factory=list)
    startup_initializers: list[str] = field(default_factory=list)
    permission_entries: list[dict[str, Any]] = field(default_factory=list)
    files: list[str] = field(default_factory=list)

    @classmethod
    def from_apk(cls, apk: Any) -> ManifestFacts:
        """Read the facts from an androguard ``APK`` object."""
        from ...apk_overview.requested_permissions import requested_permission_entries

        package = _safe(apk.get_package)
        facts = cls(
            package=package,
            min_sdk=_int(_safe(apk.get_min_sdk_version)),
            target_sdk=_int(_safe(apk.get_target_sdk_version)),
            permission_entries=requested_permission_entries(apk),
            files=sorted(str(f) for f in (_safe(apk.get_files) or [])),
        )
        manifest = _safe(apk.get_android_manifest_xml)
        application = manifest.find("application") if manifest is not None else None
        if application is not None:
            name = application.get(_ANDROID_NS + "name")
            facts.application_class = _full_name(name, package) if name else None
            resources = _safe(apk.get_android_resources)
            for child in application:
                tag = child.tag if isinstance(child.tag, str) else ""
                if tag == "meta-data":
                    facts.meta_data.append(_meta(child, "application", None, resources))
                    continue
                kind = _COMPONENT_TAGS.get(tag)
                if not kind:
                    continue
                raw_name = child.get(_ANDROID_NS + ("targetActivity" if tag == "activity-alias" else "name"))
                if not raw_name:
                    continue
                comp_name = _full_name(raw_name, package)
                actions = sorted(
                    {
                        str(action.get(_ANDROID_NS + "name"))
                        for flt in child.findall("intent-filter")
                        for action in flt.findall("action")
                        if action.get(_ANDROID_NS + "name")
                    }
                )
                facts.components.append(
                    {
                        "name": comp_name,
                        "kind": kind,
                        "permission": child.get(_ANDROID_NS + "permission"),
                        "actions": actions,
                    }
                )
                for meta in child.findall("meta-data"):
                    item = _meta(meta, "component", comp_name, resources)
                    facts.meta_data.append(item)
                    if comp_name == "androidx.startup.InitializationProvider" and item["value"] == "androidx.startup":
                        facts.startup_initializers.append(item["name"])
        return facts

    def effective_permissions(self) -> dict[str, dict[str, Any]]:
        """Effectively declared permissions: a request with ``maxSdkVersion < min_sdk`` is dropped."""
        out: dict[str, dict[str, Any]] = {}
        for entry in self.permission_entries:
            name = entry.get("name")
            if not name:
                continue
            max_sdk = entry.get("max_sdk_version")
            if self.min_sdk is not None and isinstance(max_sdk, int) and max_sdk < self.min_sdk:
                continue
            slot = out.setdefault(name, {"max_sdk_version": max_sdk})
            old = slot["max_sdk_version"]
            slot["max_sdk_version"] = None if old is None or max_sdk is None else max(old, max_sdk)
        return out


def _safe(fn: Callable[[], Any]) -> Any:
    try:
        return fn()
    except Exception:
        return None


def _int(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _full_name(name: str, package: str | None) -> str:
    if name.startswith(".") and package:
        return package + name
    if "." not in name and package:
        return f"{package}.{name}"
    return name


def _meta(element: Any, scope: str, component: str | None, resources: Any) -> dict[str, Any]:
    name = element.get(_ANDROID_NS + "name") or ""
    value = element.get(_ANDROID_NS + "value")
    if value is None:
        value = element.get(_ANDROID_NS + "resource")
    resolved = True
    if isinstance(value, str) and value.startswith("@"):
        resolved_value = _resolve_ref(value, resources)
        if resolved_value is None:
            resolved = False
        else:
            value = resolved_value
    return {
        "name": str(name),
        "value": None if value is None else str(value),
        "resolved": resolved,
        "scope": scope,
        "component": component,
    }


def _resolve_ref(ref: str, resources: Any) -> str | None:
    """Resolve ``@7F050001`` through the ARSC (default config); None when impossible."""
    if resources is None:
        return None
    try:
        res_id = int(ref[1:].split(":")[-1], 16)
        configs = resources.get_resolved_res_configs(res_id)
        for _config, value in configs or []:
            if value is not None:
                return str(value)
    except Exception:
        return None
    return None


# ---------------------------------------------------------------------- pipeline
class _Steps:
    """Runs pipeline steps; a failing step adds to ``errors`` and yields its default."""

    def __init__(self) -> None:
        self._counts: dict[str, int] = {}

    def record(self, name: str, exc: Exception) -> None:
        """Count one failure; the message has no memory addresses (byte-stable output)."""
        text = re.sub(r" at 0x[0-9a-fA-F]+", "", str(exc))[:300]
        message = f"{name}: {type(exc).__name__}: {text}"
        self._counts[message] = self._counts.get(message, 0) + 1

    @property
    def errors(self) -> list[str]:
        """De-duplicated messages, sorted; repeated ones carry ``(xN)``."""
        return sorted(m if n == 1 else f"{m} (x{n})" for m, n in self._counts.items())

    def run(self, name: str, fn: Callable[[], Any], default: Any) -> Any:
        try:
            return fn()
        except Exception as exc:
            logger.debug("privacy_analysis step %s failed", name, exc_info=True)
            self.record(name, exc)
            return default


def _norm_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _tracker_values(sdk: dict[str, Any], tracker_names: list[str], sig_db: dict[str, Any]) -> list[str]:
    """Signature-DB ids of this SDK whose tracker name was reported by ``tracker_analysis``."""
    reported = {n.lower() for n in tracker_names if n}
    out = []
    for db_id in sdk["tracker_db_ids"]:
        entry = sig_db.get(db_id) or {}
        name = str(entry.get("name") or "").lower()
        if name and name in reported:
            out.append(db_id)
    if not out and sdk["name"].lower() in reported and sdk["tracker_db_ids"]:
        out.append(sdk["tracker_db_ids"][0])
    return sorted(set(out))


def _detect(
    items: list[dict[str, Any]],
    prefix_counts: dict[tuple[str, str], int],
    internal: set[str],
    component_names: set[str],
    meta_names: set[str],
    string_hits: dict[str, list[str]],
    tracker_names: list[str],
    sig_db: dict[str, Any],
) -> list[dict[str, Any]]:
    """Detection evidence and confidence for SDKs or CMPs (only detected ones are returned).

    ``tracker_analysis`` evidence corroborates but never detects an entry on its own.
    """
    out = []
    for entry in items:
        detection = []
        prefix_sources = set()
        for item in entry.get("prefixes", []) + entry.get("obfuscated_prefixes", []):
            n = prefix_counts.get((entry["id"], item["prefix"]), 0)
            if n:
                detection.append({"kind": "class_prefix", "value": item["prefix"], "count": n})
                prefix_sources.add(item["source"])
        anchored = False
        for anchor in entry.get("anchors", []):
            value = anchor["value"]
            hit = (
                (anchor["kind"] == "class_anchor" and jvm_class(value) in internal)
                or (anchor["kind"] == "manifest_component" and value in component_names)
                or (anchor["kind"] == "manifest_meta_data" and value in meta_names)
            )
            if hit:
                anchored = True
                detection.append({"kind": anchor["kind"], "value": value})
        for value in string_hits.get(entry["id"], []):
            detection.append({"kind": "string_anchor", "value": value})
        if not detection:
            continue
        for db_id in _tracker_values(entry, tracker_names, sig_db) if "tracker_db_ids" in entry else []:
            detection.append({"kind": "tracker_analysis", "value": db_id})
        has_prefix = bool(prefix_sources)
        confidence = "high" if has_prefix and anchored else "medium" if (has_prefix or anchored) else "low"
        unique_det = {(d["kind"], d["value"]): d for d in detection}
        detection = sorted(unique_det.values(), key=lambda d: (DETECTION_KINDS.index(d["kind"]), d["value"]))
        out.append(
            {"entry": entry, "detection": detection, "confidence": confidence, "prefix_sources": sorted(prefix_sources)}
        )
    return out


def _flag_state(flag: dict[str, Any], meta: list[dict[str, Any]], read: bool | None = True) -> dict[str, Any]:
    """The emitted ManifestFlag.

    Android keeps the **last** ``<meta-data>`` value for a repeated key. ``read`` says
    whether the detected SDK's code contains the key at all (``None`` = not checked);
    a key the shipped SDK does not read never yields ``off`` (it becomes ``unknown``).
    """
    app = [m for m in meta if m["scope"] == "application" and m["name"] == flag["key"]]
    comp = [m for m in meta if m["scope"] == "component" and m["name"] == flag["key"]]
    out = {
        "key": flag["key"],
        "sdk_id": flag["sdk_id"],
        "value": None,
        "resolved": True,
        "scope": "application",
        "state": "default",
    }
    if app:
        item = app[-1]
        out["value"] = item["value"]
        out["resolved"] = item["resolved"]
        if not item["resolved"]:
            out["state"] = "unknown"
        elif flag["type"] == "presence":
            out["state"] = "on"
        else:
            out["state"] = "off" if str(item["value"]).strip().lower() in flag["off_when"] else "on"
    elif comp:
        out["value"] = comp[-1]["value"]
        out["resolved"] = comp[-1]["resolved"]
        out["scope"] = "component"
    if read is False and out["state"] in ("off", "on"):
        out["state"] = "unknown"
    out.update(
        {
            "effect": flag["effect"],
            "default_when_absent": flag["default_when_absent"],
            "data_types": list(flag["data_types"]),
            "items": list(flag["items"]) if flag["items"] is not None else None,
            "source": f"docs:{flag['sources'][0]}",
            "read_by_sdk": read,
        }
    )
    return out


def _framework_words(files: list[str]) -> list[str]:
    from ...apk_overview.app import detect_framework

    native = [f for f in files if f.startswith("lib/") and f.endswith(".so")]
    name = str(detect_framework(files, native) or "").lower()
    word = _FRAMEWORKS.get(name)
    return [word] if word else []


def _scan_strings(index: CodeIndex, cat: Catalogue) -> dict[str, Any]:
    """One pass over the DEX strings with one combined regex (04-design §2.4 step 5)."""
    iab = cat.iab_keys
    literals: list[str] = []
    for sdk in cat.sdks:
        literals += [h["host"] for h in sdk["hosts"]] + [a["value"] for a in sdk["string_anchors"]]
    literals += [iab["tcf_prefix"], iab["gpp_prefix"]] + iab["us_privacy"] + iab["google_ac"]
    literals += iab["tcf_known"] + iab["gpp_known"]
    literals += cat.markers["photo_picker"]["strings"]
    pattern = combined_pattern(literals)
    out: dict[str, Any] = {"sdk": {}, "tcf": [], "gpp": [], "usp": [], "google_ac": [], "picker": []}
    if pattern is None:
        return out
    picker = set(cat.markers["photo_picker"]["strings"])
    for value in index.strings():
        if not pattern.search(value):
            continue
        for sdk in cat.sdks:
            for host in sdk["hosts"]:
                if host_in(value, host["host"]):
                    out["sdk"].setdefault(sdk["id"], {}).setdefault(host["host"], []).append(value)
            for anchor in sdk["string_anchors"]:
                if anchor["value"] in value:
                    out["sdk"].setdefault(sdk["id"], {}).setdefault(anchor["value"], []).append(value)
        if value in iab["google_ac"]:
            out["google_ac"].append(value)  # reported as google_additional_consent, not as a TCF key
        elif value.startswith(iab["tcf_prefix"]) or value in iab["tcf_known"]:
            out["tcf"].append(value)
        if value.startswith(iab["gpp_prefix"]) or value in iab["gpp_known"]:
            out["gpp"].append(value)
        if value in iab["us_privacy"]:
            out["usp"].append(value)
        if value in picker:
            out["picker"].append(value)
    return out


def _channel(
    index: CodeIndex, keys: list[str], readers: set[MRef], writers: set[MRef], attributor: Attributor
) -> dict[str, Any]:
    """Readers and writers of one IAB key family."""
    reader_methods: set[MRef] = set()
    writer_methods: set[MRef] = set()
    used_keys = set()
    for key in sorted(set(keys)):
        users = index.string_users(key)
        if users:
            used_keys.add(key)
        for method in users:
            calls = {m for m, _ in index.facts(method).invokes}
            hop = set()
            for callee in sorted(calls):
                if index.is_internal_method(callee):
                    hop |= {m for m, _ in index.facts(callee).invokes}
            if (calls | hop) & readers:
                reader_methods.add(method)
            if (calls | hop) & writers:
                writer_methods.add(method)

    def by_origin(methods: set[MRef]) -> list[dict[str, Any]]:
        counts: dict[tuple, dict[str, Any]] = {}
        for method in sorted(methods):
            origin = attributor.frame_origin(method)
            slot = counts.setdefault(origin.key(), {"origin": origin.short(), "count": 0})
            slot["count"] += 1
        return [counts[k] for k in sorted(counts)]

    return {
        "keys": sorted(used_keys),
        "reads": bool(reader_methods),
        "writes": bool(writer_methods),
        "readers": by_origin(reader_methods),
        "writers": by_origin(writer_methods),
    }


def _refs(values: list[str]) -> set[MRef]:
    out = set()
    for ref in values:
        try:
            out.add(MRef(*split_method_ref(ref)))
        except ValueError:
            continue
    return out


def failure_section(errors: list[str]) -> dict[str, Any]:
    """The stub for a run that could not produce a section."""
    return {"schema_version": SCHEMA_VERSION, "status": "failure", "errors": list(errors)}


def analyse(
    index: CodeIndex,
    manifest: ManifestFacts,
    catalogue: Catalogue,
    config: dict[str, Any] | None = None,
    tracker_names: list[str] | None = None,
    insight_version: str | None = None,
) -> dict[str, Any]:
    """Run the privacy pipeline and return the ``privacy_analysis`` section.

    Never raises for a failing inner step: the step is recorded in ``errors`` and
    the section becomes ``partial`` with every top-level key present.

    Args:
        index: Code index (androguard or fake).
        manifest: Manifest facts.
        catalogue: Loaded catalogue.
        config: Module config (see :data:`DEFAULT_CONFIG`).
        tracker_names: ``DetectedTracker.name`` values from ``tracker_analysis``.
        insight_version: Value for ``generator.insight_version``.
    """
    started = time.perf_counter()
    cfg = {**DEFAULT_CONFIG, **(config or {})}
    cat = catalogue
    steps = _Steps()
    tracker_names = sorted(tracker_names or [])
    if insight_version is None:
        from ...about import __version__ as insight_version
    declared = manifest.effective_permissions()
    app_class_jvm = jvm_class(manifest.application_class) if manifest.application_class else None
    component_names = {c["name"] for c in manifest.components}
    meta_names = {m["name"] for m in manifest.meta_data}

    trie = SdkTrie(cat.sdks)
    cmp_trie = SdkTrie(cat.cmps)
    namespaces = steps.run(
        "app_namespaces",
        lambda: build_app_namespaces(
            manifest.package, manifest.application_class, trie, cat.shared_roots, cat.framework_prefixes
        ),
        [],
    )

    # class census
    def census() -> dict[str, Any]:
        classes = index.class_names()
        counts: dict[tuple[str, str], int] = {}
        cmp_counts: dict[tuple[str, str], int] = {}
        obfuscated = 0
        for cls in classes:
            dotted = dotted_class(cls)
            if is_obfuscated(cls):
                obfuscated += 1
            for sdk_id, _kind, prefix in trie.matches(dotted):
                counts[(sdk_id, prefix)] = counts.get((sdk_id, prefix), 0) + 1
            for cmp_id, _kind, prefix in cmp_trie.matches(dotted):
                cmp_counts[(cmp_id, prefix)] = cmp_counts.get((cmp_id, prefix), 0) + 1
        return {
            "classes": set(classes),
            "total": len(classes),
            "obfuscated": obfuscated,
            "counts": counts,
            "cmp_counts": cmp_counts,
        }

    cen = steps.run("census", census, {"classes": set(), "total": 0, "obfuscated": 0, "counts": {}, "cmp_counts": {}})
    strings = steps.run(
        "strings",
        lambda: _scan_strings(index, cat),
        {"sdk": {}, "tcf": [], "gpp": [], "usp": [], "google_ac": [], "picker": []},
    )

    def anchor_hits() -> dict[str, dict[str, int]]:
        hits: dict[str, dict[str, int]] = {}
        for sdk_id in sorted(strings["sdk"]):
            for values in strings["sdk"][sdk_id].values():
                for value in sorted(set(values)):
                    for method in index.string_users(value):
                        slot = hits.setdefault(method.cls, {})
                        slot[sdk_id] = slot.get(sdk_id, 0) + 1
        return hits

    hits = steps.run("string_anchors", anchor_hits, {})
    component_sdks: dict[str, set[str]] = {}
    for comp in sorted(component_names):
        owners = {m[0] for m in trie.matches(comp)}
        owners |= {
            s["id"]
            for s in cat.sdks
            if any(a["kind"] == "manifest_component" and a["value"] == comp for a in s["anchors"])
        }
        if owners:
            component_sdks.setdefault(package_of(jvm_class(comp)), set()).update(owners)
    attributor = Attributor(
        index,
        cat.sdks,
        trie,
        namespaces,
        hits,
        component_sdks,
        bool(cfg["string_anchor_attribution"]),
        set(cat.wrapper_classes),
    )
    entry_classes = {jvm_class(n) for n in component_names}
    entry_classes |= {jvm_class(n) for n in manifest.startup_initializers}
    if app_class_jvm:
        entry_classes.add(app_class_jvm)
    reach = Reachability(
        index, attributor.is_app_class, entry_classes, cfg["reachability_max_depth"], cfg["reachability_max_nodes"]
    )

    # matching
    matcher = Matcher(index, cat, attributor, manifest.components)
    raw = []
    for name, fn in (
        ("method_calls", matcher.method_calls),
        ("provider_reads", matcher.provider_reads),
        ("field_reads", matcher.field_reads),
        ("reflection", matcher.reflective),
        ("manifest_components", matcher.manifest_components),
    ):
        raw.extend(steps.run(name, fn, []))

    # sort, de-duplicate, cap
    raw.sort(key=lambda r: (r.sort_key(), r.match, r.api, tuple(r.via)))
    deduped = []
    seen_keys = set()
    for site in raw:
        key = site.sort_key()
        if key in seen_keys:
            continue
        seen_keys.add(key)
        deduped.append(site)
    limits: list[str] = []
    per_api: dict[str, int] = {}
    kept = []
    dropped: dict[str, int] = {}
    for site in deduped:
        api_id = site.entry["id"]
        n = per_api.get(api_id, 0)
        per_api[api_id] = n + 1
        if n >= int(cfg["max_call_sites_per_api"]):
            dropped[api_id] = dropped.get(api_id, 0) + 1
            continue
        kept.append((n, site))
    for api_id in sorted(dropped):
        limits.append(f"max_call_sites_per_api:{api_id}:{dropped[api_id]}")

    # emit call sites
    sites: list[dict[str, Any]] = []
    site_meta: dict[str, dict[str, Any]] = {}
    unknown = 0

    def dangerous(perm: str) -> bool:
        entry = cat.permissions.get(perm)
        if entry is not None:
            return entry["dangerous"]
        try:
            from ...apk_overview.dvm_permissions import DVM_PERMISSIONS

            info = DVM_PERMISSIONS.get("MANIFEST_PERMISSION", {}).get(perm.rsplit(".", 1)[-1])
            return bool(info) and str(info[0]).lower() == "dangerous"
        except Exception:
            return False

    def emit(pos: int, site: Any) -> tuple[dict[str, Any], dict[str, Any], bool]:
        entry = site.entry
        if site.match == "manifest_component":
            perm = {"required": None, "declared": [], "satisfied": None}
            reachability = "app_code" if site.origin.type == "app" else "sdk_entry"
            chain: list[str] = []
            deciding = None
        else:
            perm = permission_object(entry["permission"], set(declared))
            if pos < int(cfg["reachability_max_sites_per_api"]):
                result = steps.run("reachability", lambda: reach.reach(site.caller), None)
                if result is None:
                    reachability, chain, deciding = "unknown", [site.caller.frame()], None
                else:
                    reachability, chain, deciding = result.reachability, result.chain, result.deciding
            else:
                reachability, chain, deciding = "not_checked", [], None
        level = api_level_object(entry["api"], manifest.min_sdk)
        kind = evidence_kind_of(entry["role"], site.match, level["effective_for_app"], reachability)
        origin = {
            "type": site.origin.type,
            "sdk_id": site.origin.sdk_id,
            "name": site.origin.name,
            "confidence": site.origin.confidence,
            "rule": site.origin.rule,
            "via": list(site.via),
        }
        base = base_confidence(kind, entry["precision"], site.uri_confidence, site.reflect_confidence)
        confidence = apply_modifiers(base, kind, origin, perm["satisfied"], reachability)
        type_conf = {}
        for dt in entry["data_types"]:
            needed = entry["type_permissions"].get(dt)
            met = not needed or any(p in declared for p in needed)
            type_conf[dt] = apply_modifiers(base, kind, origin, perm["satisfied"], reachability, met)
        required = next(iter(entry["permission"].values())) if entry["permission"] else []
        meta = {
            "type_conf": type_conf,
            "sdk_id": entry["sdk_id"] if entry["role"] == "sink" else None,
            "dangerous_unsatisfied": perm["satisfied"] is False and any(dangerous(p) for p in required),
            "non_resettable": entry["non_resettable"],
            "deciding_app_class": bool(deciding is not None and app_class_jvm and deciding.cls == app_class_jvm),
            "controls_sdk_id": entry["controls_sdk_id"],
        }
        return (
            {
                "id": "",
                "api_id": entry["id"],
                "api_label": site.api_label,
                "api": site.api,
                "match": site.match,
                "role": entry["role"],
                "data_types": sorted(entry["data_types"]),
                "caller": {
                    "class": site.caller_class,
                    "method": site.caller.name if site.caller else None,
                    "descriptor": site.caller.desc if site.caller else None,
                    "offset": site.offset if site.caller else None,
                },
                "origin": origin,
                "reachability": reachability,
                "chain": chain,
                "uri_evidence": site.uri_evidence,
                "permission": perm,
                "api_level": level,
                "evidence_kind": kind,
                "confidence": confidence,
            },
            meta,
            reachability == "unknown",
        )

    for pos, site in kept:
        try:
            emitted, meta, was_unknown = emit(pos, site)
        except Exception as exc:  # one bad entry never fails the section
            logger.debug("privacy_analysis: emitting a %s site failed", site.entry.get("id"), exc_info=True)
            steps.record(f"call_site {site.entry.get('id')}", exc)
            continue
        emitted["id"] = f"cs-{len(sites) + 1:04d}"
        site_meta[emitted["id"]] = meta
        sites.append(emitted)
        unknown += int(was_unknown)
    if unknown:
        limits.append(f"reachability_budget:{unknown}")

    # SDKs, flags, consent controls
    sig_db = steps.run("signature_db", _signature_db, {})
    detected = steps.run(
        "sdk_detection",
        lambda: _detect(
            cat.sdks,
            cen["counts"],
            cen["classes"],
            component_names,
            meta_names,
            {k: sorted(v) for k, v in strings["sdk"].items()},
            tracker_names,
            sig_db,
        ),
        [],
    )
    detected_ids = {d["entry"]["id"] for d in detected}

    def key_read(key: str) -> bool | None:
        """True if non-app code of the APK contains the flag key (the shipped SDK reads it)."""
        try:
            return any(not attributor.is_app_class(m.cls) for m in index.string_users(key))
        except Exception:
            return None

    flags = [
        _flag_state(f, manifest.meta_data, key_read(f["key"]))
        for f in cat.manifest_flags
        if f["sdk_id"] in detected_ids
    ]
    # A consent control counts unless the SDK it controls calls it itself: app code,
    # obfuscated (R8-repackaged) app code and bridge libraries all switch it at runtime.
    controlled = {
        site_meta[s["id"]]["controls_sdk_id"]
        for s in sites
        if s["role"] == "consent_control"
        and site_meta[s["id"]]["controls_sdk_id"]
        and s["origin"]["sdk_id"] != site_meta[s["id"]]["controls_sdk_id"]
    }
    class_list = sorted(cen["classes"])

    def feature_present(collect: dict[str, Any]) -> bool:
        """A feature-conditional ``collects`` item applies only with evidence of the feature."""
        req = collect.get("requires") or {}
        perms, prefixes = req.get("permissions_any") or [], req.get("class_prefixes_any") or []
        if not perms and not prefixes:
            return True
        if any(p in declared for p in perms):
            return True
        jvm_prefixes = tuple("L" + p.replace(".", "/") for p in prefixes)
        return bool(jvm_prefixes) and any(c.startswith(jvm_prefixes) for c in class_list)

    sdks: list[dict[str, Any]] = []
    sdk_evidence: list[dict[str, Any]] = []

    def build_sdks() -> None:
        for det in detected:
            entry = dict(det["entry"])
            entry["collects"] = [
                c if feature_present(c) else {**c, "mode": "depends_on_usage"} for c in entry["collects"]
            ]
            sdk_flags = [f for f in flags if f["sdk_id"] == entry["id"]]
            statuses = [
                collects_status(entry["id"], c, sdk_flags, entry["id"] in controlled) for c in entry["collects"]
            ]
            labels = []
            for db_id in entry["tracker_db_ids"]:
                label = (sig_db.get(db_id) or {}).get("label")
                if label and label not in labels:
                    labels.append(label)
            sdk = {
                "id": entry["id"],
                "name": entry["name"],
                "role": entry["role"],
                "confidence": det["confidence"],
                "detection": det["detection"],
                "recipient_labels": labels,
                "tracker_db_ids": list(entry["tracker_db_ids"]),
                "collects": [
                    {
                        "data_type": c["data_type"],
                        "item": c.get("item"),
                        "mode": c["mode"],
                        "status": st,
                        "source": f"vendor:{c['source']}",
                    }
                    for c, (st, _f) in zip(entry["collects"], statuses, strict=True)
                ],
                "flags": sorted(f["key"] for f in sdk_flags),
                "call_site_count": sum(1 for s in sites if s["origin"]["sdk_id"] == entry["id"]),
                "sharing_hint": effective_sharing(entry),
                "references": dict(entry["references"]),
                "prefix_sources": det["prefix_sources"],
            }
            sdks.append(sdk)
            sdk_evidence.extend(sdk_evidence_items(sdk, entry, statuses, declared))

    steps.run("sdk_facts", build_sdks, None)

    # consent
    empty_channel = {"keys": [], "reads": False, "writes": False, "readers": [], "writers": []}

    def build_consent() -> dict[str, Any]:
        cmps = _detect(cat.cmps, cen["cmp_counts"], cen["classes"], component_names, meta_names, {}, [], {})
        readers, writers = _refs(cat.prefs["readers"]), _refs(cat.prefs["writers"])
        channels = {
            "tcf": _channel(index, strings["tcf"], readers, writers, attributor),
            "gpp": _channel(index, strings["gpp"], readers, writers, attributor),
            "us_privacy": _channel(index, strings["usp"], readers, writers, attributor),
        }
        controls: dict[tuple, dict[str, Any]] = {}
        for s in sites:
            if s["role"] != "consent_control":
                continue
            key = (s["api_id"], origin_key(s["origin"]))
            slot = controls.setdefault(
                key,
                {
                    "api_id": s["api_id"],
                    "label": s["api_label"],
                    "origin": origin_short(s["origin"]),
                    "call_site_ids": [],
                },
            )
            slot["call_site_ids"].append(s["id"])
        return {
            "verdict": consent_verdict(list(cmps), channels, sdks),
            "cmps": sorted(
                (
                    {
                        "id": c["entry"]["id"],
                        "name": c["entry"]["name"],
                        "confidence": c["confidence"],
                        "detection": c["detection"],
                    }
                    for c in cmps
                ),
                key=lambda c: c["id"],
            ),
            **channels,
            "google_additional_consent": any(index.string_users(k) for k in sorted(set(strings["google_ac"]))),
            "controls": [
                {**controls[k], "call_site_ids": sorted(controls[k]["call_site_ids"])} for k in sorted(controls)
            ],
        }

    consent = steps.run(
        "consent",
        build_consent,
        {
            "verdict": "not_applicable",
            "cmps": [],
            "tcf": dict(empty_channel),
            "gpp": dict(empty_channel),
            "us_privacy": dict(empty_channel),
            "google_additional_consent": False,
            "controls": [],
        },
    )

    # coverage
    total = cen["total"]
    ratio = cen["obfuscated"] / total if total else 0.0
    notes = [NOTE_RUNTIME_CODE, NOTE_CURATED]
    if matcher.missing_sdk_apis:
        detected_missing = sorted(a for a in matcher.missing_sdk_apis if cat.api_by_id[a]["sdk_id"] in detected_ids)
        if detected_missing:
            notes.append(
                f"{len(detected_missing)} catalogued SDK APIs were not found by name "
                "(removed or renamed by R8, or not bundled): " + ", ".join(detected_missing)
            )
    if matcher.provider_reads_untyped:
        notes.append(
            f"{matcher.provider_reads_untyped} provider reads have URI evidence only outside the reading method; "
            "they are not typed"
        )
    flag_keys = {f["key"] for f in cat.manifest_flags}
    norm_flags = {_norm_key(k): k for k in sorted(flag_keys)}
    for name in sorted(meta_names):
        if name in flag_keys:
            continue
        target = norm_flags.get(_norm_key(name))
        if target:
            notes.append(f"manifest key {name} looks like {target} but does not match exactly; it was ignored")
    coverage = {
        "dex_files": steps.run("dex_count", index.dex_count, 0),
        "classes_total": total,
        "classes_obfuscated": cen["obfuscated"],
        "obfuscation_level": "none" if ratio < 0.05 else "light" if ratio < 0.30 else "heavy",
        "secondary_code": sorted(f for f in manifest.files if _SECONDARY_CODE.match(f)),
        "code_outside_dex": sorted(steps.run("frameworks", lambda: _framework_words(manifest.files), [])),
        "provider_reads_unresolved": matcher.provider_reads_unresolved,
        "limits_hit": sorted(limits),
        "notes": sorted(set(notes)),
    }

    # photo picker (non-androidx code only)
    def picker_used() -> bool:
        users: set[MRef] = set()
        for cls in cat.markers["photo_picker"]["classes"]:
            users.update(index.class_refs(cls))
        for value in sorted(set(strings["picker"])):
            users.update(index.string_users(value))
        return any(not dotted_class(m.cls).startswith("androidx.") for m in users)

    picker = steps.run("photo_picker", picker_used, False)

    rows = steps.run("rows", lambda: build_rows(cat, sites, site_meta, sdks, sdk_evidence, declared), [])
    findings = steps.run(
        "findings",
        lambda: build_findings(cat, sites, site_meta, sdks, flags, consent, declared, coverage, picker, controlled),
        [],
    )
    used_refs = sorted({r for row in rows for r in row["compliance"]} | {r for f in findings for r in f["compliance"]})
    permissions = []
    for name in sorted(declared):
        entry = cat.permissions.get(name)
        if not entry:
            continue
        permissions.append(
            {
                "permission": name,
                "max_sdk_version": declared[name]["max_sdk_version"],
                "data_types": list(entry["data_types"]),
                "strength": entry["strength"],
                "dangerous": entry["dangerous"],
                "call_site_count": sum(
                    1
                    for s in sites
                    if s["permission"]["required"] and name in next(iter(s["permission"]["required"].values()))
                ),
                "source": "permissions:declare-data-use",
            }
        )

    emitted_flags = [{k: v for k, v in f.items() if k != "read_by_sdk"} for f in flags]
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "partial" if steps.errors else "success",
        "errors": sorted(steps.errors),
        "generator": {
            "module": "privacy_analysis",
            "insight_version": insight_version,
            "catalogue_version": cat.version,
            "catalogue_digest": cat.digest,
            "android_reference_api": ANDROID_REFERENCE_API,
            "execution_time": round(time.perf_counter() - started, 3),
        },
        "app": {
            "package": manifest.package,
            "min_sdk": manifest.min_sdk,
            "target_sdk": manifest.target_sdk,
            "app_namespaces": sorted(namespaces),
            "application_class": manifest.application_class,
        },
        "disclaimer": DISCLAIMER,
        "coverage": coverage,
        "data_safety": {"rows": rows},
        "call_sites": sites,
        "sdks": sdks,
        "permissions": permissions,
        "manifest_flags": emitted_flags,
        "consent": consent,
        "findings": findings,
        "compliance_refs": {r: dict(cat.compliance_refs[r]) for r in used_refs if r in cat.compliance_refs},
    }


def _signature_db() -> dict[str, Any]:
    from ..tracker_analysis.databases.tracker_database import load_signature_db

    return load_signature_db()


def summary_line(section: dict[str, Any] | None) -> str | None:
    """One terminal line for the section (worded per D7), None when there is no section."""
    if not isinstance(section, dict):
        return None
    if section.get("status") == "failure":
        errors = section.get("errors") or ["unknown error"]
        return f"PRIVACY (static): analysis failed: {errors[0]}"
    rows = (section.get("data_safety") or {}).get("rows") or []
    if not rows:
        return "PRIVACY (static): no data types found by static analysis"
    statuses = [r.get("status") for r in rows]
    verdict_words = {
        "cmp_detected": "consent SDK found",
        "tcf_writer_without_known_cmp": "TCF keys written, no known consent SDK",
        "tcf_reader_only": "TCF reader only",
        "none_detected": "no consent mechanism found",
        "not_applicable": "not applicable",
    }
    verdict = verdict_words.get((section.get("consent") or {}).get("verdict"), "other")
    return (
        f"PRIVACY (static): {len(rows)} data types ({statuses.count('likely_collected')} SDK-documented, "
        f"{statuses.count('may_be_collected')} code can access, {statuses.count('possible')} possible) · "
        f"{len(section.get('sdks') or [])} SDKs · consent: {verdict} · {len(section.get('findings') or [])} findings"
    )


# ------------------------------------------------------------------------ engine
@dataclass
class PrivacyAnalysisResult(BaseResult):
    """Result of the ``privacy_analysis`` module; ``section`` is the contract dict."""

    section: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Base fields plus ``privacy_analysis``."""
        base = super().to_dict()
        base["privacy_analysis"] = self.section
        return base


@register_module("privacy_analysis")
class PrivacyAnalysisModule(BaseAnalysisModule):
    """Static privacy layer: draft Data safety label, SDK attribution, consent, findings."""

    def __init__(self, config: dict[str, Any]):
        """Read the module config."""
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.settings = {k: self.config.get(k, v) for k, v in DEFAULT_CONFIG.items()}
        self.data_dir = self.config.get("catalogue_dir")

    def get_dependencies(self) -> list[str]:
        """Only the tracker result is read (optional)."""
        return ["tracker_analysis"]

    def analyze(self, apk_path: str, context: AnalysisContext) -> PrivacyAnalysisResult:
        """Run the pipeline. Never raises; a missing androguard object gives the failure stub."""
        started = time.perf_counter()
        try:
            androguard_obj = getattr(context, "androguard_obj", None)
            if androguard_obj is None:
                raise RuntimeError("no androguard object")
            apk = androguard_obj.get_androguard_apk()
            dx = androguard_obj.get_androguard_analysis_obj()
            if apk is None or dx is None:
                raise RuntimeError("androguard analysis unavailable")
            dexes = _safe(androguard_obj.get_androguard_dex) or []
        except Exception as exc:
            return self._failure(f"privacy analysis needs the androguard analysis: {exc}", started)
        try:
            catalogue = load_catalogue(self.data_dir)
        except Exception as exc:
            return self._failure(f"privacy catalogue unavailable: {exc}", started)
        try:
            index = AndroguardIndex(dx, dexes)
            manifest = ManifestFacts.from_apk(apk)
            section = analyse(index, manifest, catalogue, self.settings, _tracker_names(context))
        except Exception as exc:  # analyse() isolates steps; this is a last resort
            self.logger.debug("privacy analysis failed", exc_info=True)
            return self._failure(f"privacy analysis failed: {type(exc).__name__}: {exc}", started)
        return PrivacyAnalysisResult(
            module_name="privacy_analysis",
            status=AnalysisStatus.SUCCESS,
            execution_time=time.perf_counter() - started,
            section=section,
        )

    def _failure(self, message: str, started: float) -> PrivacyAnalysisResult:
        self.logger.warning(message)
        return PrivacyAnalysisResult(
            module_name="privacy_analysis",
            status=AnalysisStatus.FAILURE,
            execution_time=time.perf_counter() - started,
            error_message=message,
            section=failure_section([message]),
        )


def _tracker_names(context: AnalysisContext) -> list[str]:
    try:
        result = context.get_result("tracker_analysis")
    except Exception:
        return []
    names = []
    for tracker in getattr(result, "detected_trackers", None) or []:
        name = tracker.get("name") if isinstance(tracker, dict) else getattr(tracker, "name", None)
        if name:
            names.append(str(name))
    return sorted(set(names))


__all__ = [
    "DEFAULT_CONFIG",
    "ManifestFacts",
    "PrivacyAnalysisModule",
    "PrivacyAnalysisResult",
    "analyse",
    "failure_section",
    "summary_line",
]
